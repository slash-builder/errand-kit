//! A scripted worker for tests: responses are consumed in order and every request is recorded.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

use crate::worker::{Worker, WorkerOutput, WorkerRequest};
use crate::{ErrandError, Result};

/// One scripted response.
#[derive(Debug, Clone)]
enum Step {
    Return {
        text: String,
        tools: Option<Vec<String>>,
    },
    WriteFile {
        path: String,
        contents: String,
    },
    Fail(String),
}

/// Returns scripted output in order and records the requests it received.
///
/// Unless a step says otherwise (`then_return_with_tools`), `tools_reported` echoes the requested tools, as an honest
/// worker would. Running out of steps is an error.
#[derive(Debug, Default)]
pub struct FakeWorker {
    steps: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<WorkerRequest>>,
}

impl FakeWorker {
    /// An empty script.
    pub fn new() -> Self {
        Self::default()
    }

    fn push(self, step: Step) -> Self {
        if let Ok(mut q) = self.steps.lock() {
            q.push_back(step);
        }
        self
    }

    /// Next run returns `text`, reporting the requested tools.
    #[must_use]
    pub fn then_return(self, text: impl Into<String>) -> Self {
        self.push(Step::Return {
            text: text.into(),
            tools: None,
        })
    }

    /// Next run returns `text` and reports exactly `tools` (to exercise the `tools_match` gate).
    #[must_use]
    pub fn then_return_with_tools(self, text: impl Into<String>, tools: Vec<String>) -> Self {
        self.push(Step::Return {
            text: text.into(),
            tools: Some(tools),
        })
    }

    /// Next run writes `contents` to `relative_path` under the request's `cwd` (creating parent directories), as a worker
    /// creating a patch would, then returns an empty text.
    #[must_use]
    pub fn then_write_file(
        self,
        relative_path: impl Into<String>,
        contents: impl Into<String>,
    ) -> Self {
        self.push(Step::WriteFile {
            path: relative_path.into(),
            contents: contents.into(),
        })
    }

    /// Next run fails with `message`.
    #[must_use]
    pub fn then_fail(self, message: impl Into<String>) -> Self {
        self.push(Step::Fail(message.into()))
    }

    /// Every request received so far, oldest first.
    pub fn requests(&self) -> Vec<WorkerRequest> {
        self.seen.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

impl Worker for FakeWorker {
    fn kind(&self) -> &'static str {
        "fake"
    }

    fn run(&self, req: &WorkerRequest) -> Result<WorkerOutput> {
        let start = Instant::now();
        self.seen
            .lock()
            .map_err(|_| ErrandError::Worker("fake worker lock poisoned".into()))?
            .push(req.clone());
        let step = self
            .steps
            .lock()
            .map_err(|_| ErrandError::Worker("fake worker lock poisoned".into()))?
            .pop_front()
            .ok_or_else(|| {
                ErrandError::Worker("fake worker has no scripted response left".into())
            })?;
        let (text, tools) = match step {
            Step::Return { text, tools } => (text, tools.unwrap_or_else(|| req.tools.clone())),
            Step::WriteFile { path, contents } => {
                let target = req.cwd.join(&path);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| ErrandError::io(parent, e))?;
                }
                std::fs::write(&target, contents).map_err(|e| ErrandError::io(&target, e))?;
                (String::new(), req.tools.clone())
            }
            Step::Fail(m) => return Err(ErrandError::Worker(m)),
        };
        Ok(WorkerOutput {
            text,
            exit_code: 0,
            duration_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            tools_reported: Some(tools),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::time::Duration;

    fn req(cwd: &Path) -> WorkerRequest {
        WorkerRequest {
            prompt: "p".into(),
            tools: vec!["Read".into()],
            max_turns: 2,
            cwd: cwd.to_path_buf(),
            add_dirs: vec![],
            env: BTreeMap::from([("K".into(), "V".into())]),
            timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn responses_are_consumed_in_order_then_run_out() {
        let d = tempfile::tempdir().unwrap();
        let w = FakeWorker::new().then_return("one").then_return("two");
        assert_eq!(w.run(&req(d.path())).unwrap().text, "one");
        assert_eq!(w.run(&req(d.path())).unwrap().text, "two");
        let e = w.run(&req(d.path())).unwrap_err();
        assert!(e.to_string().contains("no scripted response"), "{e}");
    }

    #[test]
    fn requests_are_recorded_even_when_the_run_fails() {
        let d = tempfile::tempdir().unwrap();
        let w = FakeWorker::new().then_fail("nope");
        let e = w.run(&req(d.path())).unwrap_err();
        assert!(e.to_string().contains("nope"));
        let seen = w.requests();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].prompt, "p");
        assert_eq!(seen[0].env.get("K").map(String::as_str), Some("V"));
        assert_eq!(seen[0].tools, vec!["Read".to_string()]);
    }

    #[test]
    fn reported_tools_default_to_requested_and_can_be_overridden() {
        let d = tempfile::tempdir().unwrap();
        let w = FakeWorker::new()
            .then_return("a")
            .then_return_with_tools("b", vec!["Bash".into()]);
        assert_eq!(
            w.run(&req(d.path())).unwrap().tools_reported,
            Some(vec!["Read".to_string()])
        );
        assert_eq!(
            w.run(&req(d.path())).unwrap().tools_reported,
            Some(vec!["Bash".to_string()])
        );
    }

    #[test]
    fn write_file_creates_nested_files_in_cwd() {
        let d = tempfile::tempdir().unwrap();
        let w = FakeWorker::new().then_write_file("out/sub/x.patch", "diff");
        w.run(&req(d.path())).unwrap();
        assert_eq!(
            std::fs::read_to_string(d.path().join("out/sub/x.patch")).unwrap(),
            "diff"
        );
    }

    #[test]
    fn kind_is_fake() {
        assert_eq!(FakeWorker::new().kind(), "fake");
    }
}
