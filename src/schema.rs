//! JSON Schemas generated from the contract types. The committed files in `schema/` must equal these (a test enforces it);
//! regenerate with `errand schema --out schema`.

use schemars::schema_for;

use crate::contract::{BoundaryReport, GovernorDecision, HandBack, OutboxEntry, QueueSnapshot, RunRecord};

/// `(file name, pretty JSON)` for every schema in the contract.
pub fn all() -> Vec<(&'static str, String)> {
    fn pretty<T: serde::Serialize>(v: &T) -> String {
        // Serialising a schema cannot fail; fall back to an empty object rather than panic.
        serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into()) + "\n"
    }
    vec![
        ("run-record.schema.json", pretty(&schema_for!(RunRecord))),
        ("hand-back.schema.json", pretty(&schema_for!(HandBack))),
        ("boundary-report.schema.json", pretty(&schema_for!(BoundaryReport))),
        ("outbox-entry.schema.json", pretty(&schema_for!(OutboxEntry))),
        ("governor-decision.schema.json", pretty(&schema_for!(GovernorDecision))),
        ("queue-snapshot.schema.json", pretty(&schema_for!(QueueSnapshot))),
    ]
}

/// Write every schema into `dir`.
pub fn write_all(dir: &std::path::Path) -> crate::Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| crate::ErrandError::io(dir, e))?;
    for (name, text) in all() {
        let p = dir.join(name);
        std::fs::write(&p, text).map_err(|e| crate::ErrandError::io(p, e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::path::Path;

    use super::*;

    fn root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
    }

    /// Regenerate the committed schemas with `ERRAND_UPDATE_SCHEMAS=1 cargo test schema`.
    #[test]
    fn committed_schemas_match_the_types() {
        if std::env::var("ERRAND_UPDATE_SCHEMAS").as_deref() == Ok("1") {
            write_all(&root().join("schema")).unwrap();
        }
        for (name, text) in all() {
            let on_disk = std::fs::read_to_string(root().join("schema").join(name)).unwrap_or_default();
            assert_eq!(on_disk, text, "{name} is out of date: run ERRAND_UPDATE_SCHEMAS=1 cargo test schema");
        }
    }

    fn schema_for_fixture(file: &str) -> Option<&'static str> {
        [
            ("run-record-", "run-record.schema.json"),
            ("hand-back-", "hand-back.schema.json"),
            ("outbox-entry-", "outbox-entry.schema.json"),
            ("governor-decision-", "governor-decision.schema.json"),
            ("queue-snapshot-", "queue-snapshot.schema.json"),
        ]
        .into_iter()
        .find(|(p, _)| file.starts_with(p))
        .map(|(_, s)| s)
    }

    /// The shared conformance suite: every valid fixture parses with the Rust types AND validates against the schema; every
    /// invalid fixture is rejected by the schema AND by the Rust types. Other implementations and consumers run the same files.
    #[test]
    fn fixtures_conform() {
        use crate::contract::*;
        let mut seen = 0;
        for (dir, want_valid) in [("valid", true), ("invalid", false)] {
            for entry in std::fs::read_dir(root().join("fixtures").join(dir)).unwrap() {
                let path = entry.unwrap().path();
                let file = path.file_name().unwrap().to_str().unwrap().to_string();
                let schema_name = schema_for_fixture(&file).unwrap_or_else(|| panic!("no schema for fixture {file}"));
                let schema: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(root().join("schema").join(schema_name)).unwrap()).unwrap();
                let instance: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
                let validator = jsonschema::validator_for(&schema).unwrap();
                let schema_ok = validator.is_valid(&instance);
                let text = instance.to_string();
                let types_ok = match schema_name {
                    "run-record.schema.json" => serde_json::from_str::<RunRecord>(&text).is_ok(),
                    "hand-back.schema.json" => serde_json::from_str::<HandBack>(&text).is_ok(),
                    "outbox-entry.schema.json" => serde_json::from_str::<OutboxEntry>(&text).is_ok(),
                    "governor-decision.schema.json" => serde_json::from_str::<GovernorDecision>(&text).is_ok(),
                    _ => serde_json::from_str::<QueueSnapshot>(&text).is_ok(),
                };
                assert_eq!(schema_ok, want_valid, "{dir}/{file}: schema verdict");
                assert_eq!(types_ok, want_valid, "{dir}/{file}: Rust types verdict");
                seen += 1;
            }
        }
        assert!(seen >= 12, "expected the shared fixtures, saw {seen}");
    }

    #[test]
    fn a_run_record_round_trips() {
        use crate::contract::RunRecord;
        let text = std::fs::read_to_string(root().join("fixtures/valid/run-record-l1-handback.json")).unwrap();
        let rec: RunRecord = serde_json::from_str(&text).unwrap();
        let again: RunRecord = serde_json::from_str(&serde_json::to_string(&rec).unwrap()).unwrap();
        assert_eq!(rec, again);
    }
}
