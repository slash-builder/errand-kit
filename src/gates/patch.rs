//! Patch validation: the trusted phase decides on the patch text, before applying anything.
//!
//! A worker (an untrusted model) returns a patch; a trusted phase that holds a push credential will `git apply` it to a
//! fresh clone and push. [`validate_patch`] decides, on the **patch text alone**, whether that may happen. Scope comes from
//! the [`Recipe`], never from the ticket (spec section 5).
//!
//! # The grammar is deliberately narrower than git's
//!
//! `git apply` is forgiving: it skips leading junk, ignores trailing junk, accepts traditional `---`/`+++` diffs with no
//! `diff --git` line, and ignores anything after a tab in a file name. Every one of those is a way for the validator and
//! the applier to disagree about what a patch does, so this parser accepts **only** the output shape of `git diff`:
//!
//! * the first line is `diff --git `, and every line of the patch belongs to exactly one file section;
//! * each section is `diff --git` + extended header lines + (optionally) one `---`/`+++` pair + hunks;
//! * every hunk's declared line counts are checked against its body, so no line can hide inside or after a hunk;
//! * the patch ends with a newline; a patch with CR at the end of a header line (CRLF transport) is refused, while CR
//!   inside hunk *content* is ordinary data.
//!
//! # What is refused
//!
//! Empty or unrecognisable input; input over [`MAX_PATCH_BYTES`]; symlinks (`120000`); gitlinks (`160000`); any mode
//! change; executable files (`100755`, new **or** edited in place: the `index` line of an edit must say `100644`);
//! binary patches; unsafe paths (absolute, `..`, empty or `.` components, NUL, control or invisible characters, backslash,
//! `:`, any `.git` component in any case or NTFS-style spelling); paths outside the recipe scope; protected paths (unless
//! named exactly in `allow_protected`); header names that disagree with each other; the same path twice (compared without
//! case) or a file and a directory of the same name; hunk counts that do not match the body; trailing garbage; and more
//! files or lines than the recipe allows. Deletions count as touching a path. Renames and copies are checked on both the
//! source and the destination.
//!
//! # Why `index <old>..<new> 100644` is mandatory on edits
//!
//! A patch with no `index` and no mode lines still applies to an existing symlink: `git apply` reads the link target as
//! the file's content and rewrites it. The patch text cannot tell whether the repository has a symlink at that path, but
//! with `index ... 100644` present git refuses ("wrong type") if it does. So an in-place edit without that line is refused.
//! A pure rename (similarity 100%, no hunks) carries no mode in git's output and is accepted; the trusted phase must
//! re-check modes after applying (for example `git diff --cached --raw`) as spec section 6 already requires.

use std::borrow::Cow;
use std::collections::HashSet;
use std::iter::Peekable;
use std::str::Split;

use crate::gates::recipe::Recipe;
use crate::{ErrandError, Result};

/// Largest patch, in bytes, that will be examined. Larger input is refused before any parsing or allocation proportional
/// to its size.
pub const MAX_PATCH_BYTES: usize = 2 * 1024 * 1024;

/// Longest repository-relative path accepted, in bytes.
const MAX_PATH_BYTES: usize = 4096;
/// Most components a path may have. Real repositories are far shallower; the cap bounds the per-path work.
const MAX_PATH_DEPTH: usize = 64;
/// Longest single path component accepted, in bytes.
const MAX_COMPONENT_BYTES: usize = 255;
/// Longest header line accepted (two paths and some framing). Bounds the work done per header line.
const MAX_HEADER_LINE_BYTES: usize = 2 * MAX_PATH_BYTES + 64;
/// Most digits accepted in a hunk range number.
const MAX_COUNT_DIGITS: usize = 9;
/// The only file mode a patch may create, delete or edit.
const REGULAR_MODE: &str = "100644";

/// What a validated patch touches, as parsed from the patch text itself (not as claimed by the worker).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchSummary {
    /// Paths the patch creates or modifies (repository-relative).
    pub files: Vec<String>,
    /// Added lines.
    pub added: usize,
    /// Removed lines.
    pub removed: usize,
}

/// Validate a unified/git patch against a recipe. Returns what it touches, or why it was refused.
///
/// `files` lists, in patch order, every path the patch creates, modifies, deletes or renames (both ends of a rename; the
/// destination of a copy). `max_files` is compared with that list's length and `max_lines` with `added + removed`; a
/// count equal to the limit passes. See the module docs for the full list of refusals. Every refusal is an
/// [`ErrandError::Patch`] carrying a precise reason, and is also logged at `warn` level.
pub fn validate_patch(patch: &str, recipe: &Recipe) -> Result<PatchSummary> {
    match validate_inner(patch, recipe) {
        Ok(summary) => {
            tracing::debug!(
                files = summary.files.len(),
                added = summary.added,
                removed = summary.removed,
                "patch accepted"
            );
            Ok(summary)
        }
        Err(err) => {
            tracing::warn!(reason = %err, "patch refused");
            Err(err)
        }
    }
}

/// The paths a patch touches, parsed from the patch text. Applies the same structural and path-safety rules as
/// [`validate_patch`] (so a patch that cannot be parsed or names an unsafe path is an error) but no recipe policy: scope,
/// protected paths and size limits are not consulted.
pub fn changed_paths(patch: &str) -> Result<Vec<String>> {
    Ok(parse(patch)?.files)
}

fn validate_inner(patch: &str, recipe: &Recipe) -> Result<PatchSummary> {
    let parsed = parse(patch)?;
    let scope = recipe.scope_matcher()?;
    let protected = recipe.protected_matcher()?;
    for path in &parsed.checked {
        if protected.is_match(path.as_str()) && !recipe.is_allowed_protected(path) {
            return refuse(format!(
                "`{path}` is a protected path (CI, build, lockfile, test or repository metadata)"
            ));
        }
        if !scope.is_match(path.as_str()) {
            return refuse(format!("`{path}` is outside the recipe scope"));
        }
    }
    if let Some(max) = recipe.max_files {
        if parsed.files.len() > max {
            return refuse(format!(
                "patch touches {} files, more than the limit of {max}",
                parsed.files.len()
            ));
        }
    }
    let lines = parsed.added.saturating_add(parsed.removed);
    if let Some(max) = recipe.max_lines {
        if lines > max {
            return refuse(format!(
                "patch changes {lines} lines, more than the limit of {max}"
            ));
        }
    }
    Ok(PatchSummary {
        files: parsed.files,
        added: parsed.added,
        removed: parsed.removed,
    })
}

fn refuse<T>(reason: impl Into<String>) -> Result<T> {
    Err(ErrandError::Patch(reason.into()))
}

/// A short, escaped rendering of untrusted text for an error message (bounded, no raw control characters).
fn show(s: &str) -> String {
    let mut out: String = s.chars().take(60).flat_map(char::escape_debug).collect();
    if s.chars().nth(60).is_some() {
        out.push_str("...");
    }
    out
}

// ---------------------------------------------------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------------------------------------------------

type Lines<'a> = Peekable<Split<'a, char>>;

/// The result of parsing: policy-free facts about the patch.
struct Parsed {
    /// Paths created, modified, deleted or renamed, in patch order.
    files: Vec<String>,
    /// Every path that must pass scope and protection checks (`files` plus copy sources).
    checked: Vec<String>,
    added: usize,
    removed: usize,
}

fn parse(patch: &str) -> Result<Parsed> {
    if patch.len() > MAX_PATCH_BYTES {
        return refuse(format!(
            "patch is {} bytes, over the {MAX_PATCH_BYTES}-byte cap",
            patch.len()
        ));
    }
    if patch.trim().is_empty() {
        return refuse("patch is empty");
    }
    if !patch.starts_with("diff --git ") {
        return refuse("no recognisable file section: the patch must start with `diff --git` (leading text is refused)");
    }
    let Some(body) = patch.strip_suffix('\n') else {
        return refuse("patch does not end with a newline (truncated or altered in transit)");
    };
    let mut lines: Lines<'_> = body.split('\n').peekable();
    let mut all = Collector::default();
    while let Some(line) = lines.next() {
        let Some(rest) = line.strip_prefix("diff --git ") else {
            return refuse(format!(
                "unexpected line outside any file section: `{}`",
                show(line)
            ));
        };
        let section = parse_section(rest, &mut lines)?;
        all.add(section)?;
    }
    all.finish()
}

/// One parsed file section.
struct Section {
    touched: Vec<String>,
    checked: Vec<String>,
    added: usize,
    removed: usize,
}

#[derive(Default)]
struct Collector {
    files: Vec<String>,
    checked: Vec<String>,
    seen: HashSet<String>,
    added: usize,
    removed: usize,
}

/// Case-folded form used to detect two spellings of one file on a case-insensitive filesystem.
fn fold(path: &str) -> String {
    path.to_lowercase()
}

impl Collector {
    fn add(&mut self, section: Section) -> Result<()> {
        for path in &section.checked {
            if !self.seen.insert(fold(path)) {
                return refuse(format!(
                    "`{path}` appears more than once in the patch (compared without case)"
                ));
            }
        }
        self.files.extend(section.touched);
        self.checked.extend(section.checked);
        self.added = self.added.saturating_add(section.added);
        self.removed = self.removed.saturating_add(section.removed);
        Ok(())
    }

    fn finish(self) -> Result<Parsed> {
        // A path may not also be a directory prefix of another path in the same patch (file/directory conflict).
        for path in &self.checked {
            let folded = fold(path);
            for (i, _) in folded.match_indices('/') {
                if let Some(ancestor) = folded.get(..i) {
                    if self.seen.contains(ancestor) {
                        return refuse(format!(
                            "`{ancestor}` is both a file and a directory of `{path}` in one patch"
                        ));
                    }
                }
            }
        }
        Ok(Parsed {
            files: self.files,
            checked: self.checked,
            added: self.added,
            removed: self.removed,
        })
    }
}

/// What kind of change a section makes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Modify,
    New,
    Delete,
    Rename,
    Copy,
}

/// A name from a `---` or `+++` line.
enum Name {
    Null,
    Path(String),
}

#[derive(Default)]
struct Header {
    new_file: bool,
    deleted_file: bool,
    index_seen: bool,
    /// The `index` line carried a mode (necessarily `100644`).
    index_mode: bool,
    similarity: bool,
    rename_from: Option<String>,
    rename_to: Option<String>,
    copy_from: Option<String>,
    copy_to: Option<String>,
    old_name: Option<Name>,
    new_name: Option<Name>,
    /// The `---`/`+++` pair and its hunks have been consumed; only the next section may follow.
    done: bool,
    hunks: usize,
    hunk_old_nonzero: bool,
    hunk_new_nonzero: bool,
    added: usize,
    removed: usize,
}

/// Refuse a header-region line that is too long or ends in CR.
fn check_header_line(line: &str) -> Result<()> {
    if line.len() > MAX_HEADER_LINE_BYTES {
        return refuse(format!(
            "header line of {} bytes is over the {MAX_HEADER_LINE_BYTES}-byte cap",
            line.len()
        ));
    }
    if line.ends_with('\r') {
        return refuse(format!(
            "header line ends in a carriage return (CRLF transport?): `{}`; paths must not contain CR",
            show(line)
        ));
    }
    Ok(())
}

fn set_flag(flag: &mut bool, what: &str) -> Result<()> {
    if *flag {
        return refuse(format!("duplicate `{what}` line in one file section"));
    }
    *flag = true;
    Ok(())
}

fn set_name(slot: &mut Option<String>, value: &str, what: &str) -> Result<()> {
    if slot.is_some() {
        return refuse(format!("duplicate `{what}` line in one file section"));
    }
    *slot = Some(decode_whole(value)?);
    Ok(())
}

fn parse_section(rest: &str, lines: &mut Lines<'_>) -> Result<Section> {
    check_header_line(rest)?;
    let candidates = header_candidates(rest)?;
    let mut h = Header::default();
    while let Some(&line) = lines.peek() {
        if line.starts_with("diff --git ") {
            break;
        }
        if h.done {
            return refuse(format!(
                "unexpected content after the last hunk of a file: `{}`",
                show(line)
            ));
        }
        lines.next();
        check_header_line(line)?;
        if let Some(mode) = line.strip_prefix("new file mode ") {
            check_mode(mode)?;
            set_flag(&mut h.new_file, "new file mode")?;
        } else if let Some(mode) = line.strip_prefix("deleted file mode ") {
            check_mode(mode)?;
            set_flag(&mut h.deleted_file, "deleted file mode")?;
        } else if line.starts_with("old mode ") || line.starts_with("new mode ") {
            return refuse(format!("mode change is not allowed: `{}`", show(line)));
        } else if let Some(v) = line.strip_prefix("index ") {
            let has_mode = check_index(v)?;
            set_flag(&mut h.index_seen, "index")?;
            h.index_mode = has_mode;
        } else if let Some(v) = line.strip_prefix("similarity index ") {
            check_percent(v)?;
            set_flag(&mut h.similarity, "similarity index")?;
        } else if let Some(v) = line.strip_prefix("dissimilarity index ") {
            check_percent(v)?;
        } else if let Some(v) = line.strip_prefix("rename from ") {
            set_name(&mut h.rename_from, v, "rename from")?;
        } else if let Some(v) = line.strip_prefix("rename to ") {
            set_name(&mut h.rename_to, v, "rename to")?;
        } else if let Some(v) = line.strip_prefix("copy from ") {
            set_name(&mut h.copy_from, v, "copy from")?;
        } else if let Some(v) = line.strip_prefix("copy to ") {
            set_name(&mut h.copy_to, v, "copy to")?;
        } else if line.starts_with("Binary files ") || line == "GIT binary patch" {
            return refuse("binary patches are not allowed");
        } else if let Some(old) = line.strip_prefix("--- ") {
            h.old_name = Some(parse_name(old, "a/")?);
            let Some(next) = lines.next() else {
                return refuse("`---` line is not followed by a `+++` line");
            };
            check_header_line(next)?;
            let Some(new) = next.strip_prefix("+++ ") else {
                return refuse(format!(
                    "`---` line is not followed by a `+++` line: `{}`",
                    show(next)
                ));
            };
            h.new_name = Some(parse_name(new, "b/")?);
            parse_hunks(lines, &mut h)?;
            h.done = true;
        } else {
            return refuse(format!(
                "unrecognised line in a file header: `{}`",
                show(line)
            ));
        }
    }
    finish_section(h, &candidates)
}

/// Decide the section's kind and paths from every name the patch gave, and require that they all agree.
fn finish_section(h: Header, candidates: &[(Cow<'_, str>, Cow<'_, str>)]) -> Result<Section> {
    let has_rename = h.rename_from.is_some() || h.rename_to.is_some();
    let has_copy = h.copy_from.is_some() || h.copy_to.is_some();
    let ops = [h.new_file, h.deleted_file, has_rename, has_copy]
        .iter()
        .filter(|b| **b)
        .count();
    if ops > 1 {
        return refuse("conflicting operations (new/deleted/rename/copy) in one file section");
    }
    let kind = if h.new_file {
        Kind::New
    } else if h.deleted_file {
        Kind::Delete
    } else if has_rename {
        Kind::Rename
    } else if has_copy {
        Kind::Copy
    } else {
        Kind::Modify
    };

    // The names the section is about.
    let (touched, checked): (Vec<String>, Vec<String>) = match kind {
        Kind::Rename | Kind::Copy => {
            let (from, to) = if kind == Kind::Rename {
                (h.rename_from.clone(), h.rename_to.clone())
            } else {
                (h.copy_from.clone(), h.copy_to.clone())
            };
            let (Some(from), Some(to)) = (from, to) else {
                return refuse("rename/copy section needs both a `from` and a `to` line");
            };
            if from == to {
                return refuse(format!("rename/copy of `{}` onto itself", show(&from)));
            }
            if !candidates.iter().any(|(a, b)| *a == from && *b == to) {
                return refuse(format!(
                    "`diff --git` header does not name the rename/copy pair `{}` -> `{}`",
                    show(&from),
                    show(&to)
                ));
            }
            let touched = if kind == Kind::Rename {
                vec![from.clone(), to.clone()]
            } else {
                vec![to.clone()]
            };
            (touched, vec![from, to])
        }
        _ => {
            let path = same_name(candidates)?;
            (vec![path.clone()], vec![path])
        }
    };
    let primary = checked.last().cloned().unwrap_or_default();
    let source = checked.first().cloned().unwrap_or_default();

    if kind == Kind::Modify && h.old_name.is_none() {
        return refuse(format!(
            "file section for `{}` changes nothing",
            show(&primary)
        ));
    }
    // `---`/`+++` must agree with the header (the validated name must be the applied name).
    let agree = match (kind, &h.old_name, &h.new_name) {
        (Kind::New, Some(Name::Null), Some(Name::Path(n))) => *n == primary,
        (Kind::Delete, Some(Name::Path(o)), Some(Name::Null)) => *o == primary,
        (Kind::Modify, Some(Name::Path(o)), Some(Name::Path(n))) => *o == primary && *n == primary,
        (Kind::Rename | Kind::Copy, Some(Name::Path(o)), Some(Name::Path(n))) => {
            *o == source && *n == primary
        }
        (Kind::New | Kind::Delete | Kind::Rename | Kind::Copy, None, None) => true,
        _ => false,
    };
    if !agree {
        return refuse(format!(
            "`diff --git`, rename/copy and `---`/`+++` names disagree (or `/dev/null` is misused) for `{}`",
            show(&primary)
        ));
    }
    for path in &checked {
        check_path(path)?;
    }

    // Modes: `check_mode` already refused anything but 100644 wherever a mode was written. An edit must also *say* 100644
    // (see the module docs), because the absence of a mode line proves nothing about the file already in the repository.
    if matches!(kind, Kind::Modify | Kind::Rename | Kind::Copy) && h.hunks > 0 && !h.index_mode {
        return refuse(format!(
            "edit of `{}` has no `index <old>..<new> {REGULAR_MODE}` line, so the file type cannot be verified \
             (an edit could land on a symlink)",
            show(&primary)
        ));
    }
    if kind == Kind::New && h.hunk_old_nonzero {
        return refuse(format!(
            "new file `{}` has a hunk that removes or keeps old content",
            show(&primary)
        ));
    }
    if kind == Kind::Delete && h.hunk_new_nonzero {
        return refuse(format!(
            "deleted file `{}` has a hunk that adds or keeps content",
            show(&primary)
        ));
    }
    Ok(Section {
        touched,
        checked,
        added: h.added,
        removed: h.removed,
    })
}

/// The single path named identically on both sides of the `diff --git` line.
fn same_name(candidates: &[(Cow<'_, str>, Cow<'_, str>)]) -> Result<String> {
    let mut found: Option<&str> = None;
    for (a, b) in candidates {
        if a == b {
            match found {
                Some(prev) if prev != a.as_ref() => {
                    return refuse("the `diff --git` line is ambiguous (it splits into more than one same-name pair)");
                }
                _ => found = Some(a.as_ref()),
            }
        }
    }
    match found {
        Some(p) => Ok(p.to_string()),
        None => refuse("the `diff --git` line names two different files without a rename or copy"),
    }
}

/// Every way the text after `diff --git ` can be read as `a/<path> b/<path>` (names are not unambiguous when they contain
/// spaces). Prefixes are stripped; nothing here is trusted until it matches an authoritative name.
fn header_candidates(rest: &str) -> Result<Vec<(Cow<'_, str>, Cow<'_, str>)>> {
    let mut out: Vec<(Cow<'_, str>, Cow<'_, str>)> = Vec::new();
    match rest.find('"') {
        // No quoting anywhere: any space followed by `b/` may be the separator.
        None => {
            for (i, _) in rest.match_indices(' ') {
                let (Some(a), Some(b)) = (rest.get(..i), rest.get(i + 1..)) else {
                    continue;
                };
                if let (Some(a), Some(b)) = (a.strip_prefix("a/"), b.strip_prefix("b/")) {
                    out.push((Cow::Borrowed(a), Cow::Borrowed(b)));
                }
            }
        }
        // A quoted first name: decode it, then the rest is the second name.
        Some(0) => {
            let (a, used) = unquote_c(rest)?;
            let Some(tail) = rest.get(used..).and_then(|t| t.strip_prefix(' ')) else {
                return refuse("malformed `diff --git` line: quoted name not followed by a space and a second name");
            };
            let b = decode_whole(tail)?;
            if let (Some(a), Some(b)) = (a.strip_prefix("a/"), b.strip_prefix("b/")) {
                out.push((Cow::Owned(a.to_string()), Cow::Owned(b.to_string())));
            }
        }
        // An unquoted first name and a quoted second name: the quote must directly follow the separating space.
        Some(q) => {
            let (Some(head), Some(tail)) = (rest.get(..q), rest.get(q..)) else {
                return refuse("malformed `diff --git` line");
            };
            let Some(a) = head.strip_suffix(' ') else {
                return refuse("malformed `diff --git` line: a quote inside a name");
            };
            let b = decode_whole(tail)?;
            if let (Some(a), Some(b)) = (a.strip_prefix("a/"), b.strip_prefix("b/")) {
                out.push((Cow::Borrowed(a), Cow::Owned(b.to_string())));
            }
        }
    }
    if out.is_empty() {
        return refuse(format!(
            "`diff --git` line does not name `a/<path> b/<path>`: `{}`",
            show(rest)
        ));
    }
    Ok(out)
}

/// Parse a `---`/`+++` operand: `/dev/null`, or `<prefix><path>` (optionally quoted). git appends one TAB to names that
/// contain spaces; anything else after a TAB is refused rather than ignored.
fn parse_name(s: &str, prefix: &str) -> Result<Name> {
    let s = s.strip_suffix('\t').unwrap_or(s);
    if s == "/dev/null" {
        return Ok(Name::Null);
    }
    let decoded = decode_whole(s)?;
    match decoded.strip_prefix(prefix) {
        Some(p) => Ok(Name::Path(p.to_string())),
        None => refuse(format!(
            "file name `{}` does not start with `{prefix}`",
            show(&decoded)
        )),
    }
}

/// Decode a name that is either raw (the whole text) or one C-quoted string covering the whole text.
fn decode_whole(s: &str) -> Result<String> {
    if s.starts_with('"') {
        let (decoded, used) = unquote_c(s)?;
        if used != s.len() {
            return refuse(format!(
                "characters after a closing quote in a name: `{}`",
                show(s)
            ));
        }
        Ok(decoded)
    } else {
        Ok(s.to_string())
    }
}

/// Decode a git C-style quoted string at the start of `s` (which begins with `"`). Returns the text and the number of
/// bytes consumed including both quotes. Accepts git's escapes only: `\a \b \f \n \r \t \v \\ \"` and three-digit octal
/// (`\000`-`\377`); the result must be valid UTF-8.
fn unquote_c(s: &str) -> Result<(String, usize)> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::new();
    let mut i = 1;
    loop {
        let Some(&c) = bytes.get(i) else {
            return refuse(format!("unterminated quoted name: `{}`", show(s)));
        };
        i += 1;
        match c {
            b'"' => break,
            b'\\' => {
                let Some(&e) = bytes.get(i) else {
                    return refuse("quoted name ends inside an escape");
                };
                i += 1;
                let value = match e {
                    b'a' => 7,
                    b'b' => 8,
                    b'f' => 12,
                    b'n' => 10,
                    b'r' => 13,
                    b't' => 9,
                    b'v' => 11,
                    b'\\' | b'"' => e,
                    b'0'..=b'3' => {
                        let (Some(&d1), Some(&d2)) = (bytes.get(i), bytes.get(i + 1)) else {
                            return refuse("truncated octal escape in a quoted name");
                        };
                        if !(b'0'..=b'7').contains(&d1) || !(b'0'..=b'7').contains(&d2) {
                            return refuse("malformed octal escape in a quoted name");
                        }
                        i += 2;
                        let n = u32::from(e - b'0') * 64
                            + u32::from(d1 - b'0') * 8
                            + u32::from(d2 - b'0');
                        match u8::try_from(n) {
                            Ok(v) => v,
                            Err(_) => return refuse("octal escape out of range"),
                        }
                    }
                    _ => {
                        return refuse(format!(
                            "unknown escape `\\{}` in a quoted name",
                            show(&char::from(e).to_string())
                        ))
                    }
                };
                out.push(value);
            }
            _ => out.push(c),
        }
    }
    match String::from_utf8(out) {
        Ok(text) => Ok((text, i)),
        Err(_) => refuse("quoted name is not valid UTF-8"),
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Header line details
// ---------------------------------------------------------------------------------------------------------------------

/// Only `100644` is acceptable anywhere a mode is written.
fn check_mode(mode: &str) -> Result<()> {
    match mode {
        REGULAR_MODE => Ok(()),
        "120000" => refuse("symlink (mode 120000) is not allowed"),
        "160000" => refuse("gitlink/submodule (mode 160000) is not allowed"),
        "100755" => {
            refuse("executable file (mode 100755) is not allowed; only mode 100644 is accepted")
        }
        other => refuse(format!(
            "unsupported file mode `{}`; only 100644 is accepted",
            show(other)
        )),
    }
}

/// `index <hex>..<hex>[ <mode>]`. Returns whether a mode was present (it is always `100644` if so).
fn check_index(v: &str) -> Result<bool> {
    let (hashes, mode) = match v.split_once(' ') {
        Some((h, m)) => (h, Some(m)),
        None => (v, None),
    };
    let ok_hash = |s: &str| (4..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit());
    match hashes.split_once("..") {
        Some((a, b)) if ok_hash(a) && ok_hash(b) => {}
        _ => return refuse(format!("malformed `index` line: `{}`", show(v))),
    }
    if let Some(m) = mode {
        check_mode(m)?;
    }
    Ok(mode.is_some())
}

/// `<digits>%`, at most 100.
fn check_percent(v: &str) -> Result<()> {
    let ok = v.strip_suffix('%').is_some_and(|n| {
        (1..=3).contains(&n.len())
            && n.bytes().all(|b| b.is_ascii_digit())
            && n.parse::<u32>().is_ok_and(|n| n <= 100)
    });
    if ok {
        Ok(())
    } else {
        refuse(format!("malformed similarity index: `{}`", show(v)))
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Hunks
// ---------------------------------------------------------------------------------------------------------------------

struct HunkHeader {
    old: usize,
    new: usize,
}

fn parse_number(s: &str) -> Result<usize> {
    if s.is_empty() || s.len() > MAX_COUNT_DIGITS || !s.bytes().all(|b| b.is_ascii_digit()) {
        return refuse(format!("malformed number in a hunk header: `{}`", show(s)));
    }
    match s.parse::<usize>() {
        Ok(n) => Ok(n),
        Err(_) => refuse(format!("malformed number in a hunk header: `{}`", show(s))),
    }
}

/// `start[,count]`; returns the count (default 1). The start is validated but unused.
fn parse_range(s: &str) -> Result<usize> {
    match s.split_once(',') {
        Some((start, count)) => {
            parse_number(start)?;
            parse_number(count)
        }
        None => {
            parse_number(s)?;
            Ok(1)
        }
    }
}

/// `@@ -a[,b] +c[,d] @@[ heading]`.
fn parse_hunk_header(line: &str) -> Result<HunkHeader> {
    let bad = || refuse(format!("malformed hunk header: `{}`", show(line)));
    if line.ends_with('\r') {
        return refuse(format!(
            "hunk header ends in a carriage return (CRLF transport?): `{}`",
            show(line)
        ));
    }
    let Some(r) = line.strip_prefix("@@ -") else {
        return bad();
    };
    let Some((old, r)) = r.split_once(' ') else {
        return bad();
    };
    let Some(r) = r.strip_prefix('+') else {
        return bad();
    };
    let Some((new, r)) = r.split_once(' ') else {
        return bad();
    };
    if r != "@@" && !r.starts_with("@@ ") {
        return bad();
    }
    Ok(HunkHeader {
        old: parse_range(old)?,
        new: parse_range(new)?,
    })
}

/// Consume every hunk after a `---`/`+++` pair, checking each body against its declared counts.
fn parse_hunks(lines: &mut Lines<'_>, h: &mut Header) -> Result<()> {
    while let Some(&line) = lines.peek() {
        if !line.starts_with("@@") {
            break;
        }
        lines.next();
        let hunk = parse_hunk_header(line)?;
        if hunk.old == 0 && hunk.new == 0 {
            return refuse(format!("empty hunk: `{}`", show(line)));
        }
        h.hunk_old_nonzero |= hunk.old > 0;
        h.hunk_new_nonzero |= hunk.new > 0;
        let (mut old_left, mut new_left) = (hunk.old, hunk.new);
        let mut last_was_marker = false;
        let mut any_body = false;
        while old_left > 0 || new_left > 0 {
            let Some(body) = lines.next() else {
                return refuse("hunk is shorter than its declared line counts (truncated patch)");
            };
            match body.as_bytes().first() {
                Some(b' ') if old_left > 0 && new_left > 0 => {
                    old_left -= 1;
                    new_left -= 1;
                    last_was_marker = false;
                }
                Some(b'-') if old_left > 0 => {
                    old_left -= 1;
                    h.removed = h.removed.saturating_add(1);
                    last_was_marker = false;
                }
                Some(b'+') if new_left > 0 => {
                    new_left -= 1;
                    h.added = h.added.saturating_add(1);
                    last_was_marker = false;
                }
                Some(b'\\') if any_body && !last_was_marker && body.starts_with("\\ ") => {
                    last_was_marker = true;
                }
                _ => {
                    return refuse(format!(
                        "hunk body does not match its declared line counts at `{}`",
                        show(body)
                    ));
                }
            }
            any_body = true;
        }
        // One optional `\ No newline at end of file` belongs to the last body line.
        if !last_was_marker {
            if let Some(&next) = lines.peek() {
                if next.starts_with("\\ ") {
                    lines.next();
                }
            }
        }
        h.hunks += 1;
    }
    if h.hunks == 0 {
        return refuse("`---`/`+++` header without any hunk");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------------------------------------------------

/// Characters that are invisible or reorder text; never legitimate in a repository path we will accept.
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}')
}

/// Whether a component names the git directory under any spelling a filesystem may fold onto `.git`.
fn is_dot_git(component: &str) -> bool {
    let trimmed = component.trim_end_matches([' ', '.']);
    trimmed.eq_ignore_ascii_case(".git") || component.eq_ignore_ascii_case("git~1")
}

/// The path-safety rules. Applied to every name the patch will make the applier open.
fn check_path(p: &str) -> Result<()> {
    if p.is_empty() {
        return refuse("empty path");
    }
    if p.len() > MAX_PATH_BYTES {
        return refuse(format!(
            "path of {} bytes is over the {MAX_PATH_BYTES}-byte cap",
            p.len()
        ));
    }
    for c in p.chars() {
        if c == '\0' {
            return refuse(format!("path contains a NUL: `{}`", show(p)));
        }
        if c == '\\' {
            return refuse(format!("path contains a backslash: `{}`", show(p)));
        }
        if c == ':' {
            return refuse(format!(
                "path contains a colon (drive letters, streams): `{}`",
                show(p)
            ));
        }
        if c.is_control() || is_invisible(c) {
            return refuse(format!(
                "path contains a control or invisible character: `{}`",
                show(p)
            ));
        }
    }
    if p.starts_with('/') {
        return refuse(format!("absolute path: `{}`", show(p)));
    }
    if p.split('/').count() > MAX_PATH_DEPTH {
        return refuse(format!(
            "path is deeper than {MAX_PATH_DEPTH} components: `{}`",
            show(p)
        ));
    }
    for comp in p.split('/') {
        match comp {
            "" => return refuse(format!("path has an empty component: `{}`", show(p))),
            "." => return refuse(format!("path has a `.` component: `{}`", show(p))),
            ".." => return refuse(format!("path has a `..` component: `{}`", show(p))),
            _ => {}
        }
        if comp.len() > MAX_COMPONENT_BYTES {
            return refuse(format!(
                "path component of {} bytes is over the {MAX_COMPONENT_BYTES}-byte cap",
                comp.len()
            ));
        }
        if is_dot_git(comp) {
            return refuse(format!("path has a `.git` component: `{}`", show(p)));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::process::Command;

    // ----- builders --------------------------------------------------------------------------------------------------

    fn recipe(scope: &[&str]) -> Recipe {
        Recipe {
            repo: "o/r".into(),
            scope: scope.iter().map(|s| (*s).to_string()).collect(),
            ..Recipe::default()
        }
    }

    /// Everything in scope, so the case under test is the only reason for a refusal.
    fn open() -> Recipe {
        recipe(&["**"])
    }

    fn modify(p: &str) -> String {
        format!("diff --git a/{p} b/{p}\nindex 1111111..2222222 100644\n--- a/{p}\n+++ b/{p}\n@@ -1 +1 @@\n-old\n+new\n")
    }

    fn new_file(p: &str, mode: &str) -> String {
        format!("diff --git a/{p} b/{p}\nnew file mode {mode}\nindex 0000000..2222222\n--- /dev/null\n+++ b/{p}\n@@ -0,0 +1 @@\n+hello\n")
    }

    fn deleted(p: &str, mode: &str) -> String {
        format!("diff --git a/{p} b/{p}\ndeleted file mode {mode}\nindex 1111111..0000000\n--- a/{p}\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n")
    }

    fn rename(from: &str, to: &str) -> String {
        format!("diff --git a/{from} b/{to}\nsimilarity index 100%\nrename from {from}\nrename to {to}\n")
    }

    fn rename_edit(from: &str, to: &str) -> String {
        format!(
            "diff --git a/{from} b/{to}\nsimilarity index 90%\nrename from {from}\nrename to {to}\nindex 1111111..2222222 100644\n--- a/{from}\n+++ b/{to}\n@@ -1 +1 @@\n-old\n+new\n"
        )
    }

    fn copy(from: &str, to: &str) -> String {
        format!(
            "diff --git a/{from} b/{to}\nsimilarity index 100%\ncopy from {from}\ncopy to {to}\n"
        )
    }

    enum Expect {
        Files(&'static [&'static str]),
        Refuse(&'static str),
    }

    struct Case {
        name: String,
        patch: String,
        recipe: Recipe,
        expect: Expect,
    }

    fn ok(name: &str, patch: String, recipe: Recipe, files: &'static [&'static str]) -> Case {
        Case {
            name: name.into(),
            patch,
            recipe,
            expect: Expect::Files(files),
        }
    }

    fn no(name: &str, patch: String, recipe: Recipe, needle: &'static str) -> Case {
        Case {
            name: name.into(),
            patch,
            recipe,
            expect: Expect::Refuse(needle),
        }
    }

    /// Run every case and report all failures at once.
    fn run(cases: Vec<Case>) -> usize {
        let n = cases.len();
        let mut failures = Vec::new();
        for c in cases {
            let got = validate_patch(&c.patch, &c.recipe);
            match (&c.expect, got) {
                (Expect::Files(want), Ok(s)) => {
                    if s.files != *want {
                        failures.push(format!(
                            "{}: files {:?}, wanted {:?}",
                            c.name, s.files, want
                        ));
                    }
                }
                (Expect::Files(_), Err(e)) => {
                    failures.push(format!("{}: unexpectedly refused: {e}", c.name))
                }
                (Expect::Refuse(n), Err(ErrandError::Patch(m))) => {
                    if !m.contains(n) {
                        failures.push(format!(
                            "{}: refused for `{m}`, wanted a reason containing `{n}`",
                            c.name
                        ));
                    }
                }
                (Expect::Refuse(_), Err(e)) => {
                    failures.push(format!("{}: wrong error type: {e:?}", c.name))
                }
                (Expect::Refuse(n), Ok(s)) => {
                    failures.push(format!("{}: ACCEPTED {s:?}, wanted refusal `{n}`", c.name))
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {n} cases failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
        n
    }

    // ----- accepted patches ------------------------------------------------------------------------------------------

    #[test]
    fn accepted_patches() {
        let src = || recipe(&["src/**", "docs/**"]);
        let multi = format!(
            "{}{}",
            "diff --git a/src/a.rs b/src/a.rs\nindex 1111111..2222222 100644\n--- a/src/a.rs\n+++ b/src/a.rs\n@@ -1,2 +1,2 @@ fn heading()\n ctx\n-old\n+new\n@@ -10 +10,2 @@\n-x\n+y\n+z\n",
            modify("docs/b.md")
        );
        run(vec![
            ok("clean in-scope edit", modify("src/lib.rs"), src(), &["src/lib.rs"]),
            ok("new file", new_file("src/new.rs", "100644"), src(), &["src/new.rs"]),
            ok("delete", deleted("src/old.rs", "100644"), src(), &["src/old.rs"]),
            ok("rename inside scope", rename("src/a.rs", "src/b.rs"), src(), &["src/a.rs", "src/b.rs"]),
            ok("rename with edit", rename_edit("src/a.rs", "docs/b.md"), src(), &["src/a.rs", "docs/b.md"]),
            ok("copy inside scope lists the destination", copy("src/a.rs", "src/c.rs"), src(), &["src/c.rs"]),
            ok(
                "empty new file (no hunks)",
                "diff --git a/src/e b/src/e\nnew file mode 100644\nindex 0000000..e69de29\n".into(),
                src(),
                &["src/e"],
            ),
            ok(
                "no-newline markers",
                "diff --git a/src/a b/src/a\nindex 1111111..2222222 100644\n--- a/src/a\n+++ b/src/a\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n".into(),
                src(),
                &["src/a"],
            ),
            ok("two hunks, two files, headings, omitted counts", multi, src(), &["src/a.rs", "docs/b.md"]),
            ok(
                "name with a space (git adds a trailing tab)",
                "diff --git a/src/sp ace.txt b/src/sp ace.txt\nindex 1111111..2222222 100644\n--- a/src/sp ace.txt\t\n+++ b/src/sp ace.txt\t\n@@ -1 +1 @@\n-x\n+y\n".into(),
                src(),
                &["src/sp ace.txt"],
            ),
            ok(
                "quoted unicode path",
                "diff --git \"a/src/caf\\303\\251.rs\" \"b/src/caf\\303\\251.rs\"\nindex 1111111..2222222 100644\n--- \"a/src/caf\\303\\251.rs\"\n+++ \"b/src/caf\\303\\251.rs\"\n@@ -1 +1 @@\n-x\n+y\n".into(),
                src(),
                &["src/café.rs"],
            ),
            ok(
                "quoted path with an escaped quote",
                "diff --git \"a/src/we\\\"ird\" \"b/src/we\\\"ird\"\nindex 1111111..2222222 100644\n--- \"a/src/we\\\"ird\"\n+++ \"b/src/we\\\"ird\"\n@@ -1 +1 @@\n-x\n+y\n".into(),
                src(),
                &["src/we\"ird"],
            ),
            ok(
                "CR inside hunk content is data",
                "diff --git a/src/w b/src/w\nindex 1111111..2222222 100644\n--- a/src/w\n+++ b/src/w\n@@ -1 +1 @@\n-old\r\n+new\r\n".into(),
                src(),
                &["src/w"],
            ),
            ok(
                "hunk content that looks like headers",
                "diff --git a/src/h b/src/h\nindex 1111111..2222222 100644\n--- a/src/h\n+++ b/src/h\n@@ -1,2 +1,2 @@\n--- a/../evil\n-- x\n+++ b/../evil\n+diff --git a/../evil b/../evil\n".into(),
                src(),
                &["src/h"],
            ),
            ok(
                "allow_protected: exact path",
                modify("Cargo.lock"),
                Recipe { allow_protected: vec!["Cargo.lock".into()], ..open() },
                &["Cargo.lock"],
            ),
            ok(
                "allow_protected: exact nested path",
                modify("svc/tests/fixture.json"),
                Recipe { allow_protected: vec!["svc/tests/fixture.json".into()], ..open() },
                &["svc/tests/fixture.json"],
            ),
        ]);
    }

    #[test]
    fn summary_counts_lines_from_hunks() {
        let multi = "diff --git a/src/a b/src/a\nindex 1111111..2222222 100644\n--- a/src/a\n+++ b/src/a\n@@ -1,3 +1,4 @@\n c\n-a\n-b\n+x\n+y\n+z\n@@ -9 +10 @@\n-q\n+r\n";
        let s = validate_patch(multi, &open()).unwrap();
        assert_eq!((s.added, s.removed), (4, 3));
        assert_eq!(s.files, vec!["src/a"]);
        let s = validate_patch(&rename("a/x", "a/y"), &open()).unwrap();
        assert_eq!((s.added, s.removed), (0, 0));
    }

    // ----- refused: structure ----------------------------------------------------------------------------------------

    #[test]
    fn refused_structure() {
        let o = open;
        let two_hunks_short = "diff --git a/s b/s\nindex 1111111..2222222 100644\n--- a/s\n+++ b/s\n@@ -1,2 +1,2 @@\n-old\n+new\n";
        let m = modify("s");
        run(vec![
            no("empty patch", String::new(), o(), "empty"),
            no("whitespace only", "\n \n\n".into(), o(), "empty"),
            no("plain text", "hello world\n".into(), o(), "no recognisable file section"),
            no(
                "traditional diff with no diff --git",
                "--- a/s\n+++ b/s\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "no recognisable file section",
            ),
            no("leading junk before the first section", format!("From: x\n\n{m}"), o(), "no recognisable file section"),
            no("no trailing newline", m.trim_end().to_string(), o(), "newline"),
            no("trailing garbage after valid hunks", format!("{m}random trailing text\n"), o(), "after the last hunk"),
            no(
                "second traditional patch smuggled after a hunk",
                format!("{m}--- a/../evil\n+++ b/../evil\n@@ -1 +1 @@\n-a\n+b\n"),
                o(),
                "after the last hunk",
            ),
            no("blank line after a section", format!("{m}\n"), o(), "after the last hunk"),
            no(
                "garbage in the header of a header-only section",
                format!("{}echo pwned\n", rename("a", "b")),
                o(),
                "unrecognised line in a file header",
            ),
            no("hunk shorter than declared (truncated)", two_hunks_short.into(), o(), "shorter than its declared"),
            no(
                "declared body longer than actual, next section begins",
                format!("{two_hunks_short}{}", modify("t")),
                o(),
                "declared line counts",
            ),
            no(
                "extra added line beyond the declared counts",
                format!("{m}+hidden\n"),
                o(),
                "after the last hunk",
            ),
            no(
                "extra removed line inside a hunk",
                "diff --git a/s b/s\nindex 1111111..2222222 100644\n--- a/s\n+++ b/s\n@@ -1 +1 @@\n-a\n-b\n+c\n".into(),
                o(),
                "declared line counts",
            ),
            no(
                "context line beyond the declared old count",
                "diff --git a/s b/s\nindex 1111111..2222222 100644\n--- a/s\n+++ b/s\n@@ -1 +1,2 @@\n-a\n+b\n c\n".into(),
                o(),
                "declared line counts",
            ),
            no(
                "empty line inside a hunk is refused, not guessed",
                "diff --git a/s b/s\nindex 1111111..2222222 100644\n--- a/s\n+++ b/s\n@@ -1,2 +1,2 @@\n-a\n\n+b\n c\n".into(),
                o(),
                "declared line counts",
            ),
            no(
                "marker with no preceding body line",
                "diff --git a/s b/s\nindex 1111111..2222222 100644\n--- a/s\n+++ b/s\n@@ -1 +1 @@\n\\ No newline at end of file\n-a\n+b\n".into(),
                o(),
                "declared line counts",
            ),
            no(
                "malformed hunk header",
                "diff --git a/s b/s\nindex 1111111..2222222 100644\n--- a/s\n+++ b/s\n@@ -1 +1\n-a\n+b\n".into(),
                o(),
                "malformed hunk header",
            ),
            no(
                "non-numeric hunk range",
                "diff --git a/s b/s\nindex 1111111..2222222 100644\n--- a/s\n+++ b/s\n@@ -x +1 @@\n-a\n+b\n".into(),
                o(),
                "malformed number",
            ),
            no(
                "huge hunk count",
                "diff --git a/s b/s\nindex 1111111..2222222 100644\n--- a/s\n+++ b/s\n@@ -1,99999999999 +1 @@\n-a\n+b\n".into(),
                o(),
                "malformed number",
            ),
            no(
                "empty hunk",
                "diff --git a/s b/s\nindex 1111111..2222222 100644\n--- a/s\n+++ b/s\n@@ -0,0 +0,0 @@\n".into(),
                o(),
                "empty hunk",
            ),
            no(
                "--- without +++",
                "diff --git a/s b/s\nindex 1111111..2222222 100644\n--- a/s\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "not followed by a `+++`",
            ),
            no(
                "file header without hunks",
                "diff --git a/s b/s\nindex 1111111..2222222 100644\n--- a/s\n+++ b/s\n".into(),
                o(),
                "without any hunk",
            ),
            no("section that changes nothing", "diff --git a/s b/s\n".into(), o(), "changes nothing"),
            no(
                "unknown header line",
                "diff --git a/s b/s\nindex 1111111..2222222 100644\nhook: run\n--- a/s\n+++ b/s\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "unrecognised line in a file header",
            ),
            no(
                "duplicate new file mode line",
                "diff --git a/s b/s\nnew file mode 100644\nnew file mode 100644\n".into(),
                o(),
                "duplicate",
            ),
            no(
                "new and deleted in one section",
                "diff --git a/s b/s\nnew file mode 100644\ndeleted file mode 100644\n".into(),
                o(),
                "conflicting operations",
            ),
            no(
                "rename with only a from line",
                "diff --git a/s b/t\nrename from s\n".into(),
                o(),
                "needs both",
            ),
            no("rename onto itself", rename("s", "s"), o(), "onto itself"),
            no(
                "malformed index line",
                "diff --git a/s b/s\nindex zz..yy 100644\n--- a/s\n+++ b/s\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "malformed `index`",
            ),
            no(
                "new file hunk keeps old content",
                "diff --git a/s b/s\nnew file mode 100644\nindex 0000000..2222222\n--- /dev/null\n+++ b/s\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "new file",
            ),
            no(
                "deleted file hunk adds content",
                "diff --git a/s b/s\ndeleted file mode 100644\nindex 1111111..0000000\n--- a/s\n+++ /dev/null\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "deleted file",
            ),
        ]);
    }

    // ----- refused: modes and kinds ----------------------------------------------------------------------------------

    #[test]
    fn refused_modes_and_kinds() {
        let o = open;
        let edit_with_mode = |mode: &str| {
            format!("diff --git a/s b/s\nindex 1111111..2222222 {mode}\n--- a/s\n+++ b/s\n@@ -1 +1 @@\n-a\n+b\n")
        };
        run(vec![
            no("new symlink", new_file("s", "120000"), o(), "symlink"),
            no("deleted symlink", deleted("s", "120000"), o(), "symlink"),
            no("edit of an existing symlink (index mode)", edit_with_mode("120000"), o(), "symlink"),
            no("new gitlink", new_file("sub", "160000"), o(), "gitlink"),
            no("deleted gitlink", deleted("sub", "160000"), o(), "gitlink"),
            no("edit of a gitlink (index mode)", edit_with_mode("160000"), o(), "gitlink"),
            no(
                "mode change old/new mode",
                "diff --git a/s b/s\nold mode 100644\nnew mode 100755\n".into(),
                o(),
                "mode change",
            ),
            no(
                "mode change plus content",
                "diff --git a/s b/s\nold mode 100644\nnew mode 100644\nindex 1111111..2222222\n--- a/s\n+++ b/s\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "mode change",
            ),
            no("new executable file", new_file("s.sh", "100755"), o(), "executable"),
            no("deleted executable file", deleted("s.sh", "100755"), o(), "executable"),
            no("edit of an executable (index mode)", edit_with_mode("100755"), o(), "executable"),
            no("unusual mode", new_file("s", "100664"), o(), "unsupported file mode"),
            no("directory mode", new_file("s", "040000"), o(), "unsupported file mode"),
            no(
                "edit with no index line (could land on a symlink)",
                "diff --git a/s b/s\n--- a/s\n+++ b/s\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "no `index",
            ),
            no(
                "index without a mode on an edit (type unverifiable)",
                "diff --git a/s b/s\nindex 1111111..2222222\n--- a/s\n+++ b/s\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "no `index",
            ),
            no(
                "binary files differ",
                "diff --git a/s.png b/s.png\nindex 1111111..2222222 100644\nBinary files a/s.png and b/s.png differ\n".into(),
                o(),
                "binary",
            ),
            no(
                "new binary file",
                "diff --git a/s.png b/s.png\nnew file mode 100644\nindex 0000000..2222222\nBinary files /dev/null and b/s.png differ\n".into(),
                o(),
                "binary",
            ),
            no(
                "git binary patch",
                "diff --git a/s.bin b/s.bin\nindex 1111111..2222222 100644\nGIT binary patch\nliteral 1\nIcmZ?b\n\nliteral 0\nHcmV?d00001\n".into(),
                o(),
                "binary",
            ),
        ]);
    }

    // ----- refused: paths --------------------------------------------------------------------------------------------

    #[test]
    fn refused_paths() {
        let o = open;
        let q = |a: &str| {
            format!(
                "diff --git \"a/{a}\" \"b/{a}\"\nindex 1111111..2222222 100644\n--- \"a/{a}\"\n+++ \"b/{a}\"\n@@ -1 +1 @@\n-x\n+y\n"
            )
        };
        run(vec![
            no("dot-dot at the start", modify("../evil"), o(), "`..` component"),
            no("dot-dot in the middle", modify("src/../b"), o(), "`..` component"),
            no("dot-dot at the end", modify("src/.."), o(), "`..` component"),
            no("absolute path", modify("/etc/passwd"), o(), "absolute"),
            no("empty component", modify("src//x"), o(), "empty component"),
            no("trailing slash", modify("src/x/"), o(), "empty component"),
            no("dot component", modify("src/./x"), o(), "`.` component"),
            no("git hooks", modify(".git/hooks/pre-commit"), o(), "`.git` component"),
            no("nested .git", modify("sub/.git/config"), o(), "`.git` component"),
            no("upper-case .GIT", modify(".GIT/config"), o(), "`.git` component"),
            no("ntfs trailing space .git", modify(".git /config"), o(), "`.git` component"),
            no("ntfs trailing dot .git.", modify(".git./config"), o(), "`.git` component"),
            no("8.3 alias GIT~1", modify("GIT~1/config"), o(), "`.git` component"),
            no("backslash", modify("src\\evil"), o(), "backslash"),
            no("drive letter / stream colon", modify("C:evil"), o(), "colon"),
            no("raw escape character", modify("src/x\u{1b}y"), o(), "control"),
            no("raw tab in a path", modify("src/x\ty"), o(), "control"),
            no("bidi override", modify("src/x\u{202e}gnp.rs"), o(), "invisible"),
            no("zero-width space", modify("src/x\u{200b}y"), o(), "invisible"),
            no("quoted NUL", q("src/x\\000y"), o(), "NUL"),
            no("quoted newline", q("src/x\\ny"), o(), "control"),
            no("quoted CR", q("src/x\\ry"), o(), "control"),
            no("quoted backslash", q("src/x\\\\y"), o(), "backslash"),
            no("quoted dot-dot via octal", q("\\056\\056/evil"), o(), "`..` component"),
            no("quoted .git via octal", q("\\056git/config"), o(), "`.git` component"),
            no("quoted invalid UTF-8", q("src/\\377x"), o(), "UTF-8"),
            no("quoted unknown escape", q("src/\\qx"), o(), "unknown escape"),
            no("quoted truncated octal", q("src/\\34"), o(), "octal"),
            no("unterminated quote", "diff --git \"a/x b/x\n".into(), o(), "unterminated"),
            no("path over the length cap", modify(&"a/".repeat(2100)), o(), "cap"),
            no("component over the length cap", modify(&"a".repeat(300)), o(), "cap"),
            no("empty path", modify(""), o(), "empty path"),
            no("path deeper than the depth cap", modify(&"d/".repeat(70)), o(), "deeper than"),
            no(
                "rename destination is unsafe",
                rename("src/a", "../evil"),
                o(),
                "`..` component",
            ),
            no("rename source is .git", rename(".git/config", "src/a"), o(), "`.git` component"),
            no(
                "CRLF transport of the whole patch",
                modify("src/a.rs").replace('\n', "\r\n"),
                o(),
                "carriage return",
            ),
            no(
                "CR hidden at the end of a path",
                "diff --git a/src/a\r b/src/a\r\nindex 1111111..2222222 100644\n--- a/src/a\r\n+++ b/src/a\r\n@@ -1 +1 @@\n-x\n+y\n".into(),
                o(),
                "carriage return",
            ),
        ]);
    }

    // ----- refused: policy -------------------------------------------------------------------------------------------

    #[test]
    fn refused_protected_paths() {
        let paths = [
            ".github/workflows/ci.yml",
            ".github/CODEOWNERS",
            "Jenkinsfile",
            "ci/Jenkinsfile.release",
            ".gitlab-ci.yml",
            "Dockerfile",
            "svc/Dockerfile.dev",
            "Cargo.lock",
            "crates/x/Cargo.lock",
            "yarn.lock",
            "web/package-lock.json",
            "web/pnpm-lock.yaml",
            "tests/a.rs",
            "x/tests/y.rs",
            "x/test/y.py",
            "src/foo_test.go",
            "src/foo.test.ts",
            ".gitignore",
            ".gitmodules",
            "sub/.gitattributes",
            "Makefile",
            "crates/x/build.rs",
            "infra/main.tf",
            "docs/CODEOWNERS",
            "AGENT.md",
            "pkg/CLAUDE.md",
            ".claude/agents/x.md",
            "JENKINSFILE",
        ];
        let mut cases: Vec<Case> = paths
            .iter()
            .map(|p| {
                no(
                    &format!("protected: edit {p}"),
                    modify(p),
                    open(),
                    "protected",
                )
            })
            .collect();
        cases.push(no(
            "protected: delete Cargo.lock",
            deleted("Cargo.lock", "100644"),
            open(),
            "protected",
        ));
        cases.push(no(
            "protected: new Jenkinsfile",
            new_file("Jenkinsfile", "100644"),
            open(),
            "protected",
        ));
        cases.push(no(
            "protected: rename into tests/",
            rename("src/a.rs", "src/tests/a.rs"),
            open(),
            "protected",
        ));
        cases.push(no(
            "protected: rename out of .github",
            rename(".github/a.yml", "src/a.yml"),
            open(),
            "protected",
        ));
        cases.push(no(
            "protected: copy from a lockfile",
            copy("Cargo.lock", "src/x"),
            open(),
            "protected",
        ));
        let n = run(cases);
        assert!(n >= 30);
    }

    #[test]
    fn refused_scope() {
        let s = || recipe(&["src/**"]);
        run(vec![
            no(
                "outside scope",
                modify("other/x.rs"),
                s(),
                "outside the recipe scope",
            ),
            no(
                "outside scope: delete",
                deleted("other/x.rs", "100644"),
                s(),
                "outside the recipe scope",
            ),
            no(
                "outside scope: new file",
                new_file("other/x.rs", "100644"),
                s(),
                "outside the recipe scope",
            ),
            no(
                "rename OUT of scope",
                rename("src/a.rs", "other/a.rs"),
                s(),
                "outside the recipe scope",
            ),
            no(
                "rename INTO scope from outside",
                rename("other/a.rs", "src/a.rs"),
                s(),
                "outside the recipe scope",
            ),
            no(
                "copy out of scope",
                copy("other/a.rs", "src/a.rs"),
                s(),
                "outside the recipe scope",
            ),
            no(
                "empty scope allows nothing",
                modify("src/lib.rs"),
                recipe(&[]),
                "outside the recipe scope",
            ),
            no(
                "scope is case-sensitive",
                modify("SRC/lib.rs"),
                s(),
                "outside the recipe scope",
            ),
            no(
                "star does not cross a slash",
                modify("src/deep/x.rs"),
                recipe(&["src/*.rs"]),
                "outside the recipe scope",
            ),
            no(
                "two files, one out of scope",
                format!("{}{}", modify("src/a.rs"), modify("other/b.rs")),
                s(),
                "outside the recipe scope",
            ),
            no(
                "scope-looking prefix is not a directory match",
                modify("src2/x.rs"),
                s(),
                "outside the recipe scope",
            ),
        ]);
    }

    #[test]
    fn allow_protected_is_exact_not_broader() {
        let allow = |p: &[&str]| Recipe {
            allow_protected: p.iter().map(|s| (*s).to_string()).collect(),
            ..open()
        };
        run(vec![
            no(
                "prefix entry does not unlock a child",
                modify("tests/a.rs"),
                allow(&["tests"]),
                "protected",
            ),
            no(
                "directory entry with slash does not unlock",
                modify("tests/a.rs"),
                allow(&["tests/"]),
                "protected",
            ),
            no(
                "other file in the same directory stays protected",
                modify(".github/workflows/b.yml"),
                allow(&[".github/workflows/a.yml"]),
                "protected",
            ),
            no(
                "different case does not match",
                modify("cargo.lock"),
                allow(&["Cargo.lock"]),
                "protected",
            ),
            no(
                "nested lockfile is not the root one",
                modify("sub/Cargo.lock"),
                allow(&["Cargo.lock"]),
                "protected",
            ),
            no(
                "one allowed file does not unlock its sibling in a multi-file patch",
                format!("{}{}", modify("Cargo.lock"), modify("pnpm-lock.yaml")),
                allow(&["Cargo.lock"]),
                "pnpm-lock.yaml",
            ),
            no(
                "allow_protected never overrides scope",
                modify("Cargo.lock"),
                Recipe {
                    allow_protected: vec!["Cargo.lock".into()],
                    ..recipe(&["src/**"])
                },
                "outside the recipe scope",
            ),
            no(
                "allow_protected never overrides .git",
                modify(".git/config"),
                allow(&[".git/config"]),
                "`.git` component",
            ),
            no(
                "allow_protected never overrides path syntax",
                modify("../tests/a.rs"),
                allow(&["../tests/a.rs"]),
                "`..` component",
            ),
            no(
                "a rename needs both ends allowed",
                rename("Cargo.lock", "src/x.lock"),
                allow(&["Cargo.lock"]),
                "src/x.lock",
            ),
        ]);
    }

    #[test]
    fn refused_disagreeing_names() {
        let o = open;
        run(vec![
            no(
                "+++ names a different file than the header",
                "diff --git a/ok b/ok\nindex 1111111..2222222 100644\n--- a/ok\n+++ b/../evil\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "disagree",
            ),
            no(
                "--- names a different file than the header",
                "diff --git a/ok b/ok\nindex 1111111..2222222 100644\n--- a/evil\n+++ b/ok\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "disagree",
            ),
            no(
                "+++ names a protected file while the header names a free one",
                "diff --git a/ok b/ok\nindex 1111111..2222222 100644\n--- a/ok\n+++ b/Jenkinsfile\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "disagree",
            ),
            no(
                "header pair names two files with no rename",
                "diff --git a/ok b/other\nindex 1111111..2222222 100644\n--- a/ok\n+++ b/other\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "two different files",
            ),
            no(
                "rename lines disagree with the header",
                "diff --git a/src/a b/src/b\nsimilarity index 100%\nrename from src/a\nrename to ../evil\n".into(),
                o(),
                "does not name the rename/copy pair",
            ),
            no(
                "rename source disagrees with the header",
                "diff --git a/src/a b/src/b\nsimilarity index 100%\nrename from .github/x\nrename to src/b\n".into(),
                o(),
                "does not name the rename/copy pair",
            ),
            no(
                "+++ disagrees with rename to",
                "diff --git a/src/a b/src/b\nsimilarity index 90%\nrename from src/a\nrename to src/b\nindex 1111111..2222222 100644\n--- a/src/a\n+++ b/Jenkinsfile\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "disagree",
            ),
            no(
                "/dev/null on a plain edit",
                "diff --git a/ok b/ok\nindex 1111111..2222222 100644\n--- /dev/null\n+++ b/ok\n@@ -0,0 +1 @@\n+b\n".into(),
                o(),
                "disagree",
            ),
            no(
                "new file claim with a real --- name",
                "diff --git a/ok b/ok\nnew file mode 100644\nindex 0000000..2222222\n--- a/ok\n+++ b/ok\n@@ -0,0 +1 @@\n+b\n".into(),
                o(),
                "disagree",
            ),
            no(
                "deleted claim with a real +++ name",
                "diff --git a/ok b/ok\ndeleted file mode 100644\nindex 1111111..0000000\n--- a/ok\n+++ b/ok\n@@ -1 +0,0 @@\n-b\n".into(),
                o(),
                "disagree",
            ),
            no(
                "tab smuggles a second name after a valid one",
                "diff --git a/ok b/ok\nindex 1111111..2222222 100644\n--- a/ok\n+++ b/ok\t../../evil\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "disagree",
            ),
            no(
                "missing a/ prefix on ---",
                "diff --git a/ok b/ok\nindex 1111111..2222222 100644\n--- ok\n+++ b/ok\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "does not start with `a/`",
            ),
            no(
                "diff --git line without prefixes",
                "diff --git ok ok\nindex 1111111..2222222 100644\n--- a/ok\n+++ b/ok\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "does not name",
            ),
            no(
                "diff --git line with a foreign prefix git would strip",
                "diff --git a/ok zz/ok\nindex 1111111..2222222 100644\n--- a/ok\n+++ b/ok\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "does not name",
            ),
            no(
                "quoted header, raw +++ for another name",
                "diff --git \"a/ok\\303\\251\" \"b/ok\\303\\251\"\nindex 1111111..2222222 100644\n--- \"a/ok\\303\\251\"\n+++ b/okx\n@@ -1 +1 @@\n-a\n+b\n".into(),
                o(),
                "disagree",
            ),
        ]);
    }

    #[test]
    fn refused_duplicates_and_conflicts() {
        let o = open;
        run(vec![
            no(
                "same file twice",
                format!("{}{}", modify("src/a"), modify("src/a")),
                o(),
                "more than once",
            ),
            no(
                "same file twice, differing only by case",
                format!("{}{}", modify("src/a.rs"), modify("src/A.rs")),
                o(),
                "more than once",
            ),
            no(
                "edit plus delete of the same file",
                format!("{}{}", modify("src/a"), deleted("src/a", "100644")),
                o(),
                "more than once",
            ),
            no(
                "rename destination edited again",
                format!("{}{}", rename("src/a", "src/b"), modify("src/b")),
                o(),
                "more than once",
            ),
            no(
                "rename source recreated",
                format!(
                    "{}{}",
                    rename("src/a", "src/b"),
                    new_file("src/a", "100644")
                ),
                o(),
                "more than once",
            ),
            no(
                "file and directory of the same name",
                format!(
                    "{}{}",
                    new_file("src/a", "100644"),
                    new_file("src/a/b", "100644")
                ),
                o(),
                "both a file and a directory",
            ),
            no(
                "directory first, then file of that name",
                format!(
                    "{}{}",
                    new_file("src/a/b", "100644"),
                    new_file("src/a", "100644")
                ),
                o(),
                "both a file and a directory",
            ),
        ]);
    }

    // ----- limits ----------------------------------------------------------------------------------------------------

    #[test]
    fn max_files_boundary() {
        let three = format!("{}{}{}", modify("a/1"), modify("a/2"), modify("a/3"));
        let at = |n| Recipe {
            max_files: Some(n),
            ..open()
        };
        assert_eq!(validate_patch(&three, &at(3)).unwrap().files.len(), 3);
        assert!(
            matches!(validate_patch(&three, &at(2)), Err(ErrandError::Patch(m)) if m.contains("3 files"))
        );
        assert!(validate_patch(
            &three,
            &Recipe {
                max_files: None,
                ..open()
            }
        )
        .is_ok());
        // A rename touches two paths and is counted as two.
        let r = rename("a/x", "a/y");
        assert!(validate_patch(&r, &at(2)).is_ok());
        assert!(validate_patch(&r, &at(1)).is_err());
        assert!(validate_patch(&modify("a/1"), &at(0)).is_err());
    }

    #[test]
    fn max_lines_boundary() {
        // `modify` adds one line and removes one: two changed lines.
        let at = |n| Recipe {
            max_lines: Some(n),
            ..open()
        };
        assert_eq!(validate_patch(&modify("a/1"), &at(2)).unwrap().added, 1);
        assert!(
            matches!(validate_patch(&modify("a/1"), &at(1)), Err(ErrandError::Patch(m)) if m.contains("2 lines"))
        );
        let two = format!("{}{}", modify("a/1"), modify("a/2"));
        assert!(validate_patch(&two, &at(4)).is_ok());
        assert!(validate_patch(&two, &at(3)).is_err());
        assert!(validate_patch(&modify("a/1"), &at(0)).is_err());
    }

    #[test]
    fn path_depth_boundary() {
        let at_cap = format!("{}f", "d/".repeat(MAX_PATH_DEPTH - 1));
        assert!(validate_patch(&modify(&at_cap), &open()).is_ok());
        let over = format!("{}f", "d/".repeat(MAX_PATH_DEPTH));
        assert!(
            matches!(validate_patch(&modify(&over), &open()), Err(ErrandError::Patch(m)) if m.contains("deeper"))
        );
    }

    #[test]
    fn rename_with_one_quoted_and_one_plain_name() {
        // git quotes each name independently: a plain source and a quoted (non-ASCII) destination.
        let p = "diff --git a/src/a \"b/src/caf\\303\\251\"\nsimilarity index 100%\nrename from src/a\nrename to \"src/caf\\303\\251\"\n";
        let s = validate_patch(p, &open()).unwrap();
        assert_eq!(s.files, vec!["src/a", "src/café"]);
        // ... and the reverse.
        let p = "diff --git \"a/src/caf\\303\\251\" b/src/a\nsimilarity index 100%\nrename from \"src/caf\\303\\251\"\nrename to src/a\n";
        assert_eq!(
            validate_patch(p, &open()).unwrap().files,
            vec!["src/café", "src/a"]
        );
        // A quoted destination that decodes to something other than the header's is a disagreement.
        let p = "diff --git a/src/a \"b/src/caf\\303\\251\"\nsimilarity index 100%\nrename from src/a\nrename to src/cafe\n";
        assert!(
            matches!(validate_patch(p, &open()), Err(ErrandError::Patch(m)) if m.contains("rename/copy pair"))
        );
    }

    #[test]
    fn size_cap_boundary() {
        // A new file whose body is padded so the whole patch is exactly `total` bytes.
        let build = |total: usize| {
            let head = "diff --git a/big b/big\nnew file mode 100644\nindex 0000000..2222222\n--- /dev/null\n+++ b/big\n";
            let lines = 1000;
            let hunk = format!("@@ -0,0 +1,{lines} @@\n");
            let fixed = head.len() + hunk.len() + (lines - 1) * 3 + 2; // 999 lines of "+x\n", then "+" ... "\n"
            let mut s = String::with_capacity(total);
            s.push_str(head);
            s.push_str(&hunk);
            for _ in 0..lines - 1 {
                s.push_str("+x\n");
            }
            s.push('+');
            s.push_str(&"y".repeat(total - fixed));
            s.push('\n');
            assert_eq!(s.len(), total);
            s
        };
        let at_cap = validate_patch(&build(MAX_PATCH_BYTES), &open()).unwrap();
        assert_eq!(
            (at_cap.added, at_cap.files),
            (1000, vec!["big".to_string()])
        );
        let over = validate_patch(&build(MAX_PATCH_BYTES + 1), &open());
        assert!(matches!(over, Err(ErrandError::Patch(m)) if m.contains("cap")));
        assert!(matches!(
            changed_paths(&build(MAX_PATCH_BYTES + 1)),
            Err(ErrandError::Patch(_))
        ));
    }

    #[test]
    fn many_ambiguous_header_candidates_stay_fast() {
        // A single header line stuffed with ` b/` separators must not trigger quadratic work.
        let name = "a/".to_string() + &" b/a".repeat(1000);
        let patch = format!("diff --git {name} {name}\n");
        let started = std::time::Instant::now();
        let _ = validate_patch(&patch, &open());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        // And a line over the header cap is refused outright.
        let long = format!("diff --git a/{} b/x\n", "q".repeat(MAX_HEADER_LINE_BYTES));
        assert!(
            matches!(validate_patch(&long, &open()), Err(ErrandError::Patch(m)) if m.contains("cap"))
        );
    }

    // ----- changed_paths ---------------------------------------------------------------------------------------------

    #[test]
    fn changed_paths_lists_files_without_policy() {
        let p = format!(
            "{}{}{}",
            modify("Cargo.lock"),
            rename("x/a", "y/b"),
            copy("m/n", "m/o")
        );
        assert_eq!(
            changed_paths(&p).unwrap(),
            vec!["Cargo.lock", "x/a", "y/b", "m/o"]
        );
        // ... but it still refuses what cannot be parsed or names an unsafe path.
        assert!(changed_paths(&modify("../x")).is_err());
        assert!(changed_paths("").is_err());
        assert!(changed_paths(&new_file("l", "120000")).is_err());
    }

    #[test]
    fn truncating_a_valid_patch_never_panics_and_rarely_validates() {
        let full = format!(
            "{}{}{}",
            modify("src/a"),
            "diff --git a/src/b b/src/b\nindex 1111111..2222222 100644\n--- a/src/b\n+++ b/src/b\n@@ -1 +1 @@\n-a\n+b\n@@ -5 +5 @@\n-c\n+d\n",
            new_file("src/c", "100644")
        );
        let mut accepted = 0;
        for (i, _) in full.char_indices() {
            if validate_patch(&full[..i], &open()).is_ok() {
                accepted += 1;
            }
        }
        // Only cuts that land exactly on a hunk boundary are themselves valid patches.
        assert!(accepted <= 5, "accepted {accepted} truncations");
        assert!(validate_patch(&full, &open()).is_ok());
    }

    // ----- cross-check against real git ------------------------------------------------------------------------------

    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    /// Run git hermetically (no user or system config); panics on failure so a broken fixture is loud.
    fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
        let out = Command::new("git")
            .current_dir(dir)
            .args([
                "-c",
                "core.quotepath=true",
                "-c",
                "diff.noprefix=false",
                "-c",
                "core.autocrlf=false",
            ])
            .args([
                "-c",
                "commit.gpgsign=false",
                "-c",
                "protocol.file.allow=always",
                "-c",
                "core.fileMode=true",
            ])
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .output()
            .expect("spawn git");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    const BASE_FILES: &[(&str, &str)] = &[
        (
            "src/a.rs",
            "one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\n",
        ),
        ("src/sp ace.txt", "x\ny\n"),
        ("src/café.txt", "ü\n"),
        (
            "src/old_name.rs",
            "l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\n",
        ),
        ("src/moved.rs", "m1\nm2\nm3\nm4\nm5\n"),
        ("docs/gone.md", "bye\n"),
    ];

    /// A repo with one commit; returns (tempdir, base path).
    fn base_repo() -> (tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        std::fs::create_dir_all(&base).unwrap();
        git(&base, &["init", "-q", "-b", "main"]);
        for (p, t) in BASE_FILES {
            write(&base, p, t);
        }
        git(&base, &["add", "-A"]);
        git(&base, &["commit", "-q", "-m", "base"]);
        (tmp, base)
    }

    /// Clone the base into a scratch repo and ask real git whether it would apply `patch`.
    fn git_apply_check(tmp: &Path, base: &Path, patch: &[u8]) -> std::process::Output {
        let scratch = tmp.join(format!("scratch-{}", patch.len()));
        git(
            tmp,
            &[
                "clone",
                "-q",
                base.to_str().unwrap(),
                scratch.to_str().unwrap(),
            ],
        );
        std::fs::write(scratch.join("p.patch"), patch).unwrap();
        Command::new("git")
            .current_dir(&scratch)
            .args(["apply", "--check", "p.patch"])
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap()
    }

    fn token_set(z: &[u8]) -> std::collections::BTreeSet<String> {
        z.split(|b| *b == 0)
            .filter(|t| !t.is_empty())
            .map(|t| String::from_utf8(t.to_vec()).unwrap())
            .collect()
    }

    #[test]
    fn git_cross_check_edit_add_delete_with_awkward_names() {
        if !git_available() {
            eprintln!("git not found; skipping");
            return;
        }
        let (tmp, base) = base_repo();
        write(
            &base,
            "src/a.rs",
            "one\ntwo\nTHREE\nfour\nfive\nsix\nseven\neight\nnine\nten\neleven\n",
        );
        write(&base, "src/sp ace.txt", "x\ny\nz\n");
        write(&base, "src/café.txt", "ü\nö\n");
        write(&base, "src/new file.rs", "fresh\n");
        write(&base, "src/naïve.rs", "fresh\n");
        std::fs::remove_file(base.join("docs/gone.md")).unwrap();
        git(&base, &["add", "-A"]);
        let patch = git(&base, &["diff", "--cached", "--no-renames"]);
        let patch_text = String::from_utf8(patch.clone()).unwrap();

        let summary = validate_patch(&patch_text, &open()).unwrap();
        let theirs = token_set(&git(
            &base,
            &["diff", "--cached", "--no-renames", "--name-only", "-z"],
        ));
        let ours: std::collections::BTreeSet<String> = summary.files.iter().cloned().collect();
        assert_eq!(
            ours, theirs,
            "validator and git disagree about the file list"
        );
        assert_eq!(ours.len(), summary.files.len(), "file list has duplicates");
        assert_eq!(changed_paths(&patch_text).unwrap(), summary.files);

        // Line counts agree with git's own numstat.
        let numstat = String::from_utf8(git(
            &base,
            &["diff", "--cached", "--no-renames", "--numstat"],
        ))
        .unwrap();
        let (mut add, mut del) = (0, 0);
        for l in numstat.lines() {
            let mut it = l.split('\t');
            add += it.next().unwrap().parse::<usize>().unwrap();
            del += it.next().unwrap().parse::<usize>().unwrap();
        }
        assert_eq!((summary.added, summary.removed), (add, del));

        let applied = git_apply_check(tmp.path(), &base, &patch);
        assert!(
            applied.status.success(),
            "git refused an accepted patch: {}",
            String::from_utf8_lossy(&applied.stderr)
        );
    }

    #[test]
    fn git_cross_check_renames_and_copies() {
        if !git_available() {
            eprintln!("git not found; skipping");
            return;
        }
        let (tmp, base) = base_repo();
        // One rename with an edit, one pure rename.
        std::fs::rename(base.join("src/old_name.rs"), base.join("src/renamed.rs")).unwrap();
        write(
            &base,
            "src/renamed.rs",
            "l1\nl2\nl3\nCHANGED\nl5\nl6\nl7\nl8\nl9\nl10\n",
        );
        std::fs::rename(base.join("src/moved.rs"), base.join("docs/mövéd.rs")).unwrap();
        git(&base, &["add", "-A"]);
        let patch = git(&base, &["diff", "--cached", "-M"]);
        let patch_text = String::from_utf8(patch.clone()).unwrap();
        assert!(
            patch_text.contains("rename from"),
            "fixture should contain renames:\n{patch_text}"
        );

        let summary = validate_patch(&patch_text, &open()).unwrap();
        // `--name-status -z` yields `R095 \0 old \0 new \0`.
        let status = git(&base, &["diff", "--cached", "-M", "--name-status", "-z"]);
        let mut theirs = std::collections::BTreeSet::new();
        let mut it = status
            .split(|b| *b == 0)
            .filter(|t| !t.is_empty())
            .map(|t| String::from_utf8(t.to_vec()).unwrap());
        while let Some(code) = it.next() {
            let n = if code.starts_with('R') || code.starts_with('C') {
                2
            } else {
                1
            };
            for _ in 0..n {
                theirs.insert(it.next().unwrap());
            }
        }
        let ours: std::collections::BTreeSet<String> = summary.files.iter().cloned().collect();
        assert_eq!(ours, theirs);
        assert!(
            ours.contains("src/old_name.rs")
                && ours.contains("src/renamed.rs")
                && ours.contains("docs/mövéd.rs")
        );

        let applied = git_apply_check(tmp.path(), &base, &patch);
        assert!(
            applied.status.success(),
            "{}",
            String::from_utf8_lossy(&applied.stderr)
        );

        // The same rename is refused when the destination leaves the scope.
        assert!(validate_patch(&patch_text, &recipe(&["src/**"])).is_err());
    }

    #[test]
    fn git_cross_check_refusals_of_real_git_output() {
        if !git_available() {
            eprintln!("git not found; skipping");
            return;
        }
        // Each scenario mutates a fresh repo, lets git produce the patch, and expects the validator to refuse it.
        type Mutate = fn(&Path);
        let scenarios: Vec<(&str, Mutate, &str)> = vec![
            (
                "binary file",
                |b| std::fs::write(b.join("src/blob.bin"), [0u8, 159, 146, 150, 0, 1, 2]).unwrap(),
                "binary",
            ),
            (
                "gitlink",
                |b| {
                    // A nested repository with a commit is staged by `git add -A` as a mode 160000 entry.
                    let sub = b.join("src/sub");
                    std::fs::create_dir_all(&sub).unwrap();
                    git(&sub, &["init", "-q"]);
                    git(&sub, &["commit", "-q", "--allow-empty", "-m", "inner"]);
                },
                "gitlink",
            ),
            #[cfg(unix)]
            (
                "new symlink",
                |b| std::os::unix::fs::symlink("../../../etc/passwd", b.join("src/link")).unwrap(),
                "symlink",
            ),
            #[cfg(unix)]
            (
                "chmod +x",
                |b| {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        b.join("src/a.rs"),
                        std::fs::Permissions::from_mode(0o755),
                    )
                    .unwrap();
                },
                "mode change",
            ),
        ];
        for (name, mutate, needle) in scenarios {
            let (_tmp, base) = base_repo();
            mutate(&base);
            git(&base, &["add", "-A"]);
            let patch = String::from_utf8(git(
                &base,
                &["diff", "--cached", "--no-renames", "--binary"],
            ))
            .unwrap();
            assert!(!patch.is_empty(), "{name}: git produced no patch");
            match validate_patch(&patch, &open()) {
                Err(ErrandError::Patch(m)) if m.contains(needle) => {}
                other => panic!(
                    "{name}: expected a refusal containing `{needle}`, got {other:?}\n{patch}"
                ),
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn git_cross_check_edit_of_an_existing_symlink() {
        if !git_available() {
            eprintln!("git not found; skipping");
            return;
        }
        let (tmp, base) = base_repo();
        std::os::unix::fs::symlink("a.rs", base.join("src/link")).unwrap();
        git(&base, &["add", "-A"]);
        git(&base, &["commit", "-q", "-m", "add a symlink"]);

        // 1. Editing the symlink target in real git output carries `index ... 120000` and is refused.
        std::fs::remove_file(base.join("src/link")).unwrap();
        std::os::unix::fs::symlink("../../etc/passwd", base.join("src/link")).unwrap();
        git(&base, &["add", "-A"]);
        let real = String::from_utf8(git(&base, &["diff", "--cached"])).unwrap();
        assert!(
            matches!(validate_patch(&real, &open()), Err(ErrandError::Patch(m)) if m.contains("symlink")),
            "{real}"
        );

        // 2. A forged edit with no index line DOES apply to the symlink under git: the validator must refuse it by itself.
        let forged = "diff --git a/src/link b/src/link\n--- a/src/link\n+++ b/src/link\n@@ -1 +1 @@\n-a.rs\n\\ No newline at end of file\n+evil\n\\ No newline at end of file\n";
        let out = git_apply_check(tmp.path(), &base_at_head(&base), forged.as_bytes());
        assert!(
            out.status.success(),
            "premise changed: git no longer applies index-less edits to symlinks"
        );
        assert!(
            matches!(validate_patch(forged, &open()), Err(ErrandError::Patch(m)) if m.contains("no `index"))
        );

        // 3. A forged edit that claims `100644` is caught by git itself ("wrong type").
        let claims = "diff --git a/src/link b/src/link\nindex 1111111..2222222 100644\n--- a/src/link\n+++ b/src/link\n@@ -1 +1 @@\n-a.rs\n\\ No newline at end of file\n+evil\n\\ No newline at end of file\n";
        let out = git_apply_check(tmp.path(), &base_at_head(&base), claims.as_bytes());
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("wrong type"));
    }

    /// What git itself says a patch touches: `(sorted paths, added, removed)` from `git apply --numstat -z`.
    /// `None` when git refuses to parse the patch.
    fn git_numstat(patch: &str) -> Option<(Vec<String>, usize, usize)> {
        use std::io::Write;
        let mut child = Command::new("git")
            .args(["apply", "--numstat", "-z"])
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(patch.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        if !out.status.success() {
            return None;
        }
        let (mut paths, mut add, mut del) = (Vec::new(), 0, 0);
        for rec in out.stdout.split(|b| *b == 0).filter(|r| !r.is_empty()) {
            let text = String::from_utf8_lossy(rec);
            let mut it = text.splitn(3, '\t');
            add += it.next()?.parse::<usize>().ok()?;
            del += it.next()?.parse::<usize>().ok()?;
            paths.push(it.next()?.to_string());
        }
        paths.sort();
        Some((paths, add, del))
    }

    /// Differential test: corrupt valid git patches thousands of ways. Whatever the validator accepts, git must read the
    /// same way (same files, same line counts). A mutant that git reads differently is a validator/applier disagreement.
    #[test]
    fn mutated_patches_that_validate_are_read_identically_by_git() {
        if !git_available() {
            eprintln!("git not found; skipping");
            return;
        }
        let seeds = [
            format!(
                "{}{}{}",
                modify("src/a.rs"),
                new_file("src/sp ace.rs", "100644"),
                deleted("docs/gone.md", "100644")
            ),
            "diff --git \"a/src/caf\\303\\251.txt\" \"b/src/caf\\303\\251.txt\"\nindex 1111111..2222222 100644\n--- \"a/src/caf\\303\\251.txt\"\n+++ \"b/src/caf\\303\\251.txt\"\n@@ -1,3 +1,3 @@ heading\n a\n-b\n+c\n d\n@@ -9 +9 @@\n-x\n\\ No newline at end of file\n+y\n\\ No newline at end of file\n".into(),
        ];
        let inserts = [
            "+x",
            "-x",
            " x",
            "--- a/zz",
            "+++ b/zz",
            "diff --git a/zz b/zz",
            "rename from zz",
            "rename to zz",
            "new file mode 100644",
            "deleted file mode 100644",
            "index aaaa..bbbb 100644",
            "@@ -1 +1 @@",
            "\\ No newline at end of file",
            "",
            "GIT binary patch",
            "old mode 100644",
            "similarity index 100%",
        ];
        let bytes = *b" \t\r\"\\/.+-@ab01,";
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % n as u64) as usize
        };
        let (mut accepted, mut compared) = (0, 0);
        for round in 0..8000 {
            let mut text = seeds[round % seeds.len()].clone();
            for _ in 0..=next(3) {
                let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
                let at = next(lines.len());
                match next(5) {
                    0 => {
                        lines.remove(at);
                    }
                    1 => lines.insert(at, lines[at].clone()),
                    2 => lines.insert(at, inserts[next(inserts.len())].to_string()),
                    3 => {
                        let mut chars: Vec<char> = lines[at].chars().collect();
                        if !chars.is_empty() {
                            let c = next(chars.len());
                            chars[c] = char::from(bytes[next(bytes.len())]);
                        }
                        lines[at] = chars.into_iter().collect();
                    }
                    _ => lines.truncate(at + 1),
                }
                text = lines.join("\n");
            }
            let Ok(ours) = validate_patch(&text, &open()) else {
                continue;
            };
            accepted += 1;
            let Some((git_paths, git_add, git_del)) = git_numstat(&text) else {
                continue;
            };
            compared += 1;
            let mut our_paths = ours.files.clone();
            our_paths.sort();
            assert_eq!(
                (our_paths, ours.added, ours.removed),
                (git_paths, git_add, git_del),
                "validator and git read this patch differently:\n{text}"
            );
        }
        eprintln!("mutants accepted by the validator: {accepted}; also parsed by git and compared: {compared}");
        assert!(
            accepted > 50,
            "mutation test is not exercising the accept path ({accepted})"
        );
    }

    /// `git_apply_check` clones HEAD; the symlink test staged a change on top of HEAD, which a clone ignores.
    #[cfg(unix)]
    fn base_at_head(base: &Path) -> std::path::PathBuf {
        base.to_path_buf()
    }
}
