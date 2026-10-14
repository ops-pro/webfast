//! Caddyfile syntax: tokens, `{$ENV}` substitution, snippets, imports and the block tree.
//!
//! Only the syntax lives here; what directives mean is in `config.rs`. The rules follow Caddy's
//! lexer so a file this module accepts is read the same way by Caddy:
//!   - tokens are separated by whitespace; a newline ends a directive line unless escaped with `\`;
//!   - `#` starts a comment at the beginning of a token;
//!   - `"…"` quotes (inside, `\"` is a quote and `\` before a newline is dropped; other backslashes
//!     stay), `` `…` `` raw quotes;
//!   - `{` at the end of a line opens a block, `}` on its own line closes it;
//!   - `{$VAR}` / `{$VAR:default}` are replaced in the file text before tokenizing;
//!   - `(name) { … }` defines a snippet; `import name` or `import path/glob` splices lines in place.
//!
//! Not supported (an error, never silently ignored): heredocs, import arguments.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Token {
    pub text: String,
    pub quoted: bool,
    pub file: Arc<str>,
    pub line: usize,
}

impl Token {
    pub fn at(&self) -> Location {
        Location {
            file: self.file.clone(),
            line: self.line,
        }
    }

    /// An unquoted `{` or `}`.
    fn is_brace(&self, brace: &str) -> bool {
        !self.quoted && self.text == brace
    }
}

#[derive(Debug, Clone)]
pub struct Location {
    pub file: Arc<str>,
    pub line: usize,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file, self.line)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{at}: {message}")]
pub struct SyntaxError {
    pub at: Location,
    pub message: String,
}

pub fn error(at: Location, message: impl Into<String>) -> SyntaxError {
    SyntaxError {
        at,
        message: message.into(),
    }
}

/// A directive (or matcher definition, or subdirective): its tokens and an optional block.
#[derive(Debug, Clone)]
pub struct Line {
    pub tokens: Vec<Token>,
    pub block: Option<Vec<Line>>,
    /// Where the line starts (lines with no tokens: the global options block).
    pub at: Location,
}

impl Line {
    pub fn name(&self) -> &str {
        self.tokens.first().map(|t| t.text.as_str()).unwrap_or("")
    }
}

/// A site block: its addresses and directives.
#[derive(Debug, Clone)]
pub struct ServerBlock {
    pub keys: Vec<Token>,
    pub body: Vec<Line>,
    pub at: Location,
}

#[derive(Debug, Default)]
pub struct Caddyfile {
    pub global: Option<Vec<Line>>,
    pub sites: Vec<ServerBlock>,
}

const MAX_IMPORT_DEPTH: usize = 32;

/// Lines brought in by one `import`, with the file they came from (`None`: a snippet).
type Imported = Vec<(Vec<Line>, Option<PathBuf>)>;

/// Reads a Caddyfile from disk, resolving imports relative to the importing file.
pub fn parse_file(path: &Path) -> Result<Caddyfile, SyntaxError> {
    let text = read(path, None)?;
    parse_str(&text, path)
}

/// Parses Caddyfile text; `path` names it in errors and anchors relative imports.
pub fn parse_str(text: &str, path: &Path) -> Result<Caddyfile, SyntaxError> {
    let mut parser = Parser::default();
    let lines = parse_lines_of(text, path)?;
    let mut out = Caddyfile::default();
    let mut first = true;
    parser.top_level(lines, path, &mut out, &mut first, 0)?;
    Ok(out)
}

#[derive(Default)]
struct Parser {
    snippets: std::collections::HashMap<String, Vec<Line>>,
}

impl Parser {
    fn top_level(
        &mut self,
        lines: Vec<Line>,
        path: &Path,
        out: &mut Caddyfile,
        first: &mut bool,
        depth: usize,
    ) -> Result<(), SyntaxError> {
        for line in lines {
            let is_first = std::mem::replace(first, false);
            if line.tokens.is_empty() {
                // `{ … }` with no keys: the global options block, only as the very first thing.
                if !is_first || depth > 0 {
                    return Err(error(
                        line.at,
                        "the global options block must come first in the main Caddyfile",
                    ));
                }
                let block = line.block.unwrap_or_default();
                out.global = Some(self.expand(block, path, depth)?);
                continue;
            }
            let name = line.name().to_string();
            if name.starts_with('(') && name.ends_with(')') && line.tokens.len() == 1 && !line.tokens[0].quoted {
                let Some(block) = line.block else {
                    return Err(error(line.at, format!("snippet {name} needs a block")));
                };
                let key = name[1..name.len() - 1].to_string();
                if self.snippets.contains_key(&key) {
                    return Err(error(line.at, format!("snippet {name} is defined more than once")));
                }
                self.snippets.insert(key, block);
                continue;
            }
            if name == "import" && !line.tokens[0].quoted {
                let imported = self.import(&line, path, depth)?;
                for (lines, file) in imported {
                    match file {
                        // A snippet at the top level: its lines are top-level items of this file.
                        None => self.top_level(lines, path, out, first, depth + 1)?,
                        Some(file) => self.top_level(lines, &file, out, first, depth + 1)?,
                    }
                }
                continue;
            }
            let Some(block) = line.block else {
                return Err(error(
                    line.at,
                    format!(
                        "site {name:?} needs a block in braces (the single-site form without braces is not supported)"
                    ),
                ));
            };
            let body = self.expand(block, path, depth)?;
            out.sites.push(ServerBlock {
                keys: line.tokens,
                body,
                at: line.at,
            });
        }
        Ok(())
    }

    /// Resolves `import` lines inside a block (recursively, also inside nested blocks).
    fn expand(&mut self, lines: Vec<Line>, path: &Path, depth: usize) -> Result<Vec<Line>, SyntaxError> {
        if depth > MAX_IMPORT_DEPTH {
            let at = lines.first().map(|l| l.at.clone()).unwrap_or(Location {
                file: path_name(path),
                line: 0,
            });
            return Err(error(at, "imports nested too deeply (an import cycle?)"));
        }
        let mut out = Vec::with_capacity(lines.len());
        for mut line in lines {
            if line.name() == "import" && !line.tokens[0].quoted {
                if line.block.is_some() {
                    return Err(error(line.at, "import takes no block"));
                }
                for (lines, file) in self.import(&line, path, depth)? {
                    let base = file.as_deref().unwrap_or(path).to_path_buf();
                    out.extend(self.expand(lines, &base, depth + 1)?);
                }
                continue;
            }
            if let Some(block) = line.block.take() {
                line.block = Some(self.expand(block, path, depth)?);
            }
            out.push(line);
        }
        Ok(out)
    }

    /// The lines an `import` brings in: a snippet (no file) or the files matching a path/glob.
    fn import(&self, line: &Line, path: &Path, depth: usize) -> Result<Imported, SyntaxError> {
        if depth > MAX_IMPORT_DEPTH {
            return Err(error(line.at.clone(), "imports nested too deeply (an import cycle?)"));
        }
        let Some(target) = line.tokens.get(1) else {
            return Err(error(line.at.clone(), "import needs a snippet name or a file path"));
        };
        if line.tokens.len() > 2 {
            return Err(error(line.at.clone(), "import arguments are not supported"));
        }
        if let Some(snippet) = self.snippets.get(&target.text) {
            return Ok(vec![(snippet.clone(), None)]);
        }
        let base = path.parent().unwrap_or(Path::new("."));
        let pattern = if Path::new(&target.text).is_absolute() {
            PathBuf::from(&target.text)
        } else {
            base.join(&target.text)
        };
        let files = glob_files(&pattern).map_err(|e| error(target.at(), e))?;
        if files.is_empty() {
            if target.text.contains('*') {
                return Ok(Vec::new());
            }
            return Err(error(
                target.at(),
                format!("import {:?}: no such snippet or file", target.text),
            ));
        }
        let mut out = Vec::new();
        for file in files {
            let text = read(&file, Some(target.at()))?;
            out.push((parse_lines_of(&text, &file)?, Some(file)));
        }
        Ok(out)
    }
}

fn path_name(path: &Path) -> Arc<str> {
    Arc::from(path.display().to_string())
}

fn read(path: &Path, from: Option<Location>) -> Result<String, SyntaxError> {
    std::fs::read_to_string(path).map_err(|e| {
        let at = from.unwrap_or(Location {
            file: path_name(path),
            line: 0,
        });
        error(at, format!("cannot read {}: {e}", path.display()))
    })
}

/// Files matching a path whose last element may contain `*` (sorted, like Caddy's glob).
fn glob_files(pattern: &Path) -> Result<Vec<PathBuf>, String> {
    let name = pattern.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if !name.contains('*') {
        if pattern
            .parent()
            .map(|p| p.to_string_lossy().contains('*'))
            .unwrap_or(false)
        {
            return Err("only the last element of an import path may contain *".into());
        }
        return Ok(if pattern.is_file() {
            vec![pattern.to_path_buf()]
        } else {
            Vec::new()
        });
    }
    let dir = pattern.parent().unwrap_or(Path::new("."));
    let mut files = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return Ok(files),
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else { continue };
        if wildcard(name, file_name) && entry.path().is_file() {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

/// `*` matches any run of characters.
pub fn wildcard(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || text.len() < first.len() + last.len() || !text.ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for part in &parts[1..parts.len() - 1] {
        match rest.find(part) {
            Some(i) => rest = &rest[i + part.len()..],
            None => return false,
        }
    }
    true
}

/// Replaces `{$VAR}` and `{$VAR:default}` in the raw text (before tokenizing, as Caddy does).
pub fn replace_env(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("{$") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) if !after[..end].contains(['{', '\n', ' ']) => {
                let inner = &after[..end];
                let (name, default) = match inner.split_once(':') {
                    Some((name, default)) => (name, Some(default)),
                    None => (inner, None),
                };
                let value = std::env::var(name).ok().filter(|v| !v.is_empty());
                out.push_str(value.as_deref().or(default).unwrap_or(""));
                rest = &after[end + 1..];
            }
            _ => {
                out.push_str("{$");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// One file's text as lines (imports and snippets not yet resolved).
fn parse_lines_of(text: &str, path: &Path) -> Result<Vec<Line>, SyntaxError> {
    let file = path_name(path);
    let text = replace_env(text);
    let tokens = lex(&text, &file)?;
    let mut pos = 0;
    let lines = parse_lines(&tokens, &mut pos, None)?;
    Ok(lines)
}

/// A token plus the logical line it belongs to (escaped newlines keep the logical line).
struct Lexed {
    token: Token,
    logical: usize,
}

fn lex(text: &str, file: &Arc<str>) -> Result<Vec<Lexed>, SyntaxError> {
    let mut out = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let mut line = 1;
    let mut logical = 1;
    let at = |line: usize| Location {
        file: file.clone(),
        line,
    };
    while i < chars.len() {
        let ch = chars[i];
        match ch {
            '\n' => {
                line += 1;
                logical += 1;
                i += 1;
            }
            ' ' | '\t' | '\r' => i += 1,
            '#' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '\\' if chars.get(i + 1) == Some(&'\n') => {
                // Line continuation: the next physical line belongs to this one.
                line += 1;
                i += 2;
            }
            '\\' if chars.get(i + 1) == Some(&'\r') && chars.get(i + 2) == Some(&'\n') => {
                line += 1;
                i += 3;
            }
            '"' => {
                let start_line = line;
                let mut value = String::new();
                i += 1;
                loop {
                    let Some(&c) = chars.get(i) else {
                        return Err(error(at(start_line), "unterminated quoted string"));
                    };
                    if c == '\\' {
                        match chars.get(i + 1) {
                            Some('"') => {
                                value.push('"');
                                i += 2;
                                continue;
                            }
                            Some('\n') => {
                                value.push('\n');
                                line += 1;
                                i += 2;
                                continue;
                            }
                            _ => {}
                        }
                    }
                    if c == '"' {
                        i += 1;
                        break;
                    }
                    if c == '\n' {
                        line += 1;
                    }
                    value.push(c);
                    i += 1;
                }
                out.push(Lexed {
                    token: Token {
                        text: value,
                        quoted: true,
                        file: file.clone(),
                        line: start_line,
                    },
                    logical,
                });
                // Lines inside quotes do not break the directive line.
            }
            '`' => {
                let start_line = line;
                let mut value = String::new();
                i += 1;
                loop {
                    let Some(&c) = chars.get(i) else {
                        return Err(error(at(start_line), "unterminated backtick string"));
                    };
                    i += 1;
                    if c == '`' {
                        break;
                    }
                    if c == '\n' {
                        line += 1;
                    }
                    value.push(c);
                }
                out.push(Lexed {
                    token: Token {
                        text: value,
                        quoted: true,
                        file: file.clone(),
                        line: start_line,
                    },
                    logical,
                });
            }
            _ => {
                let start_line = line;
                let mut value = String::new();
                while let Some(&c) = chars.get(i) {
                    if c.is_whitespace() {
                        break;
                    }
                    if c == '\\' && matches!(chars.get(i + 1), Some('\n') | Some('\r')) {
                        break;
                    }
                    value.push(c);
                    i += 1;
                }
                if value.starts_with("<<") && value.len() > 2 {
                    return Err(error(at(start_line), "heredocs are not supported"));
                }
                out.push(Lexed {
                    token: Token {
                        text: value,
                        quoted: false,
                        file: file.clone(),
                        line: start_line,
                    },
                    logical,
                });
            }
        }
    }
    Ok(out)
}

/// Lines until the end of input (top level) or the `}` closing the block opened at `open`.
fn parse_lines(tokens: &[Lexed], pos: &mut usize, open: Option<&Lexed>) -> Result<Vec<Line>, SyntaxError> {
    let mut lines = Vec::new();
    loop {
        let Some(first) = tokens.get(*pos) else {
            if let Some(open) = open {
                return Err(error(open.token.at(), "unclosed block: missing }"));
            }
            return Ok(lines);
        };
        if first.token.is_brace("}") {
            if open.is_none() {
                return Err(error(first.token.at(), "unexpected }"));
            }
            // `}` must stand alone on its line.
            let prev_same_line = *pos > 0 && tokens[*pos - 1].logical == first.logical;
            if prev_same_line {
                return Err(error(first.token.at(), "} must be on its own line"));
            }
            *pos += 1;
            if let Some(next) = tokens.get(*pos)
                && next.logical == first.logical
            {
                return Err(error(next.token.at(), "unexpected token after }"));
            }
            return Ok(lines);
        }
        let logical = first.logical;
        let at = first.token.at();
        let mut line_tokens = Vec::new();
        let mut block = None;
        while let Some(t) = tokens.get(*pos) {
            if t.logical != logical {
                break;
            }
            if t.token.is_brace("}") {
                return Err(error(t.token.at(), "} must be on its own line"));
            }
            if t.token.is_brace("{") {
                let opener = t;
                *pos += 1;
                if let Some(next) = tokens.get(*pos)
                    && next.logical == logical
                {
                    return Err(error(
                        next.token.at(),
                        "a block opened with { must continue on the next line",
                    ));
                }
                block = Some(parse_lines(tokens, pos, Some(opener))?);
                break;
            }
            line_tokens.push(t.token.clone());
            *pos += 1;
        }
        lines.push(Line {
            tokens: line_tokens,
            block,
            at,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Caddyfile {
        parse_str(text, Path::new("Caddyfile")).unwrap()
    }

    fn texts(line: &Line) -> Vec<&str> {
        line.tokens.iter().map(|t| t.text.as_str()).collect()
    }

    #[test]
    fn global_snippet_site_and_quotes() {
        let file = parse(
            "{\n\tauto_https off\n}\n(hdr) {\n\theader X-A \"a \\\"b\\\" c\"\n}\n:8080, example.com {\n\timport hdr\n\trespond /x `raw\\.` 200 # comment\n\troute {\n\t\tredir @m {re.m.1} 308\n\t}\n}\n",
        );
        let global = file.global.unwrap();
        assert_eq!(texts(&global[0]), ["auto_https", "off"]);
        let site = &file.sites[0];
        assert_eq!(
            site.keys.iter().map(|t| t.text.as_str()).collect::<Vec<_>>(),
            [":8080,", "example.com"]
        );
        assert_eq!(texts(&site.body[0]), ["header", "X-A", "a \"b\" c"]);
        assert_eq!(texts(&site.body[1]), ["respond", "/x", "raw\\.", "200"]);
        let route = site.body[2].block.as_ref().unwrap();
        assert_eq!(texts(&route[0]), ["redir", "@m", "{re.m.1}", "308"]);
    }

    #[test]
    fn line_continuation_and_env() {
        // SAFETY: tests in this module do not read the environment concurrently with this write.
        unsafe { std::env::set_var("WEB_SERVER_TEST_PORT", "9000") };
        let file = parse(
            ":{$WEB_SERVER_TEST_PORT} {\n\trespond \\\n\t\t\"ok\" 200\n\theader X {$WEB_SERVER_TEST_MISSING:fallback}\n}\n",
        );
        assert_eq!(file.sites[0].keys[0].text, ":9000");
        assert_eq!(texts(&file.sites[0].body[0]), ["respond", "ok", "200"]);
        assert_eq!(texts(&file.sites[0].body[1]), ["header", "X", "fallback"]);
    }

    #[test]
    fn syntax_errors() {
        for (text, message) in [
            (":80 {\n\trespond \"x\n}\n", "unterminated"),
            (":80 {\n\trespond x\n", "unclosed block"),
            (":80 {\n\troute { respond x }\n}\n", "next line"),
            (":80 {\n}\n}\n", "unexpected }"),
            (":80 {\n\timport missing\n}\n", "no such snippet or file"),
            (":80 {\n\trespond <<EOF\n}\n", "heredocs"),
            (":80\nrespond x\n", "needs a block"),
            (":80 {\n}\n{\n}\n", "global options"),
        ] {
            let err = parse_str(text, Path::new("Caddyfile")).unwrap_err().to_string();
            assert!(err.contains(message), "{text:?}: {err}");
        }
    }

    #[test]
    fn wildcards() {
        assert!(wildcard("*.caddy", "site.caddy"));
        assert!(wildcard("a*b*c", "a-x-b-y-c"));
        assert!(!wildcard("a*b", "ab-"));
        assert!(wildcard("exact", "exact"));
    }
}
