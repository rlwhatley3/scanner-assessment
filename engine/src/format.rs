//! Reads the scanned text as the config format it is, instead of only as lines of text: which
//! parts are comments, and which keys hold which values. Everything here works on byte ranges
//! into the original text, so findings built from it still point at exact positions.

use regex::Regex;
use serde::Serialize;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Json,
    Yaml,
    /// `KEY=value` lines, as in `.env` files and shell exports.
    Dotenv,
    /// Anything else: source code, logs, prose.
    Text,
}

/// A key and its string value, as byte ranges into the text. Quotes are not included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pair {
    pub key: (usize, usize),
    pub value: (usize, usize),
}

#[derive(Debug)]
pub(crate) struct Structure {
    pub format: Format,
    comments: Vec<(usize, usize)>,
    pub pairs: Vec<Pair>,
}

impl Structure {
    /// Whether the range sits entirely inside a comment.
    pub fn in_comment(&self, start: usize, end: usize) -> bool {
        self.comments
            .iter()
            .any(|&(comment_start, comment_end)| comment_start <= start && end <= comment_end)
    }
}

static DOTENV_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[ \t]*(?:export[ \t]+)?(?P<key>[A-Za-z_][A-Za-z0-9_.]*)[ \t]*=(?P<value>.*)$")
        .expect("dotenv pattern compiles")
});

static YAML_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^[ \t]*(?:-[ \t]+)?(?P<key>["']?[A-Za-z0-9_.-]+["']?)[ \t]*:(?:[ \t]+(?P<value>.*))?$"#,
    )
    .expect("yaml pattern compiles")
});

/// Works out the format, then finds its comments and key/value pairs.
pub(crate) fn parse(text: &str) -> Structure {
    let format = detect(text);
    let (comments, pairs) = match format {
        Format::Json => (Vec::new(), json_pairs(text)),
        Format::Yaml => line_structure(text, &YAML_LINE, true),
        Format::Dotenv => line_structure(text, &DOTENV_LINE, true),
        Format::Text => (full_line_comments(text), Vec::new()),
    };
    Structure {
        format,
        comments,
        pairs,
    }
}

/// Each line with the byte offset where it starts. A trailing `\r` is left off the line.
fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut offset = 0;
    text.split('\n').map(move |line| {
        let start = offset;
        offset += line.len() + 1;
        (start, line.strip_suffix('\r').unwrap_or(line))
    })
}

fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with('#') || trimmed.starts_with("//")
}

fn detect(text: &str) -> Format {
    let trimmed = text.trim_start();
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && serde_json::from_str::<serde_json::Value>(text).is_ok()
    {
        return Format::Json;
    }
    let significant: Vec<&str> = lines(text)
        .map(|(_, line)| line)
        .filter(|line| !line.trim().is_empty() && !is_comment_line(line))
        .collect();
    if significant.is_empty() {
        return Format::Text;
    }
    let count = |pattern: &Regex| {
        significant
            .iter()
            .filter(|line| pattern.is_match(line))
            .count()
    };
    let (dotenv, yaml) = (count(&DOTENV_LINE), count(&YAML_LINE));
    if dotenv * 2 >= significant.len() && dotenv >= yaml {
        Format::Dotenv
    } else if yaml * 2 >= significant.len() {
        Format::Yaml
    } else {
        Format::Text
    }
}

fn full_line_comments(text: &str) -> Vec<(usize, usize)> {
    lines(text)
        .filter(|(_, line)| is_comment_line(line))
        .map(|(start, line)| {
            let indent = line.len() - line.trim_start().len();
            (start + indent, start + line.len())
        })
        .collect()
}

/// Where a trailing `# comment` starts in a line: a `#` after whitespace, outside quotes.
fn trailing_comment(line: &str) -> Option<usize> {
    let mut quote = None;
    let mut previous = ' ';
    for (index, character) in line.char_indices() {
        match (quote, character) {
            (None, '"' | '\'') => quote = Some(character),
            (Some(open), _) if character == open => quote = None,
            (None, '#') if previous.is_whitespace() => return Some(index),
            _ => {}
        }
        previous = character;
    }
    None
}

/// Comments and key/value pairs for line-based formats (YAML, dotenv).
fn line_structure(
    text: &str,
    pattern: &Regex,
    trailing_comments: bool,
) -> (Vec<(usize, usize)>, Vec<Pair>) {
    let mut comments = Vec::new();
    let mut pairs = Vec::new();
    for (start, line) in lines(text) {
        if is_comment_line(line) {
            let indent = line.len() - line.trim_start().len();
            comments.push((start + indent, start + line.len()));
            continue;
        }
        let comment_at = trailing_comments.then(|| trailing_comment(line)).flatten();
        if let Some(at) = comment_at {
            comments.push((start + at, start + line.len()));
        }
        let Some(captures) = pattern.captures(line) else {
            continue;
        };
        let (Some(key), Some(value)) = (captures.name("key"), captures.name("value")) else {
            continue;
        };
        let value_end = comment_at.unwrap_or(line.len()).max(value.start());
        if let Some((value_start, value_end)) = unquote(line, value.start(), value_end) {
            pairs.push(Pair {
                key: (start + key.start(), start + key.end()),
                value: (start + value_start, start + value_end),
            });
        }
    }
    (comments, pairs)
}

/// Trims whitespace and one pair of matching quotes from `line[start..end]`.
fn unquote(line: &str, start: usize, end: usize) -> Option<(usize, usize)> {
    let raw = &line[start..end];
    let leading = raw.len() - raw.trim_start().len();
    let trimmed = raw.trim();
    let (mut start, mut end) = (start + leading, start + leading + trimmed.len());
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        start += 1;
        end -= 1;
    }
    (start < end).then_some((start, end))
}

/// Every `"key": "string value"` in a JSON document, at any depth. Only string values count;
/// numbers, booleans, objects, and arrays are not secrets on their own.
fn json_pairs(text: &str) -> Vec<Pair> {
    enum Token {
        String(usize, usize),
        Colon,
        Other,
    }
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let start = index + 1;
                index = start;
                while index < bytes.len() && bytes[index] != b'"' {
                    index += if bytes[index] == b'\\' { 2 } else { 1 };
                }
                tokens.push(Token::String(start, index.min(bytes.len())));
            }
            b':' => tokens.push(Token::Colon),
            byte if byte.is_ascii_whitespace() => {}
            _ => tokens.push(Token::Other),
        }
        index += 1;
    }
    tokens
        .windows(3)
        .filter_map(|window| match window {
            [
                Token::String(key_start, key_end),
                Token::Colon,
                Token::String(start, end),
            ] if start < end => Some(Pair {
                key: (*key_start, *key_end),
                value: (*start, *end),
            }),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(text: &str) -> Vec<(&str, &str)> {
        parse(text)
            .pairs
            .iter()
            .map(|pair| {
                (
                    &text[pair.key.0..pair.key.1],
                    &text[pair.value.0..pair.value.1],
                )
            })
            .collect()
    }

    #[test]
    fn detects_each_format() {
        assert_eq!(parse(r#"{"a": {"b": "c"}}"#).format, Format::Json);
        assert_eq!(
            parse("# db\nDB_HOST=localhost\nexport DB_PASS=x\n").format,
            Format::Dotenv
        );
        assert_eq!(
            parse("server:\n  port: 80\n  host: example\n").format,
            Format::Yaml
        );
        assert_eq!(parse("fn main() {\n    run();\n}\n").format, Format::Text);
        assert_eq!(parse("{ not json").format, Format::Text);
    }

    #[test]
    fn json_pairs_are_found_at_any_depth_without_quotes() {
        let text = r#"{"db": {"password": "p@ss;w$rd", "port": 5432}, "tags": ["a"]}"#;
        assert_eq!(pairs(text), [("password", "p@ss;w$rd")]);
    }

    #[test]
    fn json_strings_with_escaped_quotes_stay_whole() {
        let text = r#"{"token": "ab\"cd"}"#;
        assert_eq!(pairs(text), [("token", r#"ab\"cd"#)]);
    }

    #[test]
    fn yaml_and_dotenv_values_lose_quotes_and_trailing_comments() {
        assert_eq!(
            pairs("api:\n  key: \"a1;b2$c3\"  # rotate monthly\n"),
            [("key", "a1;b2$c3")]
        );
        assert_eq!(
            pairs("export TOKEN='x y z' # note\nEMPTY=\n"),
            [("TOKEN", "x y z")]
        );
    }

    #[test]
    fn comments_are_found_but_a_hash_inside_quotes_is_not_one() {
        let text = "# heading\nKEY=\"a #b\" # real comment\n";
        let structure = parse(text);
        let heading = text.find("heading").unwrap();
        assert!(structure.in_comment(heading, heading + 7));
        let inside = text.find("a #b").unwrap();
        assert!(!structure.in_comment(inside, inside + 4));
        let real = text.find("real").unwrap();
        assert!(structure.in_comment(real, real + 4));
    }

    #[test]
    fn plain_text_still_knows_its_full_line_comments() {
        let text = "let a = 1;\n// password: hunter22\n";
        let structure = parse(text);
        let at = text.find("hunter22").unwrap();
        assert!(structure.in_comment(at, at + 8));
        assert!(structure.pairs.is_empty());
    }

    #[test]
    fn crlf_line_endings_keep_exact_spans() {
        let text = "A=one\r\nB=two\r\n";
        assert_eq!(pairs(text), [("A", "one"), ("B", "two")]);
    }
}
