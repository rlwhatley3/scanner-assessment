use serde::Serialize;

/// Where a finding sits in the scanned text.
///
/// Byte offsets are the source of truth: a half-open range `[start_byte, end_byte)` into the
/// UTF-8 text. Lines and columns are 1-based and derived from them for display; columns count
/// characters, not bytes. The end position is exclusive, like `end_byte`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

/// Byte offset of the start of every line. `\n`, `\r\n`, and a lone `\r` each end a line, so
/// files with mixed line endings still get one line number per visual line.
pub(crate) struct LineIndex<'a> {
    text: &'a str,
    starts: Vec<usize>,
}

impl<'a> LineIndex<'a> {
    pub fn new(text: &'a str) -> Self {
        let bytes = text.as_bytes();
        let mut starts = vec![0];
        for (index, &byte) in bytes.iter().enumerate() {
            let ends_line =
                byte == b'\n' || (byte == b'\r' && bytes.get(index + 1) != Some(&b'\n'));
            if ends_line {
                starts.push(index + 1);
            }
        }
        Self { text, starts }
    }

    pub fn location(&self, start_byte: usize, end_byte: usize) -> Location {
        let (start_line, start_column) = self.position(start_byte);
        let (end_line, end_column) = self.position(end_byte);
        Location {
            start_byte,
            end_byte,
            start_line,
            start_column,
            end_line,
            end_column,
        }
    }

    fn position(&self, offset: usize) -> (usize, usize) {
        let line = self.starts.partition_point(|&start| start <= offset) - 1;
        let column = self.text[self.starts[line]..offset].chars().count() + 1;
        (line + 1, column)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_lines_for_every_newline_style() {
        let text = "a\nb\r\nc\rd";
        let index = LineIndex::new(text);
        let d = text.find('d').unwrap();
        assert_eq!(index.location(d, d + 1).start_line, 4);
        let c = text.find('c').unwrap();
        assert_eq!(index.location(c, c + 1).start_line, 3);
    }

    #[test]
    fn columns_count_characters_not_bytes() {
        let text = "é🙂 key";
        let index = LineIndex::new(text);
        let k = text.find('k').unwrap();
        let location = index.location(k, k + 3);
        assert_eq!(k, 7);
        assert_eq!(location.start_column, 4);
        assert_eq!(location.end_column, 7);
    }

    #[test]
    fn a_range_can_span_lines() {
        let text = "one\ntwo\nthree";
        let index = LineIndex::new(text);
        let location = index.location(2, 10);
        assert_eq!((location.start_line, location.start_column), (1, 3));
        assert_eq!((location.end_line, location.end_column), (3, 3));
    }
}
