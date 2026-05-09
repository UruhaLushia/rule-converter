use std::io::BufRead;

use anyhow::Context;

pub(super) struct BufReadChars<R> {
    reader: R,
    pending: Vec<char>,
    line: String,
    done: bool,
    pub(super) error: Option<anyhow::Error>,
}

impl<R: BufRead> BufReadChars<R> {
    pub(super) fn new(reader: R) -> Self {
        Self {
            reader,
            pending: Vec::new(),
            line: String::new(),
            done: false,
            error: None,
        }
    }
}

impl<R: BufRead> Iterator for BufReadChars<R> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ch) = self.pending.pop() {
                return Some(ch);
            }
            if self.done {
                return None;
            }

            self.line.clear();
            match self.reader.read_line(&mut self.line) {
                Ok(0) => {
                    self.done = true;
                    return None;
                }
                Ok(_) => {
                    self.pending.extend(self.line.chars().rev());
                }
                Err(err) => {
                    self.error = Some(err).context("failed to read mihomo YAML input").err();
                    self.done = true;
                    return None;
                }
            }
        }
    }
}
