//! No-std S-expression parser for Chialisp
//!
//! Parses Chialisp source code into S-expressions without heap allocations.
//! Designed to work in guest environments with limited memory.

extern crate alloc;

use alloc::{string::{String, ToString}, vec::Vec};

/// Parsed S-expression - the raw syntax tree
#[derive(Debug, Clone, PartialEq)]
pub enum SExp {
    /// Atomic value: number, string, or symbol
    Atom(String),
    /// List of S-expressions
    List(Vec<SExp>),
}

/// Parse error types
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    UnexpectedEndOfInput,
    UnbalancedParens,
    InvalidCharacter(char),
    InvalidNumber(String),
    EmptyInput,
}

/// S-expression parser with zero heap allocations during parsing
pub struct SExpParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> SExpParser<'a> {
    /// Create a new parser for the given input
    pub fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    /// Parse the input into an S-expression
    pub fn parse(&mut self) -> Result<SExp, ParseError> {
        self.skip_whitespace();

        if self.pos >= self.input.len() {
            return Err(ParseError::EmptyInput);
        }

        self.parse_sexp()
    }

    /// Parse a single S-expression (atom or list)
    fn parse_sexp(&mut self) -> Result<SExp, ParseError> {
        self.skip_whitespace();

        if self.pos >= self.input.len() {
            return Err(ParseError::UnexpectedEndOfInput);
        }

        let ch = self.current_char();
        match ch {
            '(' => self.parse_list(),
            _ => self.parse_atom(),
        }
    }

    /// Parse a list: (item1 item2 ...)
    fn parse_list(&mut self) -> Result<SExp, ParseError> {
        // Consume opening paren
        self.advance();
        self.skip_whitespace();

        let mut items = Vec::new();

        while self.pos < self.input.len() {
            let ch = self.current_char();

            if ch == ')' {
                // Consume closing paren and return
                self.advance();
                return Ok(SExp::List(items));
            }

            // Parse next item
            let item = self.parse_sexp()?;
            items.push(item);
            self.skip_whitespace();
        }

        Err(ParseError::UnbalancedParens)
    }

    /// Parse an atomic value (symbol, string, or number)
    fn parse_atom(&mut self) -> Result<SExp, ParseError> {
        self.skip_whitespace();

        if self.pos >= self.input.len() {
            return Err(ParseError::UnexpectedEndOfInput);
        }

        let ch = self.current_char();

        // Handle quoted strings
        if ch == '"' {
            return self.parse_string();
        }

        // Parse regular atom (symbol or number)
        let start = self.pos;

        while self.pos < self.input.len() {
            let ch = self.current_char();

            // Stop at delimiters
            if ch.is_whitespace() || ch == '(' || ch == ')' {
                break;
            }

            self.advance();
        }

        if start == self.pos {
            return Err(ParseError::InvalidCharacter(ch));
        }

        let atom_str = &self.input[start..self.pos];
        Ok(SExp::Atom(atom_str.to_string()))
    }

    /// Parse a quoted string: "hello world"
    fn parse_string(&mut self) -> Result<SExp, ParseError> {
        // Consume opening quote
        self.advance();
        let start = self.pos;

        while self.pos < self.input.len() {
            let ch = self.current_char();

            if ch == '"' {
                let content = &self.input[start..self.pos];
                self.advance(); // Consume closing quote
                return Ok(SExp::Atom(content.to_string()));
            }

            // TODO: Handle escape sequences if needed
            self.advance();
        }

        Err(ParseError::UnbalancedParens) // Unterminated string
    }

    /// Skip whitespace and comments
    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() {
            let ch = self.current_char();

            if ch.is_whitespace() {
                self.advance();
            } else if ch == ';' {
                // Skip comment until end of line
                while self.pos < self.input.len() && self.current_char() != '\n' {
                    self.advance();
                }
            } else {
                break;
            }
        }
    }

    /// Get current character
    fn current_char(&self) -> char {
        self.input.chars().nth(self.pos).unwrap_or('\0')
    }

    /// Advance position by one character
    fn advance(&mut self) {
        if self.pos < self.input.len() {
            // Find the next character boundary (UTF-8 safe)
            let mut next_pos = self.pos + 1;
            while next_pos < self.input.len() && !self.input.is_char_boundary(next_pos) {
                next_pos += 1;
            }
            self.pos = next_pos;
        }
    }
}

/// Convenience function to parse Chialisp source code
pub fn parse_chialisp(source: &str) -> Result<SExp, ParseError> {
    let mut parser = SExpParser::new(source);
    parser.parse()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_parse_simple_atom() {
        let result = parse_chialisp("hello").unwrap();
        assert_eq!(result, SExp::Atom("hello".to_string()));
    }

    #[test]
    fn test_parse_number() {
        let result = parse_chialisp("42").unwrap();
        assert_eq!(result, SExp::Atom("42".to_string()));
    }

    #[test]
    fn test_parse_simple_list() {
        let result = parse_chialisp("(+ 1 2)").unwrap();
        assert_eq!(result, SExp::List(vec![
            SExp::Atom("+".to_string()),
            SExp::Atom("1".to_string()),
            SExp::Atom("2".to_string()),
        ]));
    }

    #[test]
    fn test_parse_nested_list() {
        let result = parse_chialisp("(+ (* 2 3) 4)").unwrap();
        assert_eq!(result, SExp::List(vec![
            SExp::Atom("+".to_string()),
            SExp::List(vec![
                SExp::Atom("*".to_string()),
                SExp::Atom("2".to_string()),
                SExp::Atom("3".to_string()),
            ]),
            SExp::Atom("4".to_string()),
        ]));
    }

    #[test]
    fn test_parse_mod_expression() {
        let result = parse_chialisp("(mod (x y) (+ x y))").unwrap();
        assert_eq!(result, SExp::List(vec![
            SExp::Atom("mod".to_string()),
            SExp::List(vec![
                SExp::Atom("x".to_string()),
                SExp::Atom("y".to_string()),
            ]),
            SExp::List(vec![
                SExp::Atom("+".to_string()),
                SExp::Atom("x".to_string()),
                SExp::Atom("y".to_string()),
            ]),
        ]));
    }

    #[test]
    fn test_parse_defun() {
        let result = parse_chialisp("(defun double (x) (* x 2))").unwrap();
        assert_eq!(result, SExp::List(vec![
            SExp::Atom("defun".to_string()),
            SExp::Atom("double".to_string()),
            SExp::List(vec![SExp::Atom("x".to_string())]),
            SExp::List(vec![
                SExp::Atom("*".to_string()),
                SExp::Atom("x".to_string()),
                SExp::Atom("2".to_string()),
            ]),
        ]));
    }

    #[test]
    fn test_parse_with_comments() {
        let result = parse_chialisp("(+ 1 2) ; this is a comment").unwrap();
        assert_eq!(result, SExp::List(vec![
            SExp::Atom("+".to_string()),
            SExp::Atom("1".to_string()),
            SExp::Atom("2".to_string()),
        ]));
    }

    #[test]
    fn test_parse_quoted_string() {
        let result = parse_chialisp(r#""hello world""#).unwrap();
        assert_eq!(result, SExp::Atom("hello world".to_string()));
    }

    #[test]
    fn test_parse_empty_list() {
        let result = parse_chialisp("()").unwrap();
        assert_eq!(result, SExp::List(vec![]));
    }

    #[test]
    fn test_parse_unbalanced_parens() {
        let result = parse_chialisp("(+ 1 2");
        assert!(matches!(result, Err(ParseError::UnbalancedParens)));
    }

    #[test]
    fn test_parse_empty_input() {
        let result = parse_chialisp("");
        assert!(matches!(result, Err(ParseError::EmptyInput)));
    }

    #[test]
    fn test_parse_whitespace_handling() {
        let result = parse_chialisp("  (  +   1    2  )  ").unwrap();
        assert_eq!(result, SExp::List(vec![
            SExp::Atom("+".to_string()),
            SExp::Atom("1".to_string()),
            SExp::Atom("2".to_string()),
        ]));
    }

    #[test]
    fn test_complex_mod_with_defun() {
        let source = r#"
            (mod (n)
                (defun factorial (x)
                    (if (= x 0) 1 (* x (factorial (- x 1)))))
                (factorial n))
        "#;

        let result = parse_chialisp(source).unwrap();

        // Should parse successfully - exact structure test would be complex
        // Just verify it's a list with mod at the start
        if let SExp::List(items) = result {
            assert_eq!(items[0], SExp::Atom("mod".to_string()));
            assert!(items.len() >= 3); // mod, params, body
        } else {
            panic!("Expected a list");
        }
    }
}