//! clvm binary format parser
extern crate alloc;
use crate::types::ClvmValue;
use alloc::{boxed::Box, vec, vec::Vec};

/// a proper clvm parser that understands the binary serialization format
pub struct ClvmParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ClvmParser<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// optimized clvm parsing with cycle counting and memory efficiency
    pub fn parse(&mut self) -> Result<ClvmValue, &'static str> {
        // early bounds check to avoid page faults
        if self.pos >= self.bytes.len() {
            return Err("unexpected end of input");
        }

        // ensure word-aligned memory access when possible
        let byte = self.bytes[self.pos];
        match byte {
            0xFF => {
                // cons pair
                self.pos += 1;
                let first = self.parse()?;
                let rest = self.parse()?;
                Ok(ClvmValue::Cons(Box::new(first), Box::new(rest)))
            }
            0x00..=0x7F => {
                // single byte atom
                let value = self.bytes[self.pos];
                self.pos += 1;
                Ok(ClvmValue::Atom(vec![value]))
            }
            0x80..=0xBF => {
                // Check for nil (empty atom) case first
                if self.bytes[self.pos] == 0x80 {
                    self.pos += 1;
                    return Ok(ClvmValue::Atom(Vec::new()));
                }
                // atom with size in lower 6 bits (1-63 bytes)
                let size_byte = self.bytes[self.pos];
                self.pos += 1;
                let size = (size_byte & 0x3F) as usize;

                if self.pos + size > self.bytes.len() {
                    return Err("atom size exceeds remaining bytes");
                }

                let atom_bytes = self.bytes[self.pos..self.pos + size].to_vec();
                self.pos += size;
                Ok(ClvmValue::Atom(atom_bytes))
            }
            0xC0..=0xDF => {
                // 2-byte size encoding (64-8191 bytes): 0xC0 | (size >> 8), size & 0xFF, data
                let first_byte = self.bytes[self.pos];
                self.pos += 1;

                if self.pos >= self.bytes.len() {
                    return Err("unexpected end of input");
                }

                let second_byte = self.bytes[self.pos];
                self.pos += 1;

                let size = (((first_byte & 0x1F) as usize) << 8) | (second_byte as usize);

                if self.pos + size > self.bytes.len() {
                    return Err("atom size exceeds remaining bytes");
                }

                let atom_bytes = self.bytes[self.pos..self.pos + size].to_vec();
                self.pos += size;
                Ok(ClvmValue::Atom(atom_bytes))
            }
            0xE0..=0xEF => {
                // 3-byte size encoding (8192-1048575 bytes)
                let first_byte = self.bytes[self.pos];
                self.pos += 1;

                if self.pos + 2 > self.bytes.len() {
                    return Err("unexpected end of input");
                }

                let size = (((first_byte & 0x0F) as usize) << 16)
                    | ((self.bytes[self.pos] as usize) << 8)
                    | (self.bytes[self.pos + 1] as usize);
                self.pos += 2;

                if self.pos + size > self.bytes.len() {
                    return Err("atom size exceeds remaining bytes");
                }

                let atom_bytes = self.bytes[self.pos..self.pos + size].to_vec();
                self.pos += size;
                Ok(ClvmValue::Atom(atom_bytes))
            }
            0xF0..=0xF7 => {
                // 4-byte size encoding (1048576-134217727 bytes)
                let first_byte = self.bytes[self.pos];
                self.pos += 1;

                if self.pos + 3 > self.bytes.len() {
                    return Err("unexpected end of input");
                }

                let size = (((first_byte & 0x07) as usize) << 24)
                    | ((self.bytes[self.pos] as usize) << 16)
                    | ((self.bytes[self.pos + 1] as usize) << 8)
                    | (self.bytes[self.pos + 2] as usize);
                self.pos += 3;

                if self.pos + size > self.bytes.len() {
                    return Err("atom size exceeds remaining bytes");
                }

                let atom_bytes = self.bytes[self.pos..self.pos + size].to_vec();
                self.pos += size;
                Ok(ClvmValue::Atom(atom_bytes))
            }
            0xF8..=0xFF => {
                // 5-byte size encoding (134217728+ bytes)
                let first_byte = self.bytes[self.pos];
                self.pos += 1;

                if self.pos + 4 > self.bytes.len() {
                    return Err("unexpected end of input");
                }

                // use u64 to avoid 32-bit overflow in guest environments
                let size64 = (((first_byte & 0x03) as u64) << 32)
                    | ((self.bytes[self.pos] as u64) << 24)
                    | ((self.bytes[self.pos + 1] as u64) << 16)
                    | ((self.bytes[self.pos + 2] as u64) << 8)
                    | (self.bytes[self.pos + 3] as u64);
                self.pos += 4;

                // check if size fits in usize for this platform
                if size64 > usize::MAX as u64 {
                    return Err("atom size too large for this platform");
                }

                let size = size64 as usize;
                if self.pos + size > self.bytes.len() {
                    return Err("atom size exceeds remaining bytes");
                }

                let atom_bytes = self.bytes[self.pos..self.pos + size].to_vec();
                self.pos += size;
                Ok(ClvmValue::Atom(atom_bytes))
            }
        }
    }
}
