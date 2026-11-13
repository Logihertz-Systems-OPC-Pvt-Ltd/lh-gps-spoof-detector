//! Zero-dependency recursive descent JSON parser and canonical serializer.
//!
//! Implemented using only the Rust standard library (`std`).

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            JsonValue::Number(n) if *n >= 0.0 => Some(*n as u64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<JsonValue>> {
        match self {
            JsonValue::Array(arr) => Some(arr),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, JsonValue>> {
        match self {
            JsonValue::Object(map) => Some(map),
            _ => None,
        }
    }

    pub fn is_object(&self) -> bool {
        matches!(self, JsonValue::Object(_))
    }

    pub fn is_array(&self) -> bool {
        matches!(self, JsonValue::Array(_))
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(map) => map.get(key),
            _ => None,
        }
    }
}

impl fmt::Display for JsonValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonValue::Null => write!(f, "null"),
            JsonValue::Bool(b) => write!(f, "{}", b),
            JsonValue::Number(n) => {
                if n.fract() == 0.0 && !n.is_nan() && !n.is_infinite() && n.abs() < 1e15 {
                    write!(f, "{:.0}", n)
                } else {
                    write!(f, "{}", n)
                }
            }
            JsonValue::String(s) => {
                write!(f, "\"")?;
                for c in s.chars() {
                    match c {
                        '"' => write!(f, "\\\"")?,
                        '\\' => write!(f, "\\\\")?,
                        '\n' => write!(f, "\\n")?,
                        '\r' => write!(f, "\\r")?,
                        '\t' => write!(f, "\\t")?,
                        other => write!(f, "{}", other)?,
                    }
                }
                write!(f, "\"")
            }
            JsonValue::Array(arr) => {
                write!(f, "[")?;
                for (i, val) in arr.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", val)?;
                }
                write!(f, "]")
            }
            JsonValue::Object(map) => {
                write!(f, "{{")?;
                for (i, (k, val)) in map.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "\"{}\": {}", k, val)?;
                }
                write!(f, "}}")
            }
        }
    }
}

pub struct JsonParser<'a> {
    chars: Vec<char>,
    pos: usize,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> JsonParser<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            chars: input.chars().collect(),
            pos: 0,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn parse(&mut self) -> Result<JsonValue, String> {
        self.skip_whitespace();
        let val = self.parse_value()?;
        self.skip_whitespace();
        if self.pos < self.chars.len() {
            return Err(format!(
                "Unexpected trailing characters at pos {}: {:?}",
                self.pos,
                &self.chars[self.pos..self.pos + 1]
            ));
        }
        Ok(val)
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.chars.len() && self.chars[self.pos].is_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<char> {
        if self.pos < self.chars.len() {
            Some(self.chars[self.pos])
        } else {
            None
        }
    }

    fn consume(&mut self) -> Option<char> {
        if self.pos < self.chars.len() {
            let c = self.chars[self.pos];
            self.pos += 1;
            Some(c)
        } else {
            None
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, String> {
        self.skip_whitespace();
        match self.peek() {
            Some('{') => self.parse_object(),
            Some('[') => self.parse_array(),
            Some('"') => self.parse_string().map(JsonValue::String),
            Some('t') | Some('f') => self.parse_bool(),
            Some('n') => self.parse_null(),
            Some(c) if c == '-' || c.is_ascii_digit() => self.parse_number(),
            Some(c) => Err(format!("Unexpected character '{}' at pos {}", c, self.pos)),
            None => Err("Unexpected end of input while parsing JSON value".to_string()),
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, String> {
        self.consume(); // '{'
        self.skip_whitespace();
        let mut map = BTreeMap::new();

        if let Some('}') = self.peek() {
            self.consume();
            return Ok(JsonValue::Object(map));
        }

        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();

            if self.consume() != Some(':') {
                return Err(format!("Expected ':' after object key at pos {}", self.pos));
            }

            self.skip_whitespace();
            let val = self.parse_value()?;
            map.insert(key, val);

            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    self.consume();
                }
                Some('}') => {
                    self.consume();
                    break;
                }
                Some(other) => {
                    return Err(format!(
                        "Expected ',' or '}}' in object, found '{}' at pos {}",
                        other, self.pos
                    ));
                }
                None => return Err("Unexpected end of input in object".to_string()),
            }
        }

        Ok(JsonValue::Object(map))
    }

    fn parse_array(&mut self) -> Result<JsonValue, String> {
        self.consume(); // '['
        self.skip_whitespace();
        let mut arr = Vec::new();

        if let Some(']') = self.peek() {
            self.consume();
            return Ok(JsonValue::Array(arr));
        }

        loop {
            self.skip_whitespace();
            let val = self.parse_value()?;
            arr.push(val);

            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    self.consume();
                }
                Some(']') => {
                    self.consume();
                    break;
                }
                Some(other) => {
                    return Err(format!(
                        "Expected ',' or ']' in array, found '{}' at pos {}",
                        other, self.pos
                    ));
                }
                None => return Err("Unexpected end of input in array".to_string()),
            }
        }

        Ok(JsonValue::Array(arr))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.consume() != Some('"') {
            return Err(format!(
                "Expected '\"' at start of string at pos {}",
                self.pos
            ));
        }

        let mut s = String::new();
        while let Some(c) = self.consume() {
            match c {
                '"' => return Ok(s),
                '\\' => {
                    match self.consume() {
                        Some('"') => s.push('"'),
                        Some('\\') => s.push('\\'),
                        Some('/') => s.push('/'),
                        Some('b') => s.push('\x08'),
                        Some('f') => s.push('\x0c'),
                        Some('n') => s.push('\n'),
                        Some('r') => s.push('\r'),
                        Some('t') => s.push('\t'),
                        Some('u') => {
                            // 4 hex digits
                            let mut hex_str = String::new();
                            for _ in 0..4 {
                                if let Some(hc) = self.consume() {
                                    hex_str.push(hc);
                                } else {
                                    return Err("Truncated unicode escape in string".to_string());
                                }
                            }
                            if let Ok(code) = u32::from_str_radix(&hex_str, 16) {
                                if let Some(unicode_char) = std::char::from_u32(code) {
                                    s.push(unicode_char);
                                }
                            }
                        }
                        Some(esc) => s.push(esc),
                        None => return Err("Unterminated string escape".to_string()),
                    }
                }
                other => s.push(other),
            }
        }

        Err("Unterminated string".to_string())
    }

    fn parse_bool(&mut self) -> Result<JsonValue, String> {
        if self.pos + 4 <= self.chars.len()
            && self.chars[self.pos..self.pos + 4] == ['t', 'r', 'u', 'e']
        {
            self.pos += 4;
            Ok(JsonValue::Bool(true))
        } else if self.pos + 5 <= self.chars.len()
            && self.chars[self.pos..self.pos + 5] == ['f', 'a', 'l', 's', 'e']
        {
            self.pos += 5;
            Ok(JsonValue::Bool(false))
        } else {
            Err(format!("Invalid boolean token at pos {}", self.pos))
        }
    }

    fn parse_null(&mut self) -> Result<JsonValue, String> {
        if self.pos + 4 <= self.chars.len()
            && self.chars[self.pos..self.pos + 4] == ['n', 'u', 'l', 'l']
        {
            self.pos += 4;
            Ok(JsonValue::Null)
        } else {
            Err(format!("Invalid null token at pos {}", self.pos))
        }
    }

    fn parse_number(&mut self) -> Result<JsonValue, String> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.consume();
        }

        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-' {
                self.consume();
            } else {
                break;
            }
        }

        let num_str: String = self.chars[start..self.pos].iter().collect();
        num_str
            .parse::<f64>()
            .map(JsonValue::Number)
            .map_err(|e| format!("Invalid number '{}': {}", num_str, e))
    }
}

pub fn parse_json(input: &str) -> Result<JsonValue, String> {
    let mut parser = JsonParser::new(input);
    parser.parse()
}

pub fn to_canonical_json_string(val: &JsonValue) -> String {
    format!("{}", val)
}

pub fn to_pretty_json_string(val: &JsonValue) -> String {
    to_pretty_json_string_indent(val, 0)
}

pub fn to_pretty_json_string_indent(val: &JsonValue, indent: usize) -> String {
    let spaces = " ".repeat(indent);
    match val {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(b) => format!("{}", b),
        JsonValue::Number(n) => {
            if n.fract() == 0.0 && !n.is_nan() && !n.is_infinite() && n.abs() < 1e15 {
                format!("{:.0}", n)
            } else {
                format!("{}", n)
            }
        }
        JsonValue::String(s) => {
            let mut out = String::from("\"");
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    other => out.push(other),
                }
            }
            out.push('"');
            out
        }
        JsonValue::Array(arr) => {
            if arr.is_empty() {
                return "[]".to_string();
            }
            let mut out = String::from("[\n");
            for (i, elem) in arr.iter().enumerate() {
                out.push_str(&" ".repeat(indent + 2));
                out.push_str(&to_pretty_json_string_indent(elem, indent + 2));
                if i + 1 < arr.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&spaces);
            out.push(']');
            out
        }
        JsonValue::Object(map) => {
            if map.is_empty() {
                return "{}".to_string();
            }
            let mut out = String::from("{\n");
            let mut items: Vec<_> = map.iter().collect();
            items.sort_by(|a, b| a.0.cmp(b.0));
            for (i, (k, elem)) in items.iter().enumerate() {
                out.push_str(&" ".repeat(indent + 2));
                out.push_str(&format!("\"{}\": ", k));
                out.push_str(&to_pretty_json_string_indent(elem, indent + 2));
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&spaces);
            out.push('}');
            out
        }
    }
}
