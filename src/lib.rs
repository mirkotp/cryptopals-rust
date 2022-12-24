#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidHexStringError,
    InvalidBase64StringError,
    NotEqualSizeError
}

/// Trait with conversions to string representations
pub trait AsString {
    /// Converts into hex representation
    fn as_hex(&self) -> String;

    /// Converts into base64 representation
    fn as_base64(&self) -> String;
}

impl AsString for [u8] {
    fn as_hex(&self) -> String {
        let mut result = "".to_owned();
        for n in self {
            result.push_str(&format!("{:02x}", n));
        }

        result
    }

    fn as_base64(&self) -> String {
        // Encode in base64
        let mut base64: Vec<u8> = Vec::with_capacity(self.len()/3*4);
        let mut iter = self.iter();

        // Base64 is encoded in groups of three bytes, if the
        // length of the byte vector is not a multiple of 3,
        // it will be necessary to add '=' padding at the end.
        loop {
            if let Some(b1) = iter.next() {
                base64.push(b1 >> 2);
                base64.push((b1 & 0b11) << 4);
            } else {
                break;
            }

            if let Some(b2) = iter.next() {
                let last = base64.pop().unwrap();
                base64.push(last | (b2 >> 4));
                base64.push((b2 & 0b1111) << 2);
            } else {
                // Padding
                base64.push(64);
                base64.push(64);
                break;
            }

            if let Some(b3) = iter.next() {
                let last = base64.pop().unwrap();
                base64.push(last | (b3 >> 6));
                base64.push(b3 & 0b111111);
            } else {
                // Padding
                base64.push(64);
                break;
            }
        }

        // Convert to string
        for b in &mut base64 {
            *b = match b {
                0..=25  => 'A' as u8 + *b,
                26..=51 => 'a' as u8 + (*b - 26),
                52..=61 => '0' as u8 + (*b - 52),
                62      => '+' as u8,
                63      => '/' as u8,
                64..    => '=' as u8
            };
        }

        String::from_utf8_lossy(&base64).into_owned()
    }
}

/// Trait with conversions to bytes
pub trait ToBytes {
    fn parse_hex(&self) -> Result<Vec<u8>, Error>;
    fn parse_base64(&self) -> Result<Vec<u8>, Error>;
}

impl ToBytes for str {
    /// Convert string representing an hex number to its bytes
    fn parse_hex(&self) -> Result<Vec<u8>, Error> {
        let input_bytes = self.as_bytes();
        let mut out = Vec::new();

        let get4bits = |x: u8| -> Result<u8, Error> {
            match x {
                48..=57 =>  Ok(x - 48), // '0' to '9' -> 0 to 9 
                65..=70 =>  Ok(x - 55), // 'A' to 'F' -> 10 to 15
                97..=102 => Ok(x - 87), // 'a' to 'f' -> 10 to 15
                _ => Err(Error::InvalidHexStringError)
            }
        };

        for i in (0..input_bytes.len()).step_by(2) {
            let b1 = get4bits(input_bytes[i])?;
            let b2 = get4bits(*input_bytes.get(i+1).unwrap())?;

            out.push((b1 << 4) | b2);
        }

        Ok(out)
    }

    /// Takes as input a base64 string and returns the corresponding
    /// byte vector
    fn parse_base64(&self) -> Result<Vec<u8>, Error> {
        let convert = |x| -> Result<u8, Error> {
            match x {
                'A'..='Z' => Ok(x as u8 - 65),
                'a'..='z' => Ok(x as u8 - 71),
                '0'..='9' => Ok(x as u8 + 4),
                '+'       => Ok(62),
                '/'       => Ok(63),
                _         => Err(Error::InvalidBase64StringError)
            }
        };

        let chars: Vec<char> = self.trim_end_matches('=').chars().collect();
        let mut bytes: Vec<u8> = Vec::with_capacity(self.len()/4*3);

        for i in (0..chars.len()).step_by(4) {
            let b1 = convert(chars[i])?;

            if let Some(c2) = chars.get(i+1) {
                let b2 = convert(*c2)?;
                bytes.push((b1 << 2) | (b2 >> 4));

                if let Some(c3) = chars.get(i+2) {
                    let b3 = convert(*c3)?;
                    bytes.push(((b2 & 0b1111) << 4) | (b3 >> 2));

                    if let Some(c4) = chars.get(i+3) {
                        let b4 = convert(*c4)?;
                        bytes.push(((b3 & 0b11) << 6) | b4);
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                bytes.push(b1 << 2);
                break;
            }
        }

        Ok(bytes)
    }
}

/// Performs a XOR of a byte sequence on a single char key.
/// Outputs a String
pub fn xor_char(bytes: &[u8], c: u8) -> String {
    let mut result = Vec::with_capacity(bytes.len());

    for i in 0..bytes.len() {
        result.push(bytes[i] ^ c);
    }

   String::from_utf8_lossy(&result).to_string()
}

/// Performs a byte by byte XOR of a byte sequence on a 
/// repeated key.
pub fn xor(s: &[u8], k: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut key = k.iter().cycle();

    for i in 0..s.len() {
        out.push(s[i]^key.next().unwrap())
    }

    out
}

/// Computes the Hamming distance (number of differing bits) between
/// two equally-sized byte sequences.
pub fn hamming_distance(a: &[u8], b: &[u8]) -> Result<u32, Error> {
    if a.len() != b.len() {
        return Err(Error::NotEqualSizeError);
    }
    
    let mut dist = 0;
    for i in 0..a.len() {
        dist += u8::count_ones(a[i] ^ b[i]);
    }

    Ok(dist)
}

/// Returns a score for the argument string based on
/// frequencies of characters in the English language.
pub fn english_score(s: &str) -> f64 {
    let mut score = 0f64;

    for c in s.chars() {
        score += match c.to_ascii_uppercase() {
            'E' => 12.02,   'T' => 9.10,    'A' => 8.12,    'O' => 7.68,
            'I' => 7.31,    'N' => 6.95,    'S' => 6.28,    'R' => 6.02,
            'H' => 5.92,    'D' => 4.32,    'L' => 3.98,    'U' => 2.88,
            'C' => 2.71,    'M' => 2.61,    'F' => 2.30,    'Y' => 2.11,
            'W' => 2.09,    'G' => 2.03,    'P' => 1.82,    'B' => 1.49,
            'V' => 1.11,    'K' => 0.69,    'X' => 0.17,    'Q' => 0.11,
            'J' => 0.10,    'Z' => 0.07,    ' ' | '\'' => 0.0,
            _ => -20.0
        }
    }

    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_works() {
        assert_eq!(
            "0123456789aAbBcCdDeEfF".parse_hex().unwrap(),
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        );

        assert_eq!("123abcXYZ".parse_hex(), Err(Error::InvalidHexStringError));
    }

    #[test]
    fn parse_base64_works() {
        assert_eq!("".parse_base64().unwrap(),         b"");
        assert_eq!("Zg==".parse_base64().unwrap(),     b"f");
        assert_eq!("Zm8=".parse_base64().unwrap(),     b"fo");
        assert_eq!("Zm9v".parse_base64().unwrap(),     b"foo");
        assert_eq!("Zm9vYg==".parse_base64().unwrap(), b"foob");
        assert_eq!("Zm9vYmE=".parse_base64().unwrap(), b"fooba");
        assert_eq!("Zm9vYmFy".parse_base64().unwrap(), b"foobar");
    }

    #[test]
    fn to_hex_works() {
        assert_eq!(
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF].as_hex(),
            "0123456789aabbccddeeff"
        );

        assert_eq!("123abcXYZ".parse_hex(), Err(Error::InvalidHexStringError));
    }

    #[test]
    fn to_base64_works() {
        assert_eq!(b"".as_base64(),       "");
        assert_eq!(b"f".as_base64(),      "Zg==");
        assert_eq!(b"fo".as_base64(),     "Zm8=");
        assert_eq!(b"foo".as_base64(),    "Zm9v");
        assert_eq!(b"foob".as_base64(),   "Zm9vYg==");
        assert_eq!(b"fooba".as_base64(),  "Zm9vYmE=");
        assert_eq!(b"foobar".as_base64(), "Zm9vYmFy");
    }


    #[test]
    fn xor_char_works() {
        assert_eq!(xor_char(b"ABC444", 'v' as u8), "745BBB");
    }

    #[test]
    fn xor_works() {
        assert_eq!(xor(b"ABC444", b"v"), b"745BBB");
    }

    #[test]
    fn hamming_distance_works() {
        assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), Ok(37));
        assert_eq!(hamming_distance(b"this is a test", b"wrong size"), Err(Error::NotEqualSizeError));
    }
}