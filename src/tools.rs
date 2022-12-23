#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidHexStringError,
    InvalidBase64StringError,
    NotEqualSizeError
}

/// Convert string representing an hex number to its bytes
pub fn parse_hex(input: &str) -> Result<Vec<u8>, Error> {
    let input_bytes = input.as_bytes();
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

/// Takes as input a string representing a hexadecimal value and returns
/// its base64 representation.
pub fn bytes_to_base64(input: &[u8]) -> String {
    // Encode in base64
    let mut base64: Vec<u8> = Vec::with_capacity(input.len()/3*4);
    let mut iter = input.iter();

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

/// Takes as input a base64 string and returns the corresponding
/// byte vector
pub fn base64_to_bytes(input: &str) -> Result<Vec<u8>, Error> {
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

    let chars: Vec<char> = input.trim_end_matches('=').chars().collect();
    let mut bytes: Vec<u8> = Vec::with_capacity(input.len()/4*3);

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

/// Computes the Hamming distance between two equally-sized byte sequences
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

/// Performs a byte by byte XOR of two equally-sized sequences
pub fn fixed_xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>, Error> {
    if a.len() != b.len() {
        return Err(Error::NotEqualSizeError);
    }
    
    let mut out: Vec<u8> = Vec::with_capacity(a.len());
    for i in 0..a.len() {
        out.push(a[i]^b[i]);
    }

    Ok(out)
}

/// Converts a u8 sequence into a String and performs a XOR
/// on each character against a given value. 
pub fn single_byte_xor(bytes: &[u8], c: u8) -> String {
    // let mut result: Vec<u16> = Vec::with_capacity(bytes.len()/2);
    let mut result = Vec::with_capacity(bytes.len());

    for i in 0..bytes.len() {
        result.push(bytes[i] ^ c);
    }

    String::from_utf8_lossy(&result).to_string()
}

/// Performs a byte by byte XOR of a byte sequence on a repeated key.
pub fn xor(s: &[u8], k: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut key = k.iter().cycle();

    for i in 0..s.len() {
        out.push(s[i]^key.next().unwrap())
    }

    out
}

/// Returns a score for the argument string based on
/// frequencies of characters in the English language.
pub fn score(s: &String) -> f64 {
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
            parse_hex("0123456789aAbBcCdDeEfF").unwrap(),
            [01, 35, 69, 103, 137, 170, 187, 204, 221, 238, 255]
        );

        assert_eq!(parse_hex("123abcXYZ"), Err(Error::InvalidHexStringError));
    }

    #[test]
    fn bytes_to_base64_works() {
        let b = parse_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
        assert_eq!(
            bytes_to_base64(&b),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );

        assert_eq!(bytes_to_base64(b""),       "");
        assert_eq!(bytes_to_base64(b"f"),      "Zg==");
        assert_eq!(bytes_to_base64(b"fo"),     "Zm8=");
        assert_eq!(bytes_to_base64(b"foo"),    "Zm9v");
        assert_eq!(bytes_to_base64(b"foob"),   "Zm9vYg==");
        assert_eq!(bytes_to_base64(b"fooba"),  "Zm9vYmE=");
        assert_eq!(bytes_to_base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_to_bytes_works() {
        let b = parse_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
        assert_eq!(
            base64_to_bytes("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t").unwrap(),
            b
        );

        assert_eq!(base64_to_bytes("").unwrap(),         b"");
        assert_eq!(base64_to_bytes("Zg==").unwrap(),     b"f");
        assert_eq!(base64_to_bytes("Zm8=").unwrap(),     b"fo");
        assert_eq!(base64_to_bytes("Zm9v").unwrap(),     b"foo");
        assert_eq!(base64_to_bytes("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(base64_to_bytes("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(base64_to_bytes("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn fixed_xor_works() {
        let a = parse_hex("1c0111001f010100061a024b53535009181c").unwrap();
        let b = parse_hex("686974207468652062756c6c277320657965").unwrap();
        let c = parse_hex("123444").unwrap();

        assert_eq!(fixed_xor(&a, &b), parse_hex("746865206b696420646f6e277420706c6179"));
        assert_eq!(fixed_xor(&a, &c), Err(Error::NotEqualSizeError))
    }    

    #[test]
    fn single_byte_xor_works() {
        assert_eq!(
            single_byte_xor(
                &parse_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap(), 
                'X' as u8
            ),
            "Cooking MC's like a pound of bacon"
        )
    }

    #[test]
    fn xor_works() {
        let plain = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let k = b"ICE";
        let cipher = parse_hex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();
        
        assert_eq!(xor(plain, k), cipher);
    }

    #[test]
    fn hamming_distance_works() {
        assert_eq!(
            hamming_distance(&b"this is a test".to_vec(), &b"wokka wokka!!!".to_vec()),
            Ok(37)
        );
    }
}