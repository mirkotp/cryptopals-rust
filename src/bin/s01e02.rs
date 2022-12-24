use cryptopals::{AsString, ToBytes};

fn main() {
    let bytes = "1c0111001f010100061a024b53535009181c".parse_hex().unwrap();
    let key = "686974207468652062756c6c277320657965".parse_hex().unwrap();
    let result = fixed_xor(&bytes, &key).unwrap();

    let expected = "746865206b696420646f6e277420706c6179".parse_hex().unwrap();
    
    assert_eq!(result, expected);
    println!("{}", result.as_hex());
    println!("OK!");
}

#[derive(Debug, PartialEq)]
struct DifferentSizeError;

/// Performs a byte by byte XOR of two equally-sized sequences
fn fixed_xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>, DifferentSizeError> {
    if a.len() != b.len() {
        return Err(DifferentSizeError);
    }
    
    let mut out: Vec<u8> = Vec::with_capacity(a.len());
    for i in 0..a.len() {
        out.push(a[i]^b[i]);
    }

    Ok(out)
}

#[test]
fn fixed_xor_works() {
    let a = "1c0111001f010100061a024b53535009181c".parse_hex().unwrap();
    let b = "686974207468652062756c6c277320657965".parse_hex().unwrap();
    let c = "123444".parse_hex().unwrap();

    assert_eq!(fixed_xor(&a, &b).unwrap(), "746865206b696420646f6e277420706c6179".parse_hex().unwrap());
    assert_eq!(fixed_xor(&a, &c), Err(DifferentSizeError))
}    