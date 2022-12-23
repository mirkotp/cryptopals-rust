use cryptopals::{parse_hex, bytes_to_base64};

fn main() {
    let bytes = parse_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
    let b64 = bytes_to_base64(&bytes);
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    assert_eq!(b64, expected);
    println!("{}", b64);
    println!("OK!");
}