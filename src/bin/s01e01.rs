use cryptopals::{ToBytes, AsString};

fn main() {
    let bytes = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".parse_hex().unwrap();
    let b64 = &bytes.as_base64();
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    assert_eq!(b64, expected);
    println!("{}", b64);
    println!("OK!");
}