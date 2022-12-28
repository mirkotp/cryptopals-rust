use cryptopals::crypto::pkcs7_pad;

fn main() {
    assert_eq!(pkcs7_pad(b"YELLOW SUBMARINE", 20), b"YELLOW SUBMARINE\x04\x04\x04\x04");
    assert_eq!(pkcs7_pad(b"YELLOW SUBMARINE!", 20), b"YELLOW SUBMARINE!\x03\x03\x03");
    assert_eq!(pkcs7_pad(b"YELLOW SUBMARINE!!", 20), b"YELLOW SUBMARINE!!\x02\x02");
    assert_eq!(pkcs7_pad(b"YELLOW SUBMARINE!!!", 20), b"YELLOW SUBMARINE!!!\x01");
    assert_eq!(pkcs7_pad(b"YELLOW SUBMARINE!!!!", 20), b"YELLOW SUBMARINE!!!!\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14");
    assert_eq!(pkcs7_pad(b"YELLOW SUBMARINE!!!!!", 20), b"YELLOW SUBMARINE!!!!!\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13");
    println!("OK!");
}