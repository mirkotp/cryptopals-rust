use cryptopals::pkcs7_padding;

fn main() {
    assert_eq!(pkcs7_padding(b"YELLOW SUBMARINE", 20), b"YELLOW SUBMARINE\x04\x04\x04\x04");
    assert_eq!(pkcs7_padding(b"YELLOW SUBMARINE!", 20), b"YELLOW SUBMARINE!\x03\x03\x03");
    assert_eq!(pkcs7_padding(b"YELLOW SUBMARINE!!", 20), b"YELLOW SUBMARINE!!\x02\x02");
    assert_eq!(pkcs7_padding(b"YELLOW SUBMARINE!!!", 20), b"YELLOW SUBMARINE!!!\x01");
    assert_eq!(pkcs7_padding(b"YELLOW SUBMARINE!!!!", 20), b"YELLOW SUBMARINE!!!!");
    assert_eq!(pkcs7_padding(b"YELLOW SUBMARINE!!!!!", 20), b"YELLOW SUBMARINE!!!!!\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13");
    println!("OK!");
}