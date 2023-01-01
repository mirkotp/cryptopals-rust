use cryptopals::crypto::{pkcs7_unpad, PaddingError};

fn main() {
    // The pkcs7_unpad function is already able to return an error
    // if the padding is invalid.
    assert_eq!(pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04", 16), Ok(b"ICE ICE BABY".to_vec()));
    assert_eq!(pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05", 16), Err(PaddingError::InvalidPadding));
    assert_eq!(pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04", 16), Err(PaddingError::InvalidPadding));
    println!("Ok!");
}