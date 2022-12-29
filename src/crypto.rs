use openssl::{symm::{Crypter, Cipher, Mode, encrypt}};
use rand::Rng;

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
pub fn xor_string(s: &[u8], k: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut key = k.iter().cycle();

    for c in s.iter() {
        // We're sure there's always a next 
        // element because of "cycle".
        out.push(c^key.next().unwrap());
    }

    out
}

/// Pads byte sequences according to PKCS#7
pub fn pkcs7_pad(bytes: &[u8], block_size: u8) -> Vec<u8> {
    let block_size = block_size as usize;
    let r = block_size - (bytes.len() % block_size);
    let mut result = bytes.to_vec();

    for _ in 0..r {
        result.push(r as u8);
    }

    result
}

#[derive(Debug, PartialEq)]
pub enum PaddingError{
    InvalidLength,
    InvalidPadding
}

/// Unpads byte sequences according to PKCS#7
pub fn pkcs7_unpad(bytes: &[u8], block_size: u8) -> Result<Vec<u8>, PaddingError> {
    if bytes.len() % block_size as usize != 0 || bytes.len() == 0 {
        return Err(PaddingError::InvalidLength);
    }

    let last = bytes[bytes.len()-1];
    if bytes.len() < last as usize {
        return Err(PaddingError::InvalidPadding);
    }

    let mut output = bytes.to_vec();
    let last_elements = &bytes[(bytes.len()-last as usize)..];

    if last_elements == vec![last; last as usize] {
        output.truncate(bytes.len()-last as usize);
    } else {
        return Err(PaddingError::InvalidPadding);
    }

    output.truncate(bytes.len()-last as usize);
    Ok(output)
}

/// Implements encryption AES-128-CBC by using ECB mode
pub fn aes_cbc_encrypt(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let block_size =cipher.block_size();
    let mut output = Vec::with_capacity(bytes.len()+32);
    let mut iv = iv.to_vec();
    let bytes = pkcs7_pad(bytes, block_size as u8);

    for i in (0..bytes.len()).step_by(block_size) {
        let slice = if i+block_size+1 < bytes.len() { 
            &bytes[i..(i+block_size)] 
        } else {
            &bytes[i..] 
        };

        let xored = xor_string(slice, &iv);
        let ciphertext = encrypt(cipher, key, Some(&iv), &xored).unwrap();
        iv = ciphertext[..16].to_vec().clone();
        
        output.extend_from_slice(&ciphertext[..16]); 
    }

    output
}

/// Implements decryption AES-128-CBC by using ECB mode
pub fn aes_cbc_decrypt(bytes: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, PaddingError> {
    let cipher = Cipher::aes_128_ecb();
    let block_size = cipher.block_size();
    let mut output: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut iv = iv.to_vec();
    
    for i in (0..bytes.len()).step_by(block_size) {
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(&iv)).unwrap();
        let slice = if i+block_size+1 < bytes.len() { 
            &bytes[i..(i+block_size)] 
        } else {
            &bytes[i..] 
        };

        let mut buffer = [0; 32];
        crypter.update(slice, &mut buffer).unwrap();
        let xored = xor_string(&buffer, &iv);
        iv = slice.to_vec();
    
        output.extend_from_slice(&xored[..16]);
    }

    pkcs7_unpad(&output, block_size as u8)
}

/// Generates a random key of the desired size
pub fn random_bytes(size: usize) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::with_capacity(size);
    let mut rng = rand::thread_rng();

    for _ in 0..size {
        key.push(rng.gen()); 
    }

    key
}

#[cfg(test)]
mod tests {
    use crate::tools::{ToBytes, AsString};

    use super::*;

    #[test]
    fn xor_char_works() {
        assert_eq!(xor_char(b"ABC444", 'v' as u8), "745BBB");
    }

    #[test]
    fn xor_works() {
        assert_eq!(xor_string(b"ABC444", b"v"), b"745BBB");
    }


    #[test]
    fn pkcs7_pad_works() {
        assert_eq!(pkcs7_pad(b"YELLOW SUBMARINE", 20), b"YELLOW SUBMARINE\x04\x04\x04\x04");
        assert_eq!(pkcs7_pad(b"YELLOW SUBMARINE!", 20), b"YELLOW SUBMARINE!\x03\x03\x03");
        assert_eq!(pkcs7_pad(b"YELLOW SUBMARINE!!", 20), b"YELLOW SUBMARINE!!\x02\x02");
        assert_eq!(pkcs7_pad(b"YELLOW SUBMARINE!!!", 20), b"YELLOW SUBMARINE!!!\x01");
        assert_eq!(pkcs7_pad(b"YELLOW SUBMARINE!!!!", 20), b"YELLOW SUBMARINE!!!!\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14");
        assert_eq!(pkcs7_pad(b"YELLOW SUBMARINE!!!!!", 20), b"YELLOW SUBMARINE!!!!!\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13");
    }

    #[test]
    fn pkcs7_unpad_works() {
        assert_eq!(pkcs7_unpad(b"YELLOW SUBMARINE\x02\x02", 18).unwrap(), b"YELLOW SUBMARINE");
        assert_eq!(pkcs7_unpad(b"YELLOW SUBMARINE!\x01", 18).unwrap(), b"YELLOW SUBMARINE!");
        assert_eq!(pkcs7_unpad(b"YELLOW SUBMARINE!!\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12", 18).unwrap(), b"YELLOW SUBMARINE!!");
        assert_eq!(pkcs7_unpad(b"YELLOW SUBMARINE!!!\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11", 18).unwrap(), b"YELLOW SUBMARINE!!!");

        assert_eq!(pkcs7_unpad(b"YELLOW SUBMARINE\x01", 18), Err(PaddingError::InvalidLength));
        assert_eq!(pkcs7_unpad(b"YELLOW SUBMARINE\x03\x03", 18), Err(PaddingError::InvalidPadding));    
    }


    #[test]
    fn aes_cbc_works() {
        let p1 = b"< 1 block";
        let p2 = b"exactly 1 block!";
        let p3 = b"more than one block";
        let p4 = b"Exactly 2 blocksExactly 2 blocks";
        let p5 = b"Just a little something more than two blocks";

        let key = b"YELLOW SUBMARINE";
        let iv = [0; 16];

        assert_eq!(aes_cbc_decrypt(&aes_cbc_encrypt(p1, key, &iv), key, &iv).unwrap(), p1);
        assert_eq!(aes_cbc_decrypt(&aes_cbc_encrypt(p2, key, &iv), key, &iv).unwrap(), p2);
        assert_eq!(aes_cbc_decrypt(&aes_cbc_encrypt(p3, key, &iv), key, &iv).unwrap(), p3);
        assert_eq!(aes_cbc_decrypt(&aes_cbc_encrypt(p4, key, &iv), key, &iv).unwrap(), p4);
        assert_eq!(aes_cbc_decrypt(&aes_cbc_encrypt(p5, key, &iv), key, &iv).unwrap(), p5);

        assert_eq!(&aes_cbc_encrypt(p1, key, &iv).as_base64(), "vXopWVGO/WC3SVZ7u68hGg==");
        assert_eq!(&aes_cbc_encrypt(p5, key, &iv).as_base64(), "xEspv6Mj7bwAOoH4TPUSTLiXj4FZLnLRBuEXu9mxKzu3S3ZVbrU6EzO7M4japWRT");

        assert_eq!(aes_cbc_decrypt(&"vXopWVGO/WC3SVZ7u68hGg==".parse_base64().unwrap(), key, &iv).unwrap(), p1);
        assert_eq!(aes_cbc_decrypt(&"xEspv6Mj7bwAOoH4TPUSTLiXj4FZLnLRBuEXu9mxKzu3S3ZVbrU6EzO7M4japWRT".parse_base64().unwrap(), key, &iv).unwrap(), p5);
    }
}