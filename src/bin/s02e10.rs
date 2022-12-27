use std::io::{BufReader, BufRead};
use std::fs::File;
use cryptopals::{xor, pkcs7_pad, pkcs7_unpad, ToBytes};
use openssl::symm::{Cipher, encrypt, Crypter, Mode};

// TODO function for loading base64 file
// TODO tests

fn main() {
    let file = File::open("./res/s02e10").unwrap();
    let reader = BufReader::new(file);

    let mut bytes = Vec::with_capacity(64*60/4*3);  // We know the size of
                                                    // the input file.
    for line in reader.lines() {
        let mut line_bytes = line.unwrap().parse_base64().unwrap();
        bytes.append(&mut line_bytes);
    }

    let iv = [0u8; 16];
    let key = b"YELLOW SUBMARINE";

    let pl3 = cbc_decrypt(&bytes, key, &iv);
    println!("{}", String::from_utf8_lossy(&pl3)); 
}

fn cbc_encrypt(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
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

        let xored = xor(slice, &iv);
        let ciphertext = encrypt(cipher, key, Some(&iv), &xored).unwrap();
        iv = ciphertext[..16].to_vec().clone();
        
        output.extend_from_slice(&ciphertext[..16]); 
    }

    output
}

fn cbc_decrypt(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
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
        let xored = xor(&buffer, &iv);
        iv = slice.to_vec();
    
        output.extend_from_slice(&xored[..16]);
    }

    pkcs7_unpad(&output, block_size as u8)
}