use cryptopals::base64_to_bytes;
use std::io::{BufReader, BufRead};
use std::fs::File;
use openssl::symm::{Cipher, decrypt};

fn main() {
    let file = File::open("./res/s01e07").unwrap();
    let reader = BufReader::new(file);

    let mut bytes = Vec::with_capacity(64*60/4*3);  // We know the size of
                                                    // the input file.
    for line in reader.lines() {
        let mut line_bytes = base64_to_bytes(&line.unwrap()).unwrap();
        bytes.append(&mut line_bytes);
    }

    let key = b"YELLOW SUBMARINE";
    let plaintext = decrypt(Cipher::aes_128_ecb(), key, None, &bytes).unwrap();
    println!("{}", String::from_utf8_lossy(&plaintext));    // TODO bytes to string
}