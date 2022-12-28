use cryptopals::tools::load_base64_file;
use openssl::symm::{Cipher, decrypt};

fn main() {
    let bytes = load_base64_file("./res/s01e07");
    let key = b"YELLOW SUBMARINE";
    let plaintext = decrypt(Cipher::aes_128_ecb(), key, None, &bytes).unwrap();
    println!("{}", String::from_utf8_lossy(&plaintext));
}