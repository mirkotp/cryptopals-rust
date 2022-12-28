use cryptopals::crypto::aes_cbc_decrypt;
use cryptopals::tools::load_base64_file;

fn main() {
    let bytes = load_base64_file("./res/s02e10");

    let iv = [0u8; 16];
    let key = b"YELLOW SUBMARINE";

    let plaintext = aes_cbc_decrypt(&bytes, key, &iv).unwrap();
    println!("{}", String::from_utf8_lossy(&plaintext)); 
}