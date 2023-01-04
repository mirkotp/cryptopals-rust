use cryptopals::tools::ToBytes;
use openssl::symm::{encrypt, Cipher};

fn main() {
    // Discover the block size. Idea: since the plaintext is appended an
    // unknown-length string we need to add a single character at a time
    // to it, and compare the length of the resulting ciphertext until we
    // find the one that triggers the creation of a new block.
    // The difference in length will be the block size.
    let initial_length = encryption_oracle(b"").len();
    let mut block_size = 0;
    for i in 0..=1024 {
        let c = encryption_oracle(&vec![b'A'; i]);

        if c.len() > initial_length {
            block_size = c.len() - initial_length;
            break;
        }
    }

    // Detect ECB: this is a very simple way to do this because we know 
    // how the implementation of the encrypting function, but we could have 
    // used a much longer plaintext and count repetition for a more general 
    // solution.
    let ciphertext = encryption_oracle(b"YELLOWSUBMARINE!YELLOWSUBMARINE!");
    if ciphertext[0..=15] == ciphertext[16..=31] {
        // ECB detected
    } else {
        println!("Not ECB!");
    }

    // Let's find the content of the suffix added by the encryption_oracle
    // function by exploiting a vulnerability in ECB mode.
    let mut padding = vec![b'A'; initial_length];
    let mut out = Vec::new();
    let b_start = ((initial_length)/block_size-1)*block_size;
    let b_end = b_start + block_size;
    for _ in 0..initial_length {
        padding.pop();

        for b in u8::MIN..u8::MAX {
            let c1 = encryption_oracle(&padding);

            let mut candidate = padding.clone();
            candidate.extend(&out);
            candidate.push(b);
            let c2 = encryption_oracle(&candidate);

            if c1[b_start..b_end] == c2[b_start..b_end] {
                out.push(b);
                break;
            }
        }
    }

    println!("{}", String::from_utf8_lossy(&out));
}

fn encryption_oracle(data: &[u8]) -> Vec<u8> {   
    let key = "P9IsxxsZAUc9Gdx4zbdbFA==".parse_base64().unwrap();
    let salt = ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg".to_string()
                + "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                + "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                + "YnkK").parse_base64().unwrap();

    let salted = [data, &salt].concat();
    encrypt(Cipher::aes_128_ecb(), &key, None, &salted).unwrap()

}
