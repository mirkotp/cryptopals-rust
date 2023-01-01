use cryptopals::tools::{ToBytes};
use openssl::symm::{encrypt, Cipher};
fn main() {
    // Let's skip the discovery of the block size and the ECB detection
    // as they are the same as in challenge 12.
    let block_size = 16;
    let initial_length = encryption_oracle(b"").len();

    // Here we count how many bytes we need to add in order to get two 
    // repeated blocks, this will help us identify the size of the 
    // prefix.
    let mut prefix_size = 0;
    'outer: for i in 2*block_size..=3*block_size {
        let cipher = encryption_oracle(&vec![b'A'; i]);
        
        for j in (block_size..cipher.len()).step_by(block_size) {
            if cipher[j..j+block_size] == cipher[j-block_size..j] {
                prefix_size = j-block_size-(i-2*block_size);
                break 'outer;
            }
        }
    }

    let offset_blocks = (prefix_size / block_size) + 1;
    let offset_bytes = (block_size - (prefix_size % block_size)) % block_size;
    let suffix_size = initial_length - offset_blocks * block_size;

    // Let's find the content of the suffix added by the encryption_oracle
    // function by exploiting a vulnerability in ECB mode.
    let mut padding = vec![b'A'; suffix_size+offset_bytes];
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
    let prefix = "oppg7QsSlFk7QoPe1/z91ynBdPdXRNpbAglRyhH1".parse_base64().unwrap();
    let suffix = ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg".to_string()
                + "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                + "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                + "YnkK").parse_base64().unwrap();

    let salted = [&prefix, data, &suffix].concat();
    encrypt(Cipher::aes_128_ecb(), &key, None, &salted).unwrap()
}
