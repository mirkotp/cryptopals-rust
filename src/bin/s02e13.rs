use json::{object, JsonValue};
use openssl::symm::{decrypt, encrypt, Cipher};

fn main() {
    // We already know how to find the block size
    let block_size = 16;

    let enc = profile_encrypt("");
    let blocks = enc.len() / block_size;

    'outer: for i in 1..=16 {
        // We act as we don't know the prefix and suffix added by
        // the profile_for function, so the first step is to find
        // how many bits we need to add to make the plaintext an
        // exact multiple of the block size.
        let enc = profile_encrypt(&String::from_utf8_lossy(&vec![b'a'; i]));
        let cur_blocks = enc.len() / block_size;
        if cur_blocks > blocks {
            // Now pad with another 4 bits to put the string "user" in
            // the next block
            let aligned_enc = profile_encrypt(&String::from_utf8_lossy(&vec![b'a'; i + 4]));
            let all_but_last = &aligned_enc[..block_size * (blocks)];

            // Find how the block "admin" would be encoded, by adding the padded
            // "admin" string 3 times and looking for two identical blocks in the
            // ciphertext.
            // We don't know the length of the prefix so we make a few tries.
            for i in 0..16 {
                let input: String = "admin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B"
                    .chars()
                    .cycle()
                    .skip(i)
                    .take(48)
                    .collect();

                let last = profile_encrypt(&input);

                for j in 1..(last.len() / block_size) {
                    let base = j * block_size;

                    // Once we find two equal blocks we use them as our last block
                    if last[base - block_size..base] == last[base..base + block_size] {
                        let cipher = [all_but_last, &last[base - block_size..base]].concat();
                        if let Some(dec) = profile_decrypt(&cipher) {
                            for (k, v) in dec.entries() {
                                if k == "role" && v == "admin" {
                                    // Found!
                                    println!("{}", &dec);
                                    break 'outer;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// Random key
const KEY: [u8; 16] = [
    222, 169, 210, 64, 54, 245, 202, 169, 10, 22, 227, 110, 176, 43, 11, 165,
];

fn kv_to_json(input: &str) -> Option<JsonValue> {
    let mut out = object! {};
    for s in input.split('&') {
        if let Some((k, v)) = s.split_once('=') {
            out.insert(k, v).unwrap();
        } else {
            return None;
        }
    }
    Some(out)
}

fn profile_for(email: &str) -> String {
    let email = email.to_string().replace("&", "").replace("=", "");
    "email=".to_string() + &email + "&uid=10&role=user"
}

fn profile_encrypt(email: &str) -> Vec<u8> {
    let plain = profile_for(email);
    encrypt(Cipher::aes_128_ecb(), &KEY, None, &plain.as_bytes()).unwrap()
}

fn profile_decrypt(cipher: &[u8]) -> Option<JsonValue> {
    if let Ok(plain) = decrypt(Cipher::aes_128_ecb(), &KEY, None, cipher) {
        kv_to_json(&String::from_utf8_lossy(&plain))
    } else {
        None
    }
}
