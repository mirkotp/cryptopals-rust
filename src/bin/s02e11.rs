use cryptopals::crypto::{random_bytes, aes_cbc_encrypt};
use openssl::symm::{encrypt, Cipher};
use rand::Rng;

fn main() {
    // We treat our 'encryption_oracle' function as a black box,
    // so we only use the boolean 'is_cbc' only to verify the results.
    // 
    // Since ECB mode doesn't use an initialization vector and since
    // it is deterministic, we know two equal blocks in the plaintext
    // will have the same encryption.
    //
    // In this case we know the encryption oracle will add 5 to 10
    // random bytes at the end and at the beginning of the plaintext,
    // so we just need to repeat a block-sized plaintext 3 times to
    // be sure that the second and third block of the ciphertext will
    // be identical (in ECB) and different with CBC.
    // Hadn't we known this we could have tried with a longer, or 
    // much longer, plaintext with more repetitions.
    
    let plaintext = b"YELLOWSUBMARINE!YELLOWSUBMARINE!YELLOWSUBMARINE!";
    let tries = 100000;

    let mut count = 0;
    for _ in 0..tries {
        let (ciphertext, is_cbc) = encryption_oracle(plaintext);
        let cbc_detected = ciphertext[16..=31] != ciphertext[32..=47];

        if is_cbc == cbc_detected {
           count += 1;
        }
    }

    println!("Correct guesses: {} out of {}", count, tries);
}

fn encryption_oracle(data: &[u8]) -> (Vec<u8>, bool) {
    let mut rng = rand::thread_rng();
    let use_cbc: bool = rng.gen();
    
    let key = random_bytes(16);
    let prefix = random_bytes(rng.gen_range(5..=10));
    let suffix = random_bytes(rng.gen_range(5..=10));

    let salted = [prefix, data.to_vec(), suffix].concat();

    if use_cbc {
        (aes_cbc_encrypt(&salted, &key, &[0; 16]), true)
    } else {
        (encrypt(Cipher::aes_128_ecb(), &key, None, &salted).unwrap(), false)
    }
}
