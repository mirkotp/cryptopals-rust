use cryptopals::tools::{hamming_distance, english_score, load_base64_file};
use cryptopals::crypto::{xor_char, xor_string};

fn main() {
    let bytes = load_base64_file("./res/s01e06");

    let mut best_distance = f64::INFINITY;
    let mut best_ksize = 0;
    for ksize in 2..=40 {
        let block1 = &bytes[0..ksize];
        let block2 = &bytes[ksize..(2*ksize)];
        let block3 = &bytes[(2*ksize)..(3*ksize)];
        let block4 = &bytes[(3*ksize)..(4*ksize)];

        let mut distance = hamming_distance(block1, block2).unwrap();
        distance += hamming_distance(block1, block3).unwrap();
        distance += hamming_distance(block1, block4).unwrap();
        distance += hamming_distance(block2, block3).unwrap();
        distance += hamming_distance(block2, block4).unwrap();
        distance += hamming_distance(block3, block4).unwrap();

        let normalized = distance as f64 / ksize as f64;
        if best_distance > normalized {
            best_distance = normalized;
            best_ksize = ksize;
        }
    }

    let mut key: Vec<u8> = Vec::with_capacity(best_ksize);
    for i in 0..best_ksize {
        let mut transpose = Vec::with_capacity(bytes.len()/best_ksize);
        for b in bytes[i..].iter().step_by(best_ksize) {
            transpose.push(*b);
        }

        let mut best_xor: u8 = 0;
        let mut best_score = f64::NEG_INFINITY;
        for x in 0..255 {
            let xored = xor_char(&transpose, x);
            let score = english_score(&xored);
            if best_score < score {
                best_score = score;
                best_xor = x;
            }
        }

        key.push(best_xor);
    }

    let decrypted = xor_string(&bytes, &key);

    println!("Best KSIZE: {}", best_ksize);
    println!("Key: {}", String::from_utf8_lossy(&key));
    println!();
    println!("Message:\n{}", String::from_utf8_lossy(&decrypted));
}