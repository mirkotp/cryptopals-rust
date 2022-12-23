use cryptopals::{base64_to_bytes, hamming_distance, single_byte_xor, score, xor};
use std::io::{BufReader, BufRead};
use std::fs::File;

fn main() {
    let file = File::open("./res/s01e06").unwrap();
    let reader = BufReader::new(file);

    let mut bytes = Vec::with_capacity(64*60/4*3);  // We know the size of
                                                    // the input file.
    for line in reader.lines() {
        let mut line_bytes = base64_to_bytes(&line.unwrap()).unwrap();
        bytes.append(&mut line_bytes);
    }

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
            let xored = single_byte_xor(&transpose, x);
            let score = score(&xored);
            if best_score < score {
                best_score = score;
                best_xor = x;
            }
        }

        key.push(best_xor);
    }

    let decrypted = xor(&bytes, &key);

    println!("Best KSIZE: {}", best_ksize);
    println!("Key: {}", String::from_utf8_lossy(&key));
    println!();
    println!("Message:\n{}", String::from_utf8_lossy(&decrypted));
}
