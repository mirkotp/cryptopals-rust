mod tools;
use std::io::{BufReader, BufRead};
use std::fs::File;

fn main() {
    let file = File::open("./res/s01e06").unwrap();
    let reader = BufReader::new(file);

    let mut bytes = Vec::with_capacity(64*60/4*3);  // We know the size of
                                                    // the input file.
    for line in reader.lines() {
        let mut line_bytes = tools::base64_to_bytes(&line.unwrap()).unwrap();
        bytes.append(&mut line_bytes);
    }

    
}

fn s01e06() {
    let file = File::open("./res/s01e06").unwrap();
    let reader = BufReader::new(file);

    let mut bytes = Vec::with_capacity(64*60/4*3);  // We know the size of
                                                    // the input file.
    for line in reader.lines() {
        let mut line_bytes = tools::base64_to_bytes(&line.unwrap()).unwrap();
        bytes.append(&mut line_bytes);
    }

    let mut best_distance = f64::INFINITY;
    let mut best_ksize = 0;
    for ksize in 2..=40 {
        let block1 = &bytes[0..ksize];
        let block2 = &bytes[ksize..(2*ksize)];
        let block3 = &bytes[(2*ksize)..(3*ksize)];
        let block4 = &bytes[(3*ksize)..(4*ksize)];

        let mut distance = tools::hamming_distance(block1, block2).unwrap();
        distance += tools::hamming_distance(block1, block3).unwrap();
        distance += tools::hamming_distance(block1, block4).unwrap();
        distance += tools::hamming_distance(block2, block3).unwrap();
        distance += tools::hamming_distance(block2, block4).unwrap();
        distance += tools::hamming_distance(block3, block4).unwrap();

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
            let xored = tools::single_byte_xor(&transpose, x);
            let score = tools::score(&xored);
            if best_score < score {
                best_score = score;
                best_xor = x;
            }
        }

        key.push(best_xor);
    }

    let decrypted = tools::xor(&bytes, &key);

    println!("Best KSIZE: {}", best_ksize);
    println!("Key: {}", String::from_utf8_lossy(&key));
    println!();
    println!("Message:\n{}", String::from_utf8_lossy(&decrypted));
}

fn s01e05() {
    let s = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let xor = tools::xor(&s.to_vec(), &b"ICE".to_vec());
    println!("{:x?}", xor);
}

fn s01e04() {
    let file = File::open("./res/s01e04").unwrap();
    let reader = BufReader::new(file);

    let mut highest_scoring_ciphertext = "".to_string();
    let mut highest_scoring = "".to_string();
    let mut highest_score = f64::NEG_INFINITY;

    for line in reader.lines() {
        let l = line.unwrap();
        let bytes = tools::parse_hex(&l).unwrap();
    
        for c in 0..0xFF {
            let xor_string = tools::single_byte_xor(&bytes, c);
            let score = tools::score(&xor_string);
    
            if score > highest_score {
                highest_scoring_ciphertext = l.to_owned();
                highest_score = score;
                highest_scoring = xor_string;   
            }
        }
    }

    println!("(Score: {:.2}): {:?}", highest_score, highest_scoring);
    println!("{}", highest_scoring_ciphertext);
}

fn s01e03() {
    let bytes = tools::parse_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();

    let mut highest_scoring = "".to_string();
    let mut highest_score = 0.0;

    for c in 'A'..'z' {
        let xor_string = tools::single_byte_xor(&bytes, c as u8);
        let score = tools::score(&xor_string);

        if score > highest_score {
            highest_score = score;
            highest_scoring = xor_string;   
        }
    }

    println!("(Score: {}): {}", highest_score, highest_scoring);
}