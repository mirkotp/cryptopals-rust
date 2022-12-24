use cryptopals::{english_score, ToBytes, xor_char};
use std::io::{BufReader, BufRead};
use std::fs::File;

fn main() {
    let file = File::open("./res/s01e04").unwrap();
    let reader = BufReader::new(file);

    let mut highest_scoring_ciphertext = "".to_string();
    let mut highest_scoring = "".to_string();
    let mut highest_score = f64::NEG_INFINITY;

    for line in reader.lines() {
        let l = line.unwrap();
        let bytes = &l.parse_hex().unwrap();
    
        for c in 0..0xFF {
            let xor_string = xor_char(&bytes, c);
            let score = english_score(&xor_string);
    
            if score > highest_score {
                highest_scoring_ciphertext = l.to_owned();
                highest_score = score;
                highest_scoring = xor_string;   
            }
        }
    }

    println!("(Score: {:.2}): {}", highest_score, highest_scoring_ciphertext);
    println!("{:?}", highest_scoring);
}
