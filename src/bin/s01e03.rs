use cryptopals::{single_byte_xor, parse_hex, score};

fn main() {
    let bytes = parse_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();

    let mut highest_scoring = "".to_string();
    let mut highest_score = 0.0;

    for c in 'A'..'z' {
        let xor_string = single_byte_xor(&bytes, c as u8);
        let score = score(&xor_string);

        if score > highest_score {
            highest_score = score;
            highest_scoring = xor_string;   
        }
    }

    println!("(Score: {}): {}", highest_score, highest_scoring);
}