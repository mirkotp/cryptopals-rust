use std::io::{BufReader, BufRead};
use std::fs::File;
use openssl::symm::{Cipher};

fn main() {
    let file = File::open("./res/s01e08").unwrap();
    let reader = BufReader::new(file);

    let block_size = Cipher::aes_128_ecb().block_size();

    for (ln, line) in reader.lines().enumerate() {
        let line = line.unwrap();
        let mut max_count = 0;

        for i in (0..line.len()).step_by(block_size) {
            let mut count = 0;

            for j in ((i+block_size)..line.len()).step_by(block_size) {
                if line[i..i+block_size] == line[j..j+block_size] {
                    count += 1;
                }
            }

            max_count = if max_count > count { max_count } else { count };
        }

        if max_count > 0 {
            println!("Ciphertext n. {} has a block repeated {} times", ln+1, max_count+1);
        }
    }
}