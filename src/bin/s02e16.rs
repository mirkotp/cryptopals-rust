use cryptopals::crypto::aes_cbc_encrypt;

fn main() {
    // TODO
    // Modify the ciphertext (without knowledge of the AES key) to accomplish this.
    // You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
    //
    //     Completely scrambles the block the error occurs in
    //     Produces the identical 1-bit error(/edit) in the next ciphertext block.
    //
    // Stop and think for a second.
    //
    // Before you implement this attack, answer this question: why does CBC mode have this property?
}

// Random key
const KEY: [u8; 16] = [
    222, 169, 210, 64, 54, 245, 202, 169, 10, 22, 227, 110, 176, 43, 11, 165,
];

const IV: [u8; 16] = [0; 16];

fn encryption_oracle(input: &str) -> Vec<u8> {
    let salted = "comment1=cooking%20MCs;userdata=".to_string() 
    + &input.to_string().replace(";", "").replace("=", "")
    + ";comment2=%20like%20a%20pound%20of%20bacon";

    aes_cbc_encrypt(salted.as_bytes(), &KEY, &IV)
}

fn is_admin(bytes: &[u8]) -> bool {
    let plain_bytes = aes_cbc_encrypt(bytes, &KEY, &IV);
    let plain = String::from_utf8_lossy(&plain_bytes);
    
    plain.contains(";admin=true;")
}