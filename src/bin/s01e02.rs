use cryptopals::{parse_hex, fixed_xor};

fn main() {
    let bytes = parse_hex("1c0111001f010100061a024b53535009181c").unwrap();
    let key = parse_hex("686974207468652062756c6c277320657965").unwrap();
    let result = fixed_xor(&bytes, &key).unwrap();

    let expected = parse_hex("746865206b696420646f6e277420706c6179").unwrap();
    
    assert_eq!(result, expected);
    println!("{:x?}", result);  // TODO bytes to hex string
    println!("OK!");
}