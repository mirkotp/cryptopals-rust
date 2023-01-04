use cryptopals::crypto::random_bytes;
use json::{object, JsonValue};
use openssl::symm::{decrypt, encrypt, Cipher};

fn main() {
    assert_eq!(
        kv_to_json("foo=bar&baz=qux&zap=zazzle"),
        json::parse(r#"{"foo":"bar", "baz":"qux", "zap":"zazzle"}"#).unwrap()
    );

    assert_eq!(
        kv_to_json(&profile_for("foo@bar.com")),
        json::parse(r#"{"email":"foo@bar.com", "uid":"10", "role":"user"}"#).unwrap()
    );

    assert_eq!(
        kv_to_json(&profile_for("foo@bar.com&role=admin")),
        json::parse(r#"{"email":"foo@bar.comroleadmin", "uid":"10", "role":"user"}"#).unwrap()
    );

    // TODO Using only the user input to profile_for() (as an oracle
    // to generate "valid" ciphertexts) and the ciphertexts themselves,
    // make a role=admin profile.
    let key = random_bytes(16);
    let enc = profile_encrypt(&key, "foo@bar.com");
    let dec = profile_decrypt(&key, &enc);
    println!("{}", dec);
}

fn kv_to_json(input: &str) -> JsonValue {
    let mut out = object! {};
    input.split('&').into_iter().for_each(|kv| {
        let (k, v) = kv.split_once('=').unwrap();
        out.insert(k, v).unwrap();
    });
    out
}

fn profile_for(email: &str) -> String {
    let email = email.to_string().replace("&", "").replace("=", "");

    "email=".to_string() + &email + "&uid=10&role=user"
}

fn profile_encrypt(key: &[u8], email: &str) -> Vec<u8> {
    let plain = profile_for(email);
    encrypt(Cipher::aes_128_ecb(), key, None, &plain.as_bytes()).unwrap()
}

fn profile_decrypt(key: &[u8], cipher: &[u8]) -> JsonValue {
    let plain = decrypt(Cipher::aes_128_ecb(), key, None, cipher).unwrap();
    kv_to_json(&String::from_utf8_lossy(&plain))
}
