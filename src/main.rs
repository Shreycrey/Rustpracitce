use aes::Aes128;
use aes::cipher::{BlockEncrypt, BlockDecrypt, generic_array::{GenericArray, typenum::U16}};
use aes::NewBlockCipher;
use std::str;

// Encrypt 16 byte block
fn encrypt(key: &GenericArray<u8, U16>, plaintext: &str) -> GenericArray<u8, U16> {
    
    // Convert plaintext to 16 byte block
    let mut block: GenericArray<u8, U16> = {
        let mut bytes = [0u8; 16];
        let text_bytes = plaintext.as_bytes();
        let len = text_bytes.len().min(16);
        bytes[..len].copy_from_slice(&text_bytes[..len]);
        GenericArray::from(bytes)
    };

    let cipher = Aes128::new(&key);

    // Cipher encryption
    cipher.encrypt_block(&mut block);

    block
}

// Decrypt 16 byte block
fn decrypt(key: &GenericArray<u8, U16>, encrypted_block: &GenericArray<u8, U16>) -> String {
    let mut block = encrypted_block.clone(); // Clone encrypted block to avoid mutating input

    let cipher = Aes128::new(&key);

    // Cipher decryption
    cipher.decrypt_block(&mut block);

    // Convert decrypted block back to plaintext
    str::from_utf8(&block).expect("Decryption failed to produce valid UTF-8").to_string()
}

fn main() {
    // Define key (16 bytes for AES-128)
    let key = GenericArray::from([2u8; 16]);

    // Define plaintext (maximum 16 bytes)
    let plaintext = "This is my main!";

    // Encrypt plaintext
    let encrypted_block = encrypt(&key, plaintext);
    println!("Encrypted block: {:?}", encrypted_block);

    // Decrypt ciphertext
    let decrypted_text = decrypt(&key, &encrypted_block);
    println!("Decrypted plaintext: {}", decrypted_text);
}

//test cases
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test1() {
        let key = GenericArray::from([2u8; 16]);
        let plaintext = "This is my test!";
        let encrypted_block = encrypt(&key, plaintext);
        let decrypted_text = decrypt(&key, &encrypted_block);
        assert_eq!(decrypted_text, plaintext);
    }

    #[test]
    fn test2() {
        let key = GenericArray::from([2u8; 16]);
        let plaintext = "Longer than sixteen bytes.";
        let encrypted_block = encrypt(&key, plaintext);
        let decrypted_text = decrypt(&key, &encrypted_block);
        assert_eq!(decrypted_text, plaintext);
    }

    #[test]
    fn test3() {
        let key = GenericArray::from([2u8; 16]);
        let plaintext = "Two word";
        let encrypted_block = encrypt(&key, plaintext);
        let decrypted_text = decrypt(&key, &encrypted_block);
        assert_eq!(decrypted_text, plaintext);
    }
}