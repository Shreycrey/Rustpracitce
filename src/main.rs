use aes::Aes128;
use aes::cipher::{BlockEncrypt, BlockDecrypt, generic_array::{GenericArray, typenum::U16}};
use aes::NewBlockCipher;
use std::str;

// PKCS7 add padding
fn pad_pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(vec![padding_len as u8; padding_len]);
    padded
}

// PKCS7 remove padding
fn unpad_pkcs7(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new(); // Return empty vector for empty input
    }
    
    let padding_len = *data.last().unwrap() as usize;
    
    // Ensure the padding length is valid
    if padding_len == 0 || padding_len > data.len() {
        panic!("Invalid padding length");
    }
    
    data[..data.len() - padding_len].to_vec()
}

// Encrypt with padding
fn encrypt(key: &GenericArray<u8, U16>, plaintext: &str) -> Vec<u8> {
    // Pad the plaintext to 16 bytes
    let padded_plaintext = pad_pkcs7(plaintext.as_bytes(), 16);
    
    let mut encrypted_blocks = Vec::new();
    let cipher = Aes128::new(&key);

    // Process the padded plaintext in 16-byte blocks
    for chunk in padded_plaintext.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        encrypted_blocks.extend_from_slice(&block);
    }

    encrypted_blocks
}

// Decrypt and unpad
fn decrypt(key: &GenericArray<u8, U16>, encrypted_data: &[u8]) -> String {
    let cipher = Aes128::new(&key);
    let mut decrypted_blocks = Vec::new();

    // Process the encrypted data in 16-byte blocks
    for chunk in encrypted_data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        decrypted_blocks.extend_from_slice(&block);
    }

    // Unpad the decrypted data
    let unpadded = unpad_pkcs7(&decrypted_blocks);
    str::from_utf8(&unpadded).expect("Decryption failed to produce valid UTF-8").to_string()
}

fn main() {
    // Define key (16 bytes for AES-128)
    let key = GenericArray::from([2u8; 16]);

    // Define plaintext (maximum 16 bytes)
    let plaintext = "This is my main!";

    // Encrypt plaintext
    let encrypted_data = encrypt(&key, plaintext);
    println!("Encrypted block: {:?}", encrypted_data);

    // Decrypt ciphertext
    let decrypted_text = decrypt(&key, &encrypted_data);
    println!("Decrypted plaintext: {}", decrypted_text);
}

// Test cases
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test1() {
        let key = GenericArray::from([2u8; 16]);
        let plaintext = "This is my test!";
        let encrypted_data = encrypt(&key, plaintext);
        let decrypted_text = decrypt(&key, &encrypted_data);
        assert_eq!(decrypted_text, plaintext);
    }

    #[test]
    fn test2() {
        let key = GenericArray::from([2u8; 16]);
        let plaintext = "Longer than sixt"; // Should fit within one block after padding
        let encrypted_data = encrypt(&key, plaintext);
        let decrypted_text = decrypt(&key, &encrypted_data);
        assert_eq!(decrypted_text, plaintext);
    }

    #[test]
    fn test3() {
        let key = GenericArray::from([2u8; 16]);
        let plaintext = "Two word"; // Should fit within one block after padding
        let encrypted_data = encrypt(&key, plaintext);
        let decrypted_text = decrypt(&key, &encrypted_data);
        assert_eq!(decrypted_text, plaintext);
    }
}
