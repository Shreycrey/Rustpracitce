This code in main.rs contains two functions, encrypt and decrypt, which work with a 16 byte plaintext string by converting it to a generic array and then encrytping/decrypting it. 

It also has three test cases to explore the testing capability of rust.

To execute, cd into the src folder and execute cargo build. After this, you either do cargo run to execute main or cargo test to execute test cases.

Expected results:
test case 1 passes.
test case 2 passes as the string is longer than 16 bytes, and PKCS7 padding is used to make it a valid length
test case 2 passes as the string is shorter than 16 bytes, and PKCS7 padding is used to make it a valid length

The implementation is padding and block alignment, bit padding is not viable enough to be used yet, but research is being done to find the best way to use it for storage efficiency.
