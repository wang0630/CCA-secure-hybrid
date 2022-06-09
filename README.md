## CCA-hybrid encryption using RSA and SHA-256
Follow the explanation from Section 11.5.5: A CCA-Secure KEM in the random oracle model from Introduction to modern cipher.

### Process of sender
1. Get N, e generated by recipient using RSA.
2. Choose r belongs to Z_N, and compute (`r^e mod N`) as our public key encryption ciphertext.
3. Compute symmetric key `k = H(r)`, where H is assumed to be a random oracle model(use SHA-256 here).
4. Use key k to encrypt the actual message using AES-OFB-256. The key here is a digest from SHA-256, and its length matches the key size requirement of AES-256.
5. Send ciphertext = `r^e mod N` and the actual ciphertext(the message) to the recipient.


### Process of recipient
1. Use RSA to compute N, e, d. d is kept secret.
2. Compute r using its private key. `r = c^d mod N`.
3. Get symmetric key `k = H(r)`.
4. Decrypt the actual message using the key k.