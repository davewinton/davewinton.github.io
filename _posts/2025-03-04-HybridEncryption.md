---
layout: post
title: Hybrid Encryption with Python
author: Dave Winton
category: cybersecurity 
feature-img: "assets/img/pexels/computer.jpeg"
tags: [cybersecurity, encryption]
excerpt_separator: <!--more-->
---

A common topic for entry level Cyber Security roles or interview questions is about the difference between asymmetric and symmetric encryption. I thought it would be fun to take a look at a hybrid cryptography system which uses both!
<!--more-->

Before we get started let's take a very high-level overview of what asymmetric and symmetric cryptography is, strengths and weaknesses, and what they are commonly used for.

## Symmetric Encryption

Symmetric encryption uses a single key for both encryption and decryption. Since the same key is shared between the sender and receiver, it requires a secure method for key distribution. This type of encryption is generally faster and more efficient, making it suitable for encrypting large amounts of data. However, its main drawback is securing the key exchange, if the key is intercepted, the encrypted data can be easily decrypted.

Symmetric encryption is commonly used in scenarios like file encryption, disk encryption, database encryption, and securing communication channels such as VPNs. Widely used algorithms include AES (Advanced Encryption Standard) and DES/3DES (Data Encryption Standard).

- **Encryption:**
    
    $$C=E(K,P)$$
    
    Where:
    
    - $$C$$ = Ciphertext (encrypted data)
    - $$E$$ = Encryption function
    - $$K$$ = Secret key
    - $$P$$ = Plaintext (original data)

- **Decryption:**
    
    $$P=D(K,C)$$
    
    Where:
    
    - $$D$$ = Decryption function
    - $$K$$ = Same secret key used for encryption
    - $$C$$ = Ciphertext
  
## Asymmetric Encryption

Asymmetric encryption, also known as public-key encryption, uses a pair of keys: a public key for encryption and a private key for decryption. This method eliminates the need for a shared secret key, making it more secure than symmetric encryption. However, it is computationally slower due to the complexity of the mathematical operations involved.

Asymmetric encryption is primarily used for secure communication, authentication, and digital signatures. It plays a crucial role in secure web browsing (SSL/TLS), email encryption (PGP), and cryptocurrency transactions. Common algorithms include RSA (Rivest-Shamir-Adleman), ECC (Elliptic Curve Cryptography), and Diffie-Hellman key exchange.

- **Encryption:**
    
    $$C=E(K_{pub},P)$$
    
    Where:
    
    - $$C$$ = Ciphertext
    - $$E$$ = Encryption function
    - $$K_{pub}$$​ = Public key
    - $$P$$ = Plaintext

- **Decryption:**
    
    $$P=D(K_{priv},C)$$
    
    Where:
    
    - $$D$$ = Decryption function
    - $$K_{priv}$$​ = Private key
    - $$C$$ = Ciphertext

For **RSA encryption**, a more specific formula is used:

- **Encryption:** $$C=P^e$$  $$mod  n$$
- **Decryption:** $$P=C^d$$  $$mod  n$$

Where $$e$$ and $$d$$ are the public and private exponents, and $$n$$ is the modulus derived from two prime numbers.

## Hybrid Encryption
Now that we understand symmetric and asymmetric encryption, let's explore hybrid encryption, which combines the strengths of both methods.

### Why Hybrid Encryption?

Asymmetric ciphers like RSA and ECC allow us to encrypt data using only the recipient’s public key, removing the need for a pre-shared secret key. However, these algorithms are computationally expensive and inefficient for encrypting large amounts of data.

On the other hand, symmetric encryption is highly efficient for encrypting large datasets but requires all parties to agree on a shared secret key, which is inconvenient in many cases or risks compromising the security of the cipher during the key exchange process.

To get the best of both worlds, we can use **hybrid encryption** 

In this section I will write a hybrid encryption/decryption tool in Python, which works as follows:

**Encryption:**
1. The `plaintext` and recipient’s `pub_key` are provided as input.
2. A secure random 256-bit `aes_key` is generated for AES encryption.
3. The plaintext is encrypted using **AES-256-EAX**, an authenticated encryption mode, generating `ctext`.
4. The `aes_key` is encrypted using the recipient’s `pub_key`, producing `enc_aes_key`.
5. _(Optional)_ The `enc_aes_key` is signed with the sender’s `pvt_key` to ensure its integrity, generating `sig`.

Where `ctext = nonce + ctag + encrypted_msg`

The final `ciphertext` will contain:

`enc_aes_key + sig (if signed) + ctext`

| Chunk           | Description                                               | Size (in bytes)     |
| --------------- | --------------------------------------------------------- | ------------------- |
| `enc_aes_key`   | The `aes_key` encrypted with the recipients `pub_key`     | `sizeof(pub_key)/8` |
| `sig`           | Signed `enc_aes_key` generated with the senders `pvt_key` | `sizeof(pvt_key)/8` |
| `nonce`         | The IV/nonce used for `AES256-EAX`                        | 16                  |
| `ctag`          | Authentication tag verifying `ctext` integrity            | 16                  |
| `encrypted_msg` | The encrypted `plaintext`                                 | Remaining Bytes     |

**Decryption:**
1. Extract `enc_aes_key`, `sig` (if present), and `ctext` from the final `ciphertext`.
2. If `sig` is present, verify it using the sender’s `pub_key`.
3. Decrypt `enc_aes_key` with the recipient’s `pvt_key` to recover `aes_key`.
4. Extract `nonce`, `ctag`, and `encrypted_msg` from `ctext`.
5. Decrypt `encrypted_msg` and verify `ctag` for integrity.
6. Output the recovered `plaintext`.

## Building the system

First, let's define the encryption and decryption functions for both RSA and AES-EAX.

```python
def rsa_encrypt(plaintext, pub_key) -> bytes:  
    """RSA Encryption using PKCS1_0AEP"""  
    cipher = PKCS1_OAEP.new(pub_key)  
    return cipher.encrypt(plaintext)  
  
  
def rsa_decrypt(ciphertext, pvt_key) -> bytes:  
    """RSA Decryption using PKCS1_0AEP"""  
    cipher = PKCS1_OAEP.new(pvt_key)  
    return cipher.decrypt(ciphertext)


def aes_eax_encrypt(plaintext, key) -> bytes:  
    """Authenticated encryption with AES-256-EAX"""  
    cipher = AES.new(key, AES.MODE_EAX, mac_len=16)  
    nonce = cipher.nonce  
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)  
    return nonce + tag + ciphertext  
  
  
def aes_eax_decrypt(ciphertext, key) -> (bytes,bool):  
    """Authenticated decryption with AES-256-EAX"""  
    nonce, tag, ciphertext = ciphertext[:16], ciphertext[16:32], ciphertext[32:]  
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)  
    plaintext = cipher.decrypt(ciphertext)  
    try:  
        cipher.verify(tag)  
        return plaintext, True  
    except ValueError:  
        return b'', False
```

We also need the ability to sign and verify using RSA..

```python
def rsa_sign(message: bytes, pvt_key: RSA.RsaKey) -> bytes:
    """Sign a message with an RsaKey private key"""
    h = SHA256.new(message)
    return pss.new(pvt_key).sign(h)


def rsa_verify(message: bytes, pub_key: RSA.RsaKey, sig: bytes) -> bool:
    """Verify a message with an RsaKey public key"""
    h = SHA256.new(message)
    msg_verifier = pss.new(pub_key)
    try:
        msg_verifier.verify(h, sig)
        print("[+] Cryptographic signature verified!")
        return True
    except ValueError:
        return False
```

We also need a way to load public and private RSA keys...

```python
def get_pvt_key(key_path):
    """Returns an RSA.RsaKey object containing the Private Key"""
    with open(key_path, "rb") as f:
        data = f.read()

    for _ in range(3):
        try:
            passwd = getpass("Enter private key passphrase: ")
            return RSA.import_key(data, passphrase=passwd)
        except (ValueError, TypeError):
            print("[!] Incorrect passphrase. Try again.")

    print("[!] Too many incorrect attempts. Exiting.")
    exit(1)


def get_pub_key(key_path) -> RSA.RsaKey | None:
    """Returns a RSA.RsaKey object containing the Public Key"""
    if path.exists(key_path):
        with open(key_path, "rb") as f:
            return RSA.import_key(f.read())
    return None
```

Next, let's implement the logic for hybrid encryption:

```python
def hybrid_encrypt(plaintext: bytes,  
                   pub_key: RSA.RsaKey,  
                   signing_key: RSA.RsaKey = None) -> str:  
    """Hybrid encryption using RSA and AES-EAX"""  
    
    # Derive aes_key from CSRNG source
    aes_key = urandom(32)  

	# Encrypt the plaintext with the aes_key
    ciphertext = aes_eax_encrypt(plaintext, aes_key) 

	# Encrypt the aes_key
    enc_aes_key = rsa_encrypt(aes_key, pub_key)   
  
    # Sign the encrypted key if a signing key is provided  
    sig = b""  
    if signing_key:  
        sig = rsa_sign(enc_aes_key, signing_key)  
        header = b'\x01'  # Signed message  
    else:  
        header = b'\x00'  # Unsigned message  
  
    print("[+] Encryption complete! Outputting ciphertext..")  
  
    try:  
        # Combine header, encrypted key, signature (if any), and ciphertext  
        return base64.b64encode(header + enc_aes_key + sig + ciphertext).decode()  
    except ValueError as e:  
        print(e)  
        quit(1)
```

You'll notice that a **header** is included in the base64-encoded output. This header is either `0x00` (unsigned) or `0x01` (signed), allowing the decryption function to determine if the `enc_aes_key` includes a signature.

Now, let's implement the **hybrid decryption** function:

```python
def hybrid_decrypt(ciphertext, pvt_key, pub_key=None) -> bytes | None:  
    """Hybrid decryption using RSA and AES-EAX"""  
    
    sig_size = 0                              # Since we don't know if sig exists, set to 0
    enc_key_size = pvt_key.size_in_bytes()    # Set the enc_key_size 
    ciphertext = base64.b64decode(ciphertext) # Decode the base64 encoded input
  
    # Extract the header and check for signed/unsigned enc_aes_key
    header = ciphertext[0:1]  
    if header == b'\x00':  
        print("[*] No signature, proceeding with decryption...")  
        sig_size = 0  
        ciphertext = ciphertext[1:]  
    elif header == b'\x01':  
        if not pub_key:  
            print("[*] No PUBKEY for verification.. Skipping verification")  
        else:  
            print("[*] Signature present, verifying integrity...")  
        sig_size = pub_key.size_in_bytes()  
        ciphertext = ciphertext[1:]  
    else:  
        raise ValueError("[!] Invalid header, unable to proceed.")  
  
    # Extract enc_aes_key, sig and ciphertext chunks from ciphertext block  
    enc_aes_key, sig, ciphertext = (ciphertext[:enc_key_size],  
                                    ciphertext[enc_key_size:enc_key_size + sig_size],  
                                    ciphertext[enc_key_size + sig_size:])  
  
    # If header indicates signed, verify the signature  
    if header == b'\x01' and pub_key:  
        if not rsa_verify(enc_aes_key, pub_key, sig):  
            raise ValueError("[!] Signature verification failed.")  
  
    # Decrypt the aes_key  
    aes_key = rsa_decrypt(enc_aes_key, pvt_key)  
    if aes_key is None:  
        raise ValueError("[!] RSA decryption of AES key failed.")  
  
    # Decrypt and verify the ciphertext  
    plaintext, verified = aes_eax_decrypt(ciphertext, aes_key)  
    if not verified:  
        print("[!] Decryption failed. Integrity check failed.")  
        exit(1)  
  
    print("[+] Decryption complete! Outputting plaintext..")  
    return plaintext
```

Now, this is just the basic skeleton of the tool, but we now should have a fully working cryptosystem! To finish it off I have created an `argparse` system and a `main()` function to nicely package the script for easy use of its functions..

```python
def main():
    parser = argparse.ArgumentParser(description="Hybrid Encryption CLI")
    parser.add_argument("-sK", "--signing-key", help="Signing key (Senders PVT_KEY)")
    parser.add_argument("-vK", "--verify-key", help="Verification key (Senders PUB_KEY)")
    parser.add_argument('--derive-key', action="store_true", help="Derive a custom key for AES encryption")
    parser.add_argument("-c", "--create-keypair", metavar="KEY_PATH", help="Generate an RSA key pair")
    parser.add_argument("-e", "--encrypt", metavar="PUB_KEY", help="Encrypt input using the specified public key")
    parser.add_argument("-d", "--decrypt", metavar="PVT_KEY", help="Decrypt input using the specified private key")
    parser.add_argument("-i", "--input", metavar="INPUT", help="Specify input text or file path")
    parser.add_argument("-o", "--output", metavar="OUTPUT", help="Specify output file path")
    args = parser.parse_args()

    if args.create_keypair:
        create_keypair(args.create_keypair)

    elif args.encrypt and args.input:
        if args.derive_key:
            derive_custom_key = True
        # Get signing key
        signing_key = None
        if args.signing_key:
            print("[*] Importing private key for signing.. Get ready to enter password")
            signing_key = get_pvt_key(args.signing_key)
            if not signing_key:
                print("[!] Private key not found.")
                exit(1)
        print("[*] Importing recipients public key..")
        pub_key = get_pub_key(args.encrypt)
        if not pub_key:
            print("[!] Public key not found.")
            exit(1)

        print("[+] Keys successfully imported!")

        input_data = args.input if path.exists(args.input) else args.input.encode()
        if path.exists(args.input):
            with open(args.input, "rb") as f:
                input_data = f.read()

        ciphertext = hybrid_encrypt(input_data, pub_key, signing_key)
        if args.output:
            with open(args.output, "w") as f:
                f.write(ciphertext)
        else:
            print(f"\n=== Encrypted Output ===\n{ciphertext}")

    elif args.decrypt and args.input:
        # Get verify-key
        verify_key = None
        if args.verify_key:
            print("[*] Importing public key for verification..")
            verify_key = get_pub_key(args.verify_key)
            if not verify_key:
                print("[!] Verify key not found.")
                exit(1)

        # Get private key
        print("[*] Importing private key for decryption..")
        pvt_key = get_pvt_key(args.decrypt)
        if not pvt_key:
            print("[!] Private key not found.")
            exit(1)

        print("[+] Keys successfully imported!")

        encrypted_data = args.input if path.exists(args.input) else args.input.encode()
        if path.exists(args.input):
            with open(args.input, "r") as f:
                encrypted_data = f.read()

        decrypted = hybrid_decrypt(encrypted_data, pvt_key, verify_key)
        if args.output:
            with open(args.output, "wb") as f:
                f.write(decrypted)
        else:
            print(f"\n=== Decrypted Output ===\n{decrypted.decode()}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

```

Here is a example usage and output:

```shell
# Encrypt an input string with the recipients PUBKEY (encryptionkey.pub) and sign with the senders PVTKEY (signingkey), write output to file (message.enc)
➜  python3 hykrypt.py \
> -e encryptionkey.pub \
> -i "This is a super secret message" \
> -o message.enc \
> -sK signingkey

[*] Importing private key for signing.. Get ready to enter password
Enter private key passphrase:
[*] Importing recipients public key..
[+] Keys successfully imported!
[+] Encryption complete!
[+] Ciphertext written to: /path/to/message.enc

# Check the contents of message.enc
➜  cat message.enc
ATP5nfWnAo6C4cZIREAeUj5QfdWcnYHvaVlOtxRwBR+g25Vll9QnWsHE1PgCoz/dpg0BrZAubNGPQtfYY12ID56WTimZBH1bmQMvT18KrLOB9hMXx8p+XOE+lK9d7Q8EuxaAg+R8xOXX4yazT5UofuJA9ZuUUt740QV11eP34YXe2UwTflDrFsUvYQrejSUop6gVMPl3rbJCVUxKJdHjGFu+7Ha+PvWq/9I/3KdgHISfm0P/wAHUhHp7qDU8RHoAY9fPc3MBsIPcoqSbQTlxVpr+0E9YDIWQPHOSG274qUiSe2HEvdKwf337sZWSolPhW4BCltXEWOe8Q0b2QgC1shsF5JzMpkMolnoxCCx435PNwjKrYXC1W3qjS2+sxXdNu+xjKxO5NdN/Zv1wYrWleATz+Mbn190PJYpIkXz/9LwKADwHgVIkOwQSpW4mR/6Lzw55ypDlF1KXns43zRRCiPyeiva/YB1sCXtcIOJ867C1W01iqNkpTASftOktQdem8IzhBT+iQHpW3OQ/x3ND5LzSdd6qWn6899ETc6ZlQMjToqL3xIWRqxv8lEGiCDU3BXkWBLnHwijJ4cKF+XL5Bdni2O2cSpid3xT2pBYgMrSVw2yw+DouR2gD44u85vESYSXvicVeLxZ5ZlpAoeiaZigJmd0gr9FbwXv1g0F+MpWTTf8tLTHR3S7pc/cj9hm6YqINheQziBPhSK4rBn2J6SDgO6F85MMirpA2QS3C8s2is7+ewoXtipiNKG3uNREOZKLJb0nH21tP9ITiTofJKvm3QrzthOm4yzhnEgqbF06dli6oFQjL8h53ZlE78f7d6eNC7bDDghPTqX7xIMNGN88Zj5OZRPW0OYiW9aUwH15kacrHSEQiU9N0XyzPlEfjsjyRy1uECysXDGm39wrj7nhLX81n3OwW5VHbj8BSzy+HshxvIm589tKL6uFaF+Fo+k1L9+nx8LZN20nYGXLUDkyjg/zOHVwLMz/vfnW1fEkQ4lB/16ZYKYfKfWrkTX7Ck4yI/jblbBV1HcK+ztF1KNVA9+8nbIBAU8uID2sqbqYQG/kGO5FHe+ji1HcUE7n/clPk1uIOnLxKELe1Y+x6CwgYR64AcCU66IUwkxKGsPeBHAbQ2ftAZ/0+poNAdcY3aOGh3J/Q488zNdeBleORVaXcwHgHWmZ2b6ueHirMT/vi5R6AWKBSWrVHvTJyOzaromrAKJrICgf/3SCYjG5gFf+aKy6aA03FOYBtEZcQEkzld75SfQOXq5W3Oe5KK5o=

# Decrypt message.enc with the recipients PVTKEY (encryptionkey) and verify with the 
➜  python3 hykrypt.py \
> -d encryptionkey \
> -i message.enc \
> -vK signingkey.pub

[*] Importing public key for verification..
[*] Importing private key for decryption..
Enter private key passphrase:
[+] Keys successfully imported!
[*] Signature present, verifying integrity...
[+] Cryptographic signature verified!
[*] Checking the integrity of ciphertext..
[+] Successfully verified ciphertext!
[+] Decryption complete! Outputting plaintext..

=== Decrypted Output ===
This is a super secret message

```

To see the full script you can visit [HyKrypt](https://github.com/davewinton/hykrypt) on my GitHub page.

## Conclusion
Understanding the strengths and weaknesses of symmetric and asymmetric encryption is crucial for designing secure systems. Symmetric encryption offers speed and efficiency but requires a secure key exchange mechanism. Asymmetric encryption solves the key distribution problem but is computationally expensive for large data encryption. By combining both, hybrid encryption provides the best of both worlds, leveraging asymmetric encryption for key exchange and symmetric encryption for bulk data encryption.

This hybrid approach is widely used in real-world applications such as HTTPS, email encryption, and secure messaging apps. Whether you're implementing secure communications or designing encryption-based applications, knowing how to apply these techniques effectively is essential for ensuring data security and integrity.

Hopefully if you read this far, you found this example interesting and learned a thing or two about both asymmetric and symmetric encryption!

## Disclaimer
This post is for educational purposes only and should not be used as a substitute for professional security guidance. While the concepts and implementations discussed are grounded in well-established cryptographic principles, security is a constantly evolving field, and vulnerabilities may exist in specific implementations. Always consult cryptography experts and follow best practices when developing secure systems. Use encryption responsibly and ensure compliance with local regulations.

It should also be noted that RSA is **not** a quantum-resistant cipher and will likely be phased out in the coming decades in favor of newer asymmetric cryptographic algorithms. Lattice-based cryptographic schemes such as **Kyber** and **Dilithium**, both endorsed by NIST for post-quantum public-key cryptography, are among the likely successors.

The primary threat to RSA and other classical public-key systems is **Shor’s Algorithm**, which—when implemented on sufficiently powerful quantum computers—will render RSA, ECC, and similar cryptosystems obsolete, likely within the next 10–20 years. While higher-bit RSA keys (e.g., 3072, 4096, or greater) are currently considered secure against classical attacks, their long-term viability is uncertain.

Thus, while this cryptosystem was both a fun and educational exercise in learning about symmetric and asymmetric encryption, it should **not** be used for serious cryptographic needs or in production systems.
