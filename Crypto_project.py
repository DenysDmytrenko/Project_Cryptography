from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, dsa, ec
import os
import time

#---------------------------------------------------------
#-------------------Keypair Generation--------------------
#---------------------------------------------------------
RSA_key_gen_times = []

for _ in range(100):
    RSA_keypair_gen_start = time.perf_counter()
    RSA_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024
    )

    RSA_public_key = RSA_private_key.public_key()
    RSA_keypair_gen_end = time.perf_counter()
    RSA_key_gen_times.append(RSA_keypair_gen_end - RSA_keypair_gen_start)

RSA_avg_key_gen_time = sum(RSA_key_gen_times) / len(RSA_key_gen_times)

DSA_key_gen_times = []

for _ in range(100):
    DSA_keypair_gen_start = time.perf_counter()
    DSA_private_key = dsa.generate_private_key(
        key_size=1024
    )

    DSA_public_key = DSA_private_key.public_key()
    DSA_keypair_gen_end = time.perf_counter()
    DSA_key_gen_times.append(DSA_keypair_gen_end - DSA_keypair_gen_start)
    
DSA_avg_key_gen_time = sum(DSA_key_gen_times) / len(DSA_key_gen_times)

ECC_key_gen_times = []

for _ in range(100):
    ECC_keypair_gen_start = time.perf_counter()
    ECC_private_key = ec.generate_private_key(
        ec.SECP192R1()
    )

    ECC_public_key = ECC_private_key.public_key()
    ECC_keypair_gen_end = time.perf_counter()
    ECC_key_gen_times.append(ECC_keypair_gen_end - ECC_keypair_gen_start)
    
ECC_avg_key_gen_time = sum(ECC_key_gen_times) / len(ECC_key_gen_times)

#---------------------------------------------------------
#-----------------RSA Encryption/Decription---------------
#---------------------------------------------------------

def split_message(message, chunk_size):
    return [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]

def encrypt_message(RSA_private_key, message, chunk_size):
    encrypted_chunks = []
    for chunk in split_message(message, chunk_size):
        encrypted_chunks.append(RSA_private_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ))
    return encrypted_chunks

def decrypt_message(RSA_private_key, encrypted_chunks):
    decrypted_chunks = []
    for chunk in encrypted_chunks:
        decrypted_chunks.append(RSA_private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ))
    return b"".join(decrypted_chunks)

long_plaintext = os.urandom(10 * 1024)

RSA_encrypt_times = []
for _ in range(100):
    RSA_encrypt_start = time.perf_counter()
    long_ciphertext = encrypt_message(RSA_public_key, long_plaintext, 32)
    RSA_encrypt_end = time.perf_counter()
    RSA_encrypt_times.append(RSA_encrypt_end - RSA_encrypt_start)

RSA_avg_encrypt_time = sum(RSA_encrypt_times) / len(RSA_encrypt_times)

RSA_decrypt_times = []
for _ in range(100):
    RSA_decrypt_start = time.perf_counter()
    long_plaintext_2 = decrypt_message(RSA_private_key, long_ciphertext)
    RSA_decrypt_end = time.perf_counter()
    RSA_decrypt_times.append(RSA_decrypt_end - RSA_decrypt_start)

RSA_avg_decrypt_time = sum(RSA_decrypt_times) / len(RSA_decrypt_times)

#---------------------------------------------------------
#---------------------Digital Signing---------------------
#---------------------------------------------------------

message = os.urandom(1000000)

RSA_signing_times = []
for _ in range(100):
    RSA_signing_start = time.perf_counter()
    RSA_signature = RSA_private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    RSA_signing_end = time.perf_counter()
    RSA_signing_times.append(RSA_signing_end - RSA_signing_start)

RSA_avg_signing_time = sum(RSA_signing_times) / len(RSA_signing_times)

DSA_signing_times = []

for _ in range(100):
    DSA_signing_start = time.perf_counter()
    DSA_signature = DSA_private_key.sign(
        message,
        hashes.SHA256()
    )
    DSA_signing_end = time.perf_counter()
    DSA_signing_times.append(DSA_signing_end - DSA_signing_start)

DSA_avg_signing_time = sum(DSA_signing_times) / len(DSA_signing_times)

ECC_signing_times = []

for _ in range(100):
    ECC_signing_start = time.perf_counter()
    ECC_signature = ECC_private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    ECC_signing_end = time.perf_counter()
    ECC_signing_times.append(ECC_signing_end - ECC_signing_start)
    
ECC_avg_signing_time = sum(ECC_signing_times) / len(ECC_signing_times)

#---------------------------------------------------------
#----------------------Verify Signing---------------------
#---------------------------------------------------------

RSA_verify_times = []

for _ in range(100):
    RSA_verify_start = time.perf_counter()
    RSA_public_key.verify(
        RSA_signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    RSA_verify_end = time.perf_counter()
    RSA_verify_times.append(RSA_verify_end - RSA_verify_start)
    
RSA_avg_verify_time = sum(RSA_verify_times) / len(RSA_verify_times)

DSA_verify_times = []

for _ in range(100):
    DSA_verify_start = time.perf_counter()
    DSA_public_key.verify(
        DSA_signature,
        message,
        hashes.SHA256()
    )
    DSA_verify_end = time.perf_counter()
    DSA_verify_times.append(DSA_verify_end - DSA_verify_start)

DSA_avg_verify_time = sum(DSA_verify_times) / len(DSA_verify_times)

ECC_verify_times = []

for _ in range(100):
    ECC_verify_start = time.perf_counter()
    ECC_public_key.verify(
        ECC_signature,
        message,
        ec.ECDSA(hashes.SHA256())
    )
    ECC_verify_end = time.perf_counter()
    ECC_verify_times.append(ECC_verify_end - ECC_verify_start)
    
ECC_avg_verify_time = sum(ECC_verify_times) / len(ECC_verify_times)

#---------------------------------------------------------
#------------------------Prints---------------------------
#---------------------------------------------------------

print(f"\n\t\tKeypairing Generation Results")
print(f"\nRSA Keypair Generation (100 iterations): {RSA_avg_key_gen_time:.4f} seconds")
print(f"DSA Keypair Generation (100 iterations): {DSA_avg_key_gen_time:.4f} seconds")
print(f"ECC Keypair Generation (100 iterations): {ECC_avg_key_gen_time:.4f} seconds")
print(f"\n\t\tRSA Encryption/Decription Results")
print(f"\nRSA Encryption (100 iterations): {RSA_avg_encrypt_time:.4f} seconds")
print(f"RSA Decryption (100 iterations): {RSA_avg_decrypt_time:.4f} seconds")
print(f"\n\t\tDigital Signing Results")
print(f"\nRSA Digital Signing (100 iterations): {RSA_avg_signing_time:.4f} seconds")
print(f"DSA Digital Signing (100 iterations): {DSA_avg_signing_time:.4f} seconds")
print(f"ECC Digital Signing (100 iterations): {ECC_avg_signing_time:.4f} seconds")
print(f"\n\t\tSignature Verification Results")
print(f"\nRSA Signature Verification (100 iterations): {RSA_avg_verify_time:.4f} seconds")
print(f"DSA Signature Verification (100 iterations): {DSA_avg_verify_time:.4f} seconds")
print(f"ECC Signature Verification (100 iterations): {ECC_avg_verify_time:.4f} seconds\n ")