import os
import subprocess
import binascii
import filecmp
from pathlib import Path

def generate_random_hex(length=16):
    """Generate random hex string for keys/IVs"""
    return binascii.hexlify(os.urandom(length)).decode('utf-8')

def encrypt_file(input_path, output_path, cipher_type, key, iv=None):
    """Encrypt file using OpenSSL"""
    cmd = [
        'openssl', 'enc',
        '-' + cipher_type,
        '-e',
        '-in', input_path,
        '-out', output_path,
        '-K', key
    ]
    
    if iv:
        cmd.extend(['-iv', iv])
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result

def decrypt_file(input_path, output_path, cipher_type, key, iv=None):
    """Decrypt file using OpenSSL"""
    cmd = [
        'openssl', 'enc',
        '-' + cipher_type,
        '-d',
        '-in', input_path,
        '-out', output_path,
        '-K', key
    ]
    
    if iv:
        cmd.extend(['-iv', iv])
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result

def generate_hmac(file_path, key, algorithm='sha256'):
    """Generate HMAC for file integrity check"""
    cmd = [
        'openssl', 'dgst',
        '-' + algorithm,
        '-hmac', key,
        file_path
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.split('= ')[1].strip()

def check_ecb_pattern_leak(input_path, output_path):
    """Demonstrate ECB pattern leak by encrypting an image"""
    key = generate_random_hex(16)
    encrypt_file(input_path, output_path, 'aes-128-ecb', key)
    return key

def simulate_replay_attack(input_path, output_path1, output_path2, cipher_type='aes-128-cbc'):
    """Demonstrate how reusing IV leads to identical ciphertexts"""
    key = generate_random_hex(16)
    iv = generate_random_hex(16)
    
    result1 = encrypt_file(input_path, output_path1, cipher_type, key, iv)
    result2 = encrypt_file(input_path, output_path2, cipher_type, key, iv)
    
    return {
        'key': key,
        'iv': iv,
        'files_identical': filecmp.cmp(output_path1, output_path2, shallow=False)
    }

def brute_force_demo(ciphertext_path, original_text, cipher_type='aes-128-cbc'):
    """Demonstrate brute forcing with a weak key"""
    weak_key = "6162"  # "ab" in hex
    iv = "0102030405060708"
    
    with open("temp_original.txt", "w") as f:
        f.write(original_text)
    
    encrypt_file("temp_original.txt", ciphertext_path, cipher_type, weak_key, iv)
    
    possible_keys = ["6161", "6162", "6163", "6164"]
    
    for key_attempt in possible_keys:
        try:
            decrypt_file(ciphertext_path, f"temp_decrypted_{key_attempt}.txt", cipher_type, key_attempt, iv)
            with open(f"temp_decrypted_{key_attempt}.txt", "r") as f:
                decrypted = f.read()
            if decrypted == original_text:
                return {
                    'success': True,
                    'found_key': key_attempt,
                    'decrypted_text': decrypted,
                    'total_attempts': possible_keys.index(key_attempt) + 1
                }
        except:
            continue
    
    return {'success': False, 'total_attempts': len(possible_keys)}