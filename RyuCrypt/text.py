#!/usr/bin/env python3
"""
Text encryption and decryption module.
Supports AES, 3DES, and RSA algorithms.
"""

import os
import base64
from typing import Tuple, Optional
from dotenv import load_dotenv
from Crypto.Cipher import AES, DES3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Load environment variables
load_dotenv()

class TextEncryptor:
    """Class for handling text encryption and decryption."""
    
    def __init__(self):
        """Initialize the TextEncryptor with keys from environment variables."""
        # Get keys from environment variables
        aes_key_str = os.getenv('AES_KEY', '')
        des3_key_str = os.getenv('TRIPLE_DES_KEY', '')
        self.rsa_public_key_path = os.getenv('RSA_PUBLIC_KEY_PATH')
        self.rsa_private_key_path = os.getenv('RSA_PRIVATE_KEY_PATH')
        
        # Decode base64 keys
        try:
            self.aes_key = base64.b64decode(aes_key_str)
            self.des3_key = base64.b64decode(des3_key_str)
        except Exception as e:
            raise ValueError(f"Error decoding keys: {e}")
        
        # Validate keys
        if len(self.aes_key) not in [16, 24, 32]:
            raise ValueError(f"AES key must be 16, 24, or 32 bytes long (got {len(self.aes_key)} bytes)")
        
        if len(self.des3_key) not in [16, 24]:
            raise ValueError(f"3DES key must be 16 or 24 bytes long (got {len(self.des3_key)} bytes)")
    
    def _load_rsa_keys(self) -> Tuple[Optional[RSA.RsaKey], Optional[RSA.RsaKey]]:
        """Load RSA public and private keys from files."""
        public_key = None
        private_key = None
        
        try:
            if self.rsa_public_key_path and os.path.exists(self.rsa_public_key_path):
                with open(self.rsa_public_key_path, 'rb') as f:
                    public_key = RSA.import_key(f.read())
            
            if self.rsa_private_key_path and os.path.exists(self.rsa_private_key_path):
                with open(self.rsa_private_key_path, 'rb') as f:
                    private_key = RSA.import_key(f.read())
        except Exception as e:
            print(f"Error loading RSA keys: {e}")
        
        return public_key, private_key
    
    def encrypt_aes(self, plaintext: str) -> Tuple[bytes, bytes]:
        """
        Encrypt text using AES-CBC.
        
        Args:
            plaintext: The text to encrypt
            
        Returns:
            Tuple of (iv, ciphertext)
        """
        iv = get_random_bytes(16)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return iv, ciphertext
    
    def decrypt_aes(self, iv: bytes, ciphertext: bytes) -> str:
        """
        Decrypt text using AES-CBC.
        
        Args:
            iv: Initialization vector
            ciphertext: Encrypted data
            
        Returns:
            Decrypted text
        """
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, AES.block_size)
        return plaintext.decode('utf-8')
    
    def encrypt_3des(self, plaintext: str) -> Tuple[bytes, bytes]:
        """
        Encrypt text using 3DES-CBC.
        
        Args:
            plaintext: The text to encrypt
            
        Returns:
            Tuple of (iv, ciphertext)
        """
        iv = get_random_bytes(8)  # 3DES uses 8-byte IV
        cipher = DES3.new(self.des3_key, DES3.MODE_CBC, iv)
        padded_data = pad(plaintext.encode('utf-8'), DES3.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return iv, ciphertext
    
    def decrypt_3des(self, iv: bytes, ciphertext: bytes) -> str:
        """
        Decrypt text using 3DES-CBC.
        
        Args:
            iv: Initialization vector
            ciphertext: Encrypted data
            
        Returns:
            Decrypted text
        """
        cipher = DES3.new(self.des3_key, DES3.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, DES3.block_size)
        return plaintext.decode('utf-8')
    
    def encrypt_rsa(self, plaintext: str) -> bytes:
        """
        Encrypt text using RSA.
        
        Args:
            plaintext: The text to encrypt
            
        Returns:
            Encrypted data
        """
        public_key, _ = self._load_rsa_keys()
        if not public_key:
            raise ValueError("RSA public key not found")
        
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(plaintext.encode('utf-8'))
    
    def decrypt_rsa(self, ciphertext: bytes) -> str:
        """
        Decrypt text using RSA.
        
        Args:
            ciphertext: Encrypted data
            
        Returns:
            Decrypted text
        """
        _, private_key = self._load_rsa_keys()
        if not private_key:
            raise ValueError("RSA private key not found")
        
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(ciphertext).decode('utf-8')
    
    def encrypt_text_to_file(self, plaintext: str, output_file: str, algorithm: str = 'aes') -> None:
        """
        Encrypt text and save to a file.
        
        Args:
            plaintext: Text to encrypt
            output_file: Path to save encrypted data
            algorithm: Encryption algorithm ('aes', '3des', or 'rsa')
        """
        if algorithm.lower() == 'aes':
            iv, ciphertext = self.encrypt_aes(plaintext)
            with open(output_file, 'wb') as f:
                f.write(iv + ciphertext)
        
        elif algorithm.lower() == '3des':
            iv, ciphertext = self.encrypt_3des(plaintext)
            with open(output_file, 'wb') as f:
                f.write(iv + ciphertext)
        
        elif algorithm.lower() == 'rsa':
            ciphertext = self.encrypt_rsa(plaintext)
            with open(output_file, 'wb') as f:
                f.write(ciphertext)
        
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def decrypt_text_from_file(self, input_file: str, algorithm: str = 'aes') -> str:
        """
        Decrypt text from a file.
        
        Args:
            input_file: Path to encrypted file
            algorithm: Encryption algorithm ('aes', '3des', or 'rsa')
            
        Returns:
            Decrypted text
        """
        with open(input_file, 'rb') as f:
            data = f.read()
        
        if algorithm.lower() == 'aes':
            iv = data[:16]
            ciphertext = data[16:]
            return self.decrypt_aes(iv, ciphertext)
        
        elif algorithm.lower() == '3des':
            iv = data[:8]
            ciphertext = data[8:]
            return self.decrypt_3des(iv, ciphertext)
        
        elif algorithm.lower() == 'rsa':
            return self.decrypt_rsa(data)
        
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")


# Helper functions for direct use
def encrypt_text(text: str, output_file: str, algorithm: str = 'aes') -> None:
    """
    Encrypt text and save to a file.
    
    Args:
        text: Text to encrypt
        output_file: Path to save encrypted data
        algorithm: Encryption algorithm ('aes', '3des', or 'rsa')
    """
    encryptor = TextEncryptor()
    encryptor.encrypt_text_to_file(text, output_file, algorithm)


def decrypt_text(input_file: str, algorithm: str = 'aes') -> str:
    """
    Decrypt text from a file.
    
    Args:
        input_file: Path to encrypted file
        algorithm: Encryption algorithm ('aes', '3des', or 'rsa')
        
    Returns:
        Decrypted text
    """
    encryptor = TextEncryptor()
    return encryptor.decrypt_text_from_file(input_file, algorithm)


if __name__ == "__main__":
    # Example usage
    test_text = "This is a secret message!"
    
    # Test AES
    encrypt_text(test_text, "encrypted_aes.txt", "aes")
    decrypted = decrypt_text("encrypted_aes.txt", "aes")
    print(f"AES Decrypted: {decrypted}")
    
    # Test 3DES
    encrypt_text(test_text, "encrypted_3des.txt", "3des")
    decrypted = decrypt_text("encrypted_3des.txt", "3des")
    print(f"3DES Decrypted: {decrypted}")
    
    # Test RSA (requires key files)
    try:
        encrypt_text(test_text, "encrypted_rsa.txt", "rsa")
        decrypted = decrypt_text("encrypted_rsa.txt", "rsa")
        print(f"RSA Decrypted: {decrypted}")
    except Exception as e:
        print(f"RSA test failed: {e}") 