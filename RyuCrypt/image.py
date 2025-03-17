#!/usr/bin/env python3
"""
Image encryption and decryption module.
Encrypts and decrypts images while maintaining the .jpg format.
"""

import os
import io
import base64
from typing import Tuple
from dotenv import load_dotenv
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Load environment variables
load_dotenv()

class ImageEncryptor:
    """Class for handling image encryption and decryption."""
    
    def __init__(self):
        """Initialize the ImageEncryptor with keys from environment variables."""
        # Get key from environment variable
        image_key_str = os.getenv('IMAGE_KEY', '')
        
        # Decode base64 key
        try:
            self.key = base64.b64decode(image_key_str)
        except Exception as e:
            raise ValueError(f"Error decoding image key: {e}")
        
        # Validate key
        if len(self.key) != 16:
            raise ValueError(f"Image encryption key must be 16 bytes long (got {len(self.key)} bytes)")
    
    def _image_to_bytes(self, image_path: str) -> bytes:
        """
        Convert an image to bytes.
        
        Args:
            image_path: Path to the image
            
        Returns:
            Image data as bytes
        """
        with Image.open(image_path) as img:
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format=img.format)
            return img_byte_arr.getvalue()
    
    def _bytes_to_image(self, data: bytes, output_path: str) -> None:
        """
        Convert bytes back to an image and save it.
        
        Args:
            data: Image data as bytes
            output_path: Path to save the image
        """
        img = Image.open(io.BytesIO(data))
        img.save(output_path)
    
    def encrypt_image(self, image_path: str, output_path: str) -> None:
        """
        Encrypt an image and save it.
        
        Args:
            image_path: Path to the image to encrypt
            output_path: Path to save the encrypted image
        """
        # Read the image
        image_data = self._image_to_bytes(image_path)
        
        # Extract header (first 20 bytes) to preserve format information
        header = image_data[:20]
        data_to_encrypt = image_data[20:]
        
        # Encrypt the image data (excluding header)
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = pad(data_to_encrypt, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        # Combine header, IV, and encrypted data
        final_data = header + iv + encrypted_data
        
        # Save as a new image
        with open(output_path, 'wb') as f:
            f.write(final_data)
    
    def decrypt_image(self, encrypted_path: str, output_path: str) -> None:
        """
        Decrypt an image and save it.
        
        Args:
            encrypted_path: Path to the encrypted image
            output_path: Path to save the decrypted image
        """
        # Read the encrypted image
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Extract header, IV, and encrypted data
        header = encrypted_data[:20]
        iv = encrypted_data[20:36]
        data_to_decrypt = encrypted_data[36:]
        
        # Decrypt the image data
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(data_to_decrypt)
        
        try:
            decrypted_data = unpad(decrypted_padded_data, AES.block_size)
        except ValueError:
            # If unpadding fails, try to use the data as is
            decrypted_data = decrypted_padded_data
        
        # Combine header and decrypted data
        final_data = header + decrypted_data
        
        # Save as a new image
        with open(output_path, 'wb') as f:
            f.write(final_data)


# Helper functions for direct use
def encrypt_image(image_path: str, output_path: str) -> None:
    """
    Encrypt an image and save it.
    
    Args:
        image_path: Path to the image to encrypt
        output_path: Path to save the encrypted image
    """
    encryptor = ImageEncryptor()
    encryptor.encrypt_image(image_path, output_path)


def decrypt_image(encrypted_path: str, output_path: str) -> None:
    """
    Decrypt an image and save it.
    
    Args:
        encrypted_path: Path to the encrypted image
        output_path: Path to save the decrypted image
    """
    encryptor = ImageEncryptor()
    encryptor.decrypt_image(encrypted_path, output_path)


if __name__ == "__main__":
    # Example usage
    try:
        # Test with a sample image
        sample_image = "sample.jpg"
        encrypted_image = "encrypted_sample.jpg"
        decrypted_image = "decrypted_sample.jpg"
        
        if os.path.exists(sample_image):
            encrypt_image(sample_image, encrypted_image)
            print(f"Image encrypted and saved to {encrypted_image}")
            
            decrypt_image(encrypted_image, decrypted_image)
            print(f"Image decrypted and saved to {decrypted_image}")
        else:
            print(f"Sample image {sample_image} not found")
    except Exception as e:
        print(f"Error: {e}") 