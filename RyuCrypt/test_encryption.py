#!/usr/bin/env python3
"""
Test script for the encryption tool.
Demonstrates text and image encryption/decryption.
"""

import os
import base64
from Crypto.Random import get_random_bytes
from text import encrypt_text, decrypt_text
from image import encrypt_image, decrypt_image

def setup_test_environment():
    """Set up the test environment with temporary keys."""
    # Create keys directory
    os.makedirs('keys', exist_ok=True)
    
    # Generate temporary keys
    aes_key = get_random_bytes(32)
    des3_key = get_random_bytes(24)
    image_key = get_random_bytes(16)
    
    # Create .env file with temporary keys
    with open('.env', 'w') as f:
        f.write(f"AES_KEY={base64.b64encode(aes_key).decode('utf-8')}\n")
        f.write(f"TRIPLE_DES_KEY={base64.b64encode(des3_key).decode('utf-8')}\n")
        f.write(f"IMAGE_KEY={base64.b64encode(image_key).decode('utf-8')}\n")
        f.write("RSA_PUBLIC_KEY_PATH=keys/public_key.pem\n")
        f.write("RSA_PRIVATE_KEY_PATH=keys/private_key.pem\n")
    
    # Generate RSA key pair
    from Crypto.PublicKey import RSA
    key = RSA.generate(2048)
    
    # Save private key
    with open('keys/private_key.pem', 'wb') as f:
        f.write(key.export_key('PEM'))
    
    # Save public key
    with open('keys/public_key.pem', 'wb') as f:
        f.write(key.publickey().export_key('PEM'))
    
    print("Test environment set up successfully")

def create_test_image():
    """Create a test image for encryption/decryption."""
    try:
        from PIL import Image, ImageDraw
        
        # Create a simple test image
        img = Image.new('RGB', (300, 200), color=(73, 109, 137))
        d = ImageDraw.Draw(img)
        d.text((10, 10), "Test Image for Encryption", fill=(255, 255, 0))
        
        img.save('sample.jpg')
        print("Test image created: sample.jpg")
    except Exception as e:
        print(f"Error creating test image: {e}")

def test_text_encryption():
    """Test text encryption and decryption."""
    print("\n=== Testing Text Encryption ===")
    
    # Test data
    test_text = "This is a secret message for testing encryption!"
    
    # Test AES
    print("\nTesting AES encryption:")
    encrypt_text(test_text, "encrypted_aes.txt", "aes")
    decrypted = decrypt_text("encrypted_aes.txt", "aes")
    print(f"Original: {test_text}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_text == decrypted}")
    
    # Test 3DES
    print("\nTesting 3DES encryption:")
    encrypt_text(test_text, "encrypted_3des.txt", "3des")
    decrypted = decrypt_text("encrypted_3des.txt", "3des")
    print(f"Original: {test_text}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_text == decrypted}")
    
    # Test RSA
    print("\nTesting RSA encryption:")
    try:
        encrypt_text(test_text, "encrypted_rsa.txt", "rsa")
        decrypted = decrypt_text("encrypted_rsa.txt", "rsa")
        print(f"Original: {test_text}")
        print(f"Decrypted: {decrypted}")
        print(f"Match: {test_text == decrypted}")
    except Exception as e:
        print(f"RSA test failed: {e}")

def test_image_encryption():
    """Test image encryption and decryption."""
    print("\n=== Testing Image Encryption ===")
    
    if not os.path.exists('sample.jpg'):
        create_test_image()
    
    if os.path.exists('sample.jpg'):
        # Encrypt the image
        encrypt_image('sample.jpg', 'encrypted_sample.jpg')
        print("Image encrypted successfully")
        
        # Decrypt the image
        decrypt_image('encrypted_sample.jpg', 'decrypted_sample.jpg')
        print("Image decrypted successfully")
        
        print("Check the images to verify encryption/decryption worked correctly:")
        print("- Original: sample.jpg")
        print("- Encrypted: encrypted_sample.jpg")
        print("- Decrypted: decrypted_sample.jpg")
    else:
        print("Sample image not found")

def main():
    """Run all tests."""
    print("=== Encryption Tool Test ===")
    
    # Set up test environment
    setup_test_environment()
    
    # Test text encryption
    test_text_encryption()
    
    # Test image encryption
    test_image_encryption()
    
    print("\nAll tests completed!")

if __name__ == "__main__":
    main() 