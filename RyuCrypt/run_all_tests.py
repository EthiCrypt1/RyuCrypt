#!/usr/bin/env python3
"""
Comprehensive test script for the encryption project.
Tests all functionality including CLI commands, text and image encryption/decryption.
"""

import os
import subprocess
import shutil
from PIL import Image, ImageDraw

def setup():
    """Set up the test environment."""
    print("\n=== Setting up test environment ===")
    
    # Create test directory
    if os.path.exists("test_output"):
        shutil.rmtree("test_output")
    os.makedirs("test_output", exist_ok=True)
    
    # Generate encryption keys
    print("Generating encryption keys...")
    subprocess.run(["python", "cli.py", "generate-keys"], check=True)
    subprocess.run(["python", "cli.py", "generate-keys", "--rsa"], check=True)
    
    # Create test image
    create_test_image()

def create_test_image():
    """Create a test image for encryption/decryption."""
    print("Creating test image...")
    
    # Create a simple test image
    img = Image.new('RGB', (300, 200), color=(73, 109, 137))
    d = ImageDraw.Draw(img)
    d.text((10, 10), "Test Image for Encryption", fill=(255, 255, 0))
    
    img.save('test_output/original.jpg')
    print("Test image created: test_output/original.jpg")

def test_text_encryption_cli():
    """Test text encryption and decryption using CLI."""
    print("\n=== Testing Text Encryption via CLI ===")
    
    # Test data
    test_text = "This is a secret message for testing encryption!"
    
    # Test AES encryption/decryption
    print("\nTesting AES encryption/decryption:")
    subprocess.run([
        "python", "cli.py", "text-cmd", "encrypt",
        "--input", test_text,
        "--output", "test_output/aes_encrypted.txt",
        "--algorithm", "aes"
    ], check=True)
    
    subprocess.run([
        "python", "cli.py", "text-cmd", "decrypt",
        "--input", "test_output/aes_encrypted.txt",
        "--output", "test_output/aes_decrypted.txt",
        "--algorithm", "aes"
    ], check=True)
    
    with open("test_output/aes_decrypted.txt", "r") as f:
        decrypted = f.read()
    
    print(f"Original: {test_text}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_text == decrypted}")
    
    # Test 3DES encryption/decryption
    print("\nTesting 3DES encryption/decryption:")
    subprocess.run([
        "python", "cli.py", "text-cmd", "encrypt",
        "--input", test_text,
        "--output", "test_output/3des_encrypted.txt",
        "--algorithm", "3des"
    ], check=True)
    
    subprocess.run([
        "python", "cli.py", "text-cmd", "decrypt",
        "--input", "test_output/3des_encrypted.txt",
        "--output", "test_output/3des_decrypted.txt",
        "--algorithm", "3des"
    ], check=True)
    
    with open("test_output/3des_decrypted.txt", "r") as f:
        decrypted = f.read()
    
    print(f"Original: {test_text}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_text == decrypted}")
    
    # Test RSA encryption/decryption
    print("\nTesting RSA encryption/decryption:")
    try:
        subprocess.run([
            "python", "cli.py", "text-cmd", "encrypt",
            "--input", test_text,
            "--output", "test_output/rsa_encrypted.txt",
            "--algorithm", "rsa"
        ], check=True)
        
        subprocess.run([
            "python", "cli.py", "text-cmd", "decrypt",
            "--input", "test_output/rsa_encrypted.txt",
            "--output", "test_output/rsa_decrypted.txt",
            "--algorithm", "rsa"
        ], check=True)
        
        with open("test_output/rsa_decrypted.txt", "r") as f:
            decrypted = f.read()
        
        print(f"Original: {test_text}")
        print(f"Decrypted: {decrypted}")
        print(f"Match: {test_text == decrypted}")
    except subprocess.CalledProcessError as e:
        print(f"RSA test failed: {e}")

def test_file_encryption_cli():
    """Test file encryption and decryption using CLI."""
    print("\n=== Testing File Encryption via CLI ===")
    
    # Create a test file
    test_text = "This is a secret message stored in a file for testing encryption!"
    with open("test_output/original.txt", "w") as f:
        f.write(test_text)
    
    # Test AES encryption/decryption with file input
    print("\nTesting AES file encryption/decryption:")
    subprocess.run([
        "python", "cli.py", "text-cmd", "encrypt",
        "--input", "test_output/original.txt",
        "--output", "test_output/file_aes_encrypted.txt",
        "--algorithm", "aes",
        "--is-file"
    ], check=True)
    
    subprocess.run([
        "python", "cli.py", "text-cmd", "decrypt",
        "--input", "test_output/file_aes_encrypted.txt",
        "--output", "test_output/file_aes_decrypted.txt",
        "--algorithm", "aes"
    ], check=True)
    
    with open("test_output/file_aes_decrypted.txt", "r") as f:
        decrypted = f.read()
    
    print(f"Original: {test_text}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_text == decrypted}")

def test_image_encryption_cli():
    """Test image encryption and decryption using CLI."""
    print("\n=== Testing Image Encryption via CLI ===")
    
    # Test image encryption/decryption
    subprocess.run([
        "python", "cli.py", "image-cmd", "encrypt",
        "--input", "test_output/original.jpg",
        "--output", "test_output/encrypted.jpg"
    ], check=True)
    
    subprocess.run([
        "python", "cli.py", "image-cmd", "decrypt",
        "--input", "test_output/encrypted.jpg",
        "--output", "test_output/decrypted.jpg"
    ], check=True)
    
    print("Image encryption/decryption completed.")
    print("Check the images to verify encryption/decryption worked correctly:")
    print("- Original: test_output/original.jpg")
    print("- Encrypted: test_output/encrypted.jpg")
    print("- Decrypted: test_output/decrypted.jpg")

def test_direct_api():
    """Test the direct API functions."""
    print("\n=== Testing Direct API Functions ===")
    
    from text import encrypt_text, decrypt_text
    from image import encrypt_image, decrypt_image
    
    # Test text encryption/decryption
    test_text = "This is a direct API test message!"
    
    print("\nTesting direct text API:")
    encrypt_text(test_text, "test_output/api_encrypted.txt", "aes")
    decrypted = decrypt_text("test_output/api_encrypted.txt", "aes")
    
    print(f"Original: {test_text}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_text == decrypted}")
    
    # Test image encryption/decryption
    print("\nTesting direct image API:")
    encrypt_image("test_output/original.jpg", "test_output/api_encrypted.jpg")
    decrypt_image("test_output/api_encrypted.jpg", "test_output/api_decrypted.jpg")
    
    print("Direct API image encryption/decryption completed.")
    print("Check the images to verify encryption/decryption worked correctly:")
    print("- Original: test_output/original.jpg")
    print("- Encrypted: test_output/api_encrypted.jpg")
    print("- Decrypted: test_output/api_decrypted.jpg")

def main():
    """Run all tests."""
    print("=== Encryption Project Comprehensive Test ===")
    
    # Set up test environment
    setup()
    
    # Test text encryption via CLI
    test_text_encryption_cli()
    
    # Test file encryption via CLI
    test_file_encryption_cli()
    
    # Test image encryption via CLI
    test_image_encryption_cli()
    
    # Test direct API functions
    test_direct_api()
    
    print("\n=== All tests completed! ===")
    print("Test outputs are available in the 'test_output' directory.")

if __name__ == "__main__":
    main() 