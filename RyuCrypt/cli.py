#!/usr/bin/env python3
"""
Command-line interface for RyuCrypt.
Provides commands for encrypting and decrypting text and images.
"""

import os
import sys
import argparse
from dotenv import load_dotenv
import text
import image
import base64

# Load environment variables
load_dotenv()

def encrypt_text_data(input_text, output_file=None, algorithm='aes'):
    """Encrypt text data and optionally save to file."""
    encryptor = text.TextEncryptor()
    
    if algorithm == 'aes':
        iv, ciphertext = encryptor.encrypt_aes(input_text)
        # Store IV and ciphertext separately in base64
        iv_b64 = base64.b64encode(iv).decode('utf-8')
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        encrypted = f"{iv_b64}#{ciphertext_b64}"  # Use # instead of | for PowerShell compatibility
    elif algorithm == '3des':
        iv, ciphertext = encryptor.encrypt_3des(input_text)
        # Store IV and ciphertext separately in base64
        iv_b64 = base64.b64encode(iv).decode('utf-8')
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        encrypted = f"{iv_b64}#{ciphertext_b64}"  # Use # instead of | for PowerShell compatibility
    elif algorithm == 'rsa':
        ciphertext = encryptor.encrypt_rsa(input_text)
        encrypted = base64.b64encode(ciphertext).decode('utf-8')
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(encrypted)
        return f"Text encrypted successfully and saved to {output_file}"
    else:
        return f"Encrypted Text: {encrypted}"

def decrypt_text_data(input_data, is_file=True, algorithm='aes'):
    """Decrypt text data from file or base64 string."""
    encryptor = text.TextEncryptor()
    
    try:
        # If input is a file, read its contents
        if is_file:
            with open(input_data, 'r', encoding='utf-8') as f:
                input_data = f.read().strip()
        
        # Clean up the input string
        input_data = input_data.replace('\n', '').replace('\r', '').strip()
        
        if algorithm in ['aes', '3des']:
            # Split IV and ciphertext
            if '#' not in input_data:
                raise ValueError("Invalid encrypted format. Expected 'iv#ciphertext'")
            
            iv_b64, ciphertext_b64 = input_data.split('#', 1)
            iv = base64.b64decode(iv_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            
            if algorithm == 'aes':
                return encryptor.decrypt_aes(iv, ciphertext)
            else:  # 3des
                return encryptor.decrypt_3des(iv, ciphertext)
        else:  # RSA
            ciphertext = base64.b64decode(input_data)
            return encryptor.decrypt_rsa(ciphertext)
    except Exception as e:
        raise ValueError(f"Failed to decrypt text: {str(e)}")

def main():
    # Simple argument parsing without argparse
    args = sys.argv[1:]
    if not args:
        print("Usage: RyuCrypt <mode> <type> -i <input> [-o <output>] [<algorithm>]")
        print("\nExamples:")
        print("  RyuCrypt -en -text -i \"hello world\" -aes")
        print("  RyuCrypt -en -file -i input.txt -o encrypted.txt -aes")
        print("  RyuCrypt -en -image -i input.jpg -o encrypted.jpg")
        sys.exit(1)

    # Initialize default values
    mode = None
    input_type = None
    input_value = None
    output_file = None
    algorithm = 'aes'

    # Parse arguments
    i = 0
    while i < len(args):
        arg = args[i].lower()
        if arg in ['-en', '-de']:
            mode = arg[1:]  # Remove the dash
        elif arg in ['-text', '-file', '-image']:
            input_type = arg[1:]  # Remove the dash
        elif arg == '-i' and i + 1 < len(args):
            input_value = args[i + 1]
            i += 1
        elif arg == '-o' and i + 1 < len(args):
            output_file = args[i + 1]
            i += 1
        elif arg in ['-aes', '-3des', '-rsa']:
            algorithm = arg[1:]  # Remove the dash
        i += 1

    # Validate required arguments
    if not mode:
        print("Error: Mode (-en or -de) is required", file=sys.stderr)
        sys.exit(1)
    if not input_type:
        print("Error: Type (-text, -file, or -image) is required", file=sys.stderr)
        sys.exit(1)
    if not input_value:
        print("Error: Input (-i) is required", file=sys.stderr)
        sys.exit(1)

    try:
        # Text encryption/decryption
        if input_type in ['text', 'file']:
            if mode == 'en':
                if input_type == 'text':
                    # Direct text encryption
                    result = encrypt_text_data(input_value, output_file, algorithm)
                else:
                    # File encryption
                    with open(input_value, 'r', encoding='utf-8') as f:
                        input_text = f.read()
                    result = encrypt_text_data(input_text, output_file, algorithm)
                if not output_file:
                    print(result)
            
            else:  # Decryption
                if input_type == 'text':
                    # Direct text decryption (if input is a file path)
                    if os.path.isfile(input_value):
                        decrypted = decrypt_text_data(input_value, is_file=True, algorithm=algorithm)
                    else:
                        # Assume input is base64 encoded ciphertext
                        decrypted = decrypt_text_data(input_value, is_file=False, algorithm=algorithm)
                else:
                    # File decryption
                    decrypted = decrypt_text_data(input_value, is_file=True, algorithm=algorithm)
                
                if output_file:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(decrypted)
                    print(f"Text decrypted successfully and saved to {output_file}")
                else:
                    print(f"Decrypted Text: {decrypted}")
        
        # Image encryption/decryption
        elif input_type == 'image':
            if not output_file:
                print("Error: Output file (-o) is required for image encryption/decryption", file=sys.stderr)
                sys.exit(1)
            
            if mode == 'en':
                image.encrypt_image(input_value, output_file)
                print(f"Image encrypted successfully and saved to {output_file}")
            else:
                image.decrypt_image(input_value, output_file)
                print(f"Image decrypted successfully and saved to {output_file}")
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()