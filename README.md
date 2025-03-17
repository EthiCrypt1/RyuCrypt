# RyuCrypt
# RyuCrypt - Advanced Encryption Tool 🔐

RyuCrypt is a command-line encryption tool that supports **AES, 3DES, and RSA encryption** for text, files, and images. It allows secure encryption and decryption with a simple CLI interface.

## 🚀 Features
- **Supports Multiple Encryption Algorithms:** AES, 3DES, RSA
- **Encrypt and Decrypt Text** (Save encrypted text as `.txt`)
- **Encrypt and Decrypt Files** (Encrypt entire text files)
- **Encrypt and Decrypt Images** (Preserves `.jpg` format)
- **CLI-Based Usage** for easy command-line operations
- **Text Encryption Without Saving** (Displays encrypted/decrypted text in terminal if no output file is specified)

---

## 📌 Installation
Ensure you have Python installed, then install dependencies:
```bash
pip install -r requirements.txt
```
If `requirements.txt` is missing, install manually:
```bash
pip install click python-dotenv pycryptodome pillow
```

---

## 🔑 Generating Encryption Keys
Before using RyuCrypt, generate encryption keys:
### **Generate AES, 3DES, and Image Encryption Keys**
```bash
python cli.py generate-keys
```
### **Generate RSA Key Pair**
```bash
python cli.py generate-keys --rsa
```
This creates a `.env` file (for AES & 3DES) and `keys/` directory with RSA keys.

---

## 📜 Usage
RyuCrypt follows a simple command structure:
```bash
RyuCrypt <mode> <type> -i <input> -o <output> <algorithm>
```

### **1. Encrypt and Decrypt Text**
#### **Encryption:**
```bash
RyuCrypt -en -text -i "hello world" -o encrypted.txt -aes
```
```bash
RyuCrypt -en -text -i "hello world" -o encrypted.txt -3des
```
```bash
RyuCrypt -en -text -i "hello world" -o encrypted.txt -rsa
```
#### **Decryption:**
```bash
RyuCrypt -de -text -i encrypted.txt -o decrypted.txt -aes
```
```bash
RyuCrypt -de -text -i encrypted.txt -o decrypted.txt -3des
```
```bash
RyuCrypt -de -text -i encrypted.txt -o decrypted.txt -rsa
```

#### **Encrypt Text Without Saving to a File**
```bash
RyuCrypt -en -text -i "hello world" -aes
```
**Output:** `Encrypted Text: U2FsdGVkX1+3yD...`

#### **Decrypt Text Without Saving to a File**
```bash
RyuCrypt -de -text -i encrypted.txt -aes
```
**Output:** `Decrypted Text: hello world`

---

### **2. Encrypt and Decrypt Files**
#### **Encryption:**
```bash
RyuCrypt -en -file -i input.txt -o encrypted.txt -aes
```
```bash
RyuCrypt -en -file -i input.txt -o encrypted.txt -3des
```
```bash
RyuCrypt -en -file -i input.txt -o encrypted.txt -rsa
```
#### **Decryption:**
```bash
RyuCrypt -de -file -i encrypted.txt -o decrypted.txt -aes
```
```bash
RyuCrypt -de -file -i encrypted.txt -o decrypted.txt -3des
```
```bash
RyuCrypt -de -file -i encrypted.txt -o decrypted.txt -rsa
```

---

### **3. Encrypt and Decrypt Images**
#### **Encryption:**
```bash
RyuCrypt -en -image -i input.jpg -o encrypted.jpg
```
#### **Decryption:**
```bash
RyuCrypt -de -image -i encrypted.jpg -o decrypted.jpg
```

---

## 🛠 Running Tests
To verify RyuCrypt's functionality, run:
```bash
python run_all_tests.py
```
This tests:
✅ AES, 3DES, RSA encryption/decryption  
✅ Text, file, and image encryption  
✅ CLI functionality  

---

## 📌 Notes
- **Text encryption without `-o` prints the result instead of saving it**
- **Image encryption always requires a file output**
- **Ensure keys are generated before encrypting/decrypting with RSA**

---

## 🤝 Contributing
Feel free to contribute! Fork the repo, make changes, and submit a pull request.

---

## 📜 License
RyuCrypt is open-source and available under the MIT License.

Happy Encrypting! 🔐🚀

