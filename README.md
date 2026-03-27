# 🔐 Advanced File Secure v2

A secure file encryption tool built using **AES-256-GCM (Authenticated Encryption)** and **Argon2id key derivation**, with a simple and interactive UI powered by Streamlit.

This application allows users to encrypt sensitive files before storing or sharing them, ensuring **confidentiality, integrity, and authenticity**.

---

## 🚀 Features

* 🔒 **AES-256-GCM Encryption**

  * Provides authenticated encryption (confidentiality + integrity)
  * Protects against tampering and bit-flipping attacks

* 🧠 **Argon2id Key Derivation**

  * Memory-hard, GPU-resistant password hashing
  * Follows OWASP-recommended parameters

* 📦 **Versioned File Format**

  * Self-contained encrypted bundle
  * Supports future upgrades

* 📝 **Filename Preservation**

  * Original filename securely embedded and restored after decryption

* 🔍 **Password Strength Meter**

  * Uses zxcvbn for real-time feedback
  * Encourages strong passwords

* 🛡️ **Authenticated Integrity**

  * AES-GCM authentication ensures tamper detection

* 🧹 **Secure Memory Handling**

  * Key material wiped from memory after use (best-effort)

---

## 🛠️ Tech Stack

* Python 3
* Streamlit (UI)
* cryptography (AES-GCM)
* argon2-cffi (Argon2id)
* zxcvbn (password strength)

---

## 📦 Installation

### 1. Clone the repository

```
git clone https://github.com/your-username/advanced-file-secure.git
cd advanced-file-secure
```

### 2. Install dependencies

```
pip install -r requirements.txt
```

### 3. Run the application

```
streamlit run app.py
```

---

## 🌐 Live Demo

*(Add after deployment)*
👉 https://your-app-name.streamlit.app

---

## 🔐 How It Works

### 1. Key Derivation

* Password → Argon2id → 256-bit encryption key
* Uses:

  * Salt (random)
  * Memory-hard computation

### 2. Encryption

* AES-GCM encrypts file data
* Provides:

  * Confidentiality
  * Integrity (authentication tag)

### 3. File Structure (v2)

```
[MAGIC][VERSION][SALT][NONCE][FILENAME][CIPHERTEXT]
```

* Header is authenticated using AAD
* Any modification → decryption fails

### 4. Decryption

* Extract metadata
* Re-derive key
* Verify integrity via AES-GCM

---

## 🔒 Security Design Decisions

### ✅ Why AES-GCM?

* Authenticated encryption (AEAD)
* Prevents:

  * Bit-flipping attacks
  * Padding oracle attacks

---

### ✅ Why Argon2id?

* Memory-hard → resistant to GPU attacks
* Recommended by OWASP for password-based systems

---

### ✅ Why Versioned Format?

* Enables backward compatibility
* Allows future upgrades (e.g., new algorithms)

---

### ✅ Why AAD?

* Protects metadata (filename, header)
* Ensures full-file integrity

---

## ⚠️ Limitations

* Encryption is currently **memory-based (not chunked streaming)**
* Argon2 parameters are **fixed (not adaptive to device performance)**
* No multi-user key management (single-password system)

---

## 🔮 Future Improvements

* 📁 Chunk-based streaming encryption (large files)
* 🔑 Hybrid encryption (RSA + AES)
* ☁️ Secure cloud storage integration
* ⚙️ Adaptive Argon2 tuning
* 📊 File integrity hashing dashboard

---

## 🎓 Use Cases

* Secure file storage
* Privacy-focused file sharing
* Pre-cloud encryption (Zero Trust model)

---

## 👨‍💻 Author

**Raghul M**
ECE @ IIIT Manipur
Cybersecurity & Systems Enthusiast

---

## ⭐ If you found this useful, consider giving it a star!
