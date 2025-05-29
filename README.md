# 🔐 Advanced File Security

Advanced File Security is a Flask-based web application that demonstrates and educates users on various cryptographic techniques. It allows users to securely encrypt, decrypt, and analyze files using modern cryptographic algorithms and also illustrates common vulnerabilities like ECB leaks, replay attacks, and brute-force attempts.

---

##  Features

- **AES Encryption & Decryption**
  - Supports multiple cipher modes (e.g., CBC, ECB)
  - Auto-generates keys and IVs if not provided
  - Verifies integrity using HMAC

- **ECB Pattern Leak Demo**
  - Upload an image and observe how ECB mode reveals patterns

- **Replay Attack Simulation**
  - Simulate replaying encrypted messages with the same IV and key

- **Brute-Force Attack Demonstration**
  - Attempt to brute-force a simple ciphertext with limited keyspace
