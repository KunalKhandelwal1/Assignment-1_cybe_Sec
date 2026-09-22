# CS_Lab_1

Video demonstration: https://drive.google.com/file/d/1GXxJ4OALZJAgupHLm78vAKwjd7UZBaZX/view?usp=sharing

A simple class portal where students can log in, encrypt files using Post-Quantum
ML-KEM-768 keys (via `liboqs`), and decrypt them using their private key — all
processed locally in the browser.

## Architecture

The project is a Flask (Python) web app with a SQLite database and browser-side
PQC crypto for the file encryption/decryption feature.

![Architecture before](before.png)

![Architecture after](after.png)

---

## How It Works — Full Flow (Post-Quantum)

Classical RSA-OAEP-2048 has been replaced with the NIST FIPS 203 Key
Encapsulation Mechanism **ML-KEM-768** (formerly Kyber768, NIST level 3) via
**liboqs**. The AES-256-GCM file layer is unchanged, and the client-side
private-key security boundary is intact (secret keys never leave the browser).

### 1. 🔐 Key Generation (ML-KEM-768 KEM via liboqs)

- The browser generates an **ML-KEM-768 keypair** entirely in-memory using
  **liboqs-wasm / oqs.js** (WebAssembly build) with a bundled pure-JS FIPS 203
  fallback (`public/ml-kem.js`, interoperable with liboqs).
- Sizes (FIPS 203): public key **1184 bytes**, secret key **2400 bytes**,
  ciphertext **1088 bytes**, shared secret **32 bytes**.
- The **public key** is exported as PEM (`-----BEGIN ML-KEM-768 PUBLIC KEY-----`)
  and saved as `public_key.pqc` (`.pem` also accepted).
- The **private (secret) key** is exported as PEM
  (`-----BEGIN ML-KEM-768 PRIVATE KEY-----`) and saved as `private_key.pqc`.
- The server **never sees the private key** at any point.

> **Fallback:** If the page is opened over plain HTTP on a non-localhost address (e.g., a LAN IP),
> `crypto.subtle` is unavailable. In that case, the browser calls `POST /generate-keys` and the
> Flask server generates the keypair using **liboqs-python**
> (`oqs.KeyEncapsulation("ML-KEM-768")`, alias `"Kyber768"`) instead.

---

### 2. 🔒 Encryption (Hybrid ML-KEM-768 KEM + AES-256-GCM)

Classical PKE (encrypt-AES-key-with-RSA) is replaced with a **KEM flow**:

```
User selects a file + provides ML-KEM-768 public key
        ↓
Step 1: KEM encapsulation with recipient public key → (kem_ciphertext[1088 B], shared_secret[32 B])
Step 2: Derive 256-bit AES key = HKDF-SHA256(shared_secret, salt="", info="ClassmateHub-ML-KEM-768-AES-256-GCM-v1")
        (direct 32-byte use would also be compliant; HKDF adds domain separation)
Step 3: File bytes encrypted with AES-256-GCM + 12-byte random IV → ciphertext (ct || 16-B tag)
        ↓
Browser POSTs { ciphertext, iv, encrypted_key (= base64 kem_ciphertext), filename } to /set-message
        ↓
Flask stores all 4 fields in SQLite under the user's account
```

> Why two layers? The KEM transports a fresh shared secret without ever
> encrypting under RSA. AES-GCM encrypts the actual file. This is the
> PQC hybrid pattern (KEM + DEM) recommended for post-quantum migration.

---

### 3. 🔓 Decryption (Browser-side, Private Key never leaves the client)

```
User provides ML-KEM-768 private_key.pqc on their account page
        ↓
Step 1: shared_secret = KEM decapsulation(private key, kem_ciphertext)
Step 2: aes_key = HKDF-SHA256(shared_secret); ciphertext decrypted with AES-GCM + IV → file bytes
        ↓
Text files  → content displayed on screen
Any file    → downloadable via "Download Decrypted File" button
        ↓
Private key is NEVER sent to the server
```

---

### 4. 🏗️ System Architecture

```
Browser (client-side)              Server (Flask/Python + liboqs)     Database (SQLite)
─────────────────────              ──────────────────────────         ─────────────────
public/ml-kem.js                   app.py                             classmates.db
public/crypto.js                     │                                  │
  │ (liboqs-wasm / ML-KEM-768 KEM,   │                                  │
  │  HKDF-SHA256, AES-256-GCM)       │                                  │
  ├─ generateKeyPair()        ←──── /generate-keys (liboqs fallback)  │
  ├─ encryptFile()  (encap)   ←──── /encrypt-file  (liboqs fallback)  │
  ├─ decryptFile()  (decap)   ←──── /decrypt-file  (liboqs fallback)  │
  │                                  │                                  │
  │                           POST /set-message ──────────────→  { ciphertext,
  │                           GET  /account    ←──────────────      iv,
  │                                                                  encrypted_key
  │                                                                  (= kem_ct),
  │                                                                  filename }
```

---

## Features

- Log in with a username and password
- View your own account page
- **Generate** a quantum-safe ML-KEM-768 keypair (public + private key) via liboqs
- **Download** both keys as `.pqc` files (`.pem` compatible)
- **Encrypt** any file using a KEM public key — stored encrypted in the database
- **Decrypt** the file using the private key — entirely in the browser (decapsulation)
- Download the decrypted file
- Change your login password any time

---

## Encryption Algorithm

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key encapsulation (PQC) | ML-KEM-768 (FIPS 203, formerly Kyber768) via liboqs | Produces kem_ciphertext + 32-byte shared secret |
| Key derivation | HKDF-SHA256 (info `ClassmateHub-ML-KEM-768-AES-256-GCM-v1`) | Derives 256-bit AES key from shared secret |
| Symmetric  | AES-256-GCM (12-byte IV, 16-byte tag)    | Encrypts the actual file content |

This is a **PQC hybrid (KEM + DEM)** scheme — the NIST-recommended post-quantum
replacement for RSA-based hybrid encryption.

FIPS 203 sizes: `pk=1184 B`, `sk=2400 B`, `ct=1088 B`, `ss=32 B`.

---

## Tech Stack

- [Python](https://python.org/) with [Flask](https://flask.palletsprojects.com/)
- [SQLite](https://sqlite.org/) for storage (via Python `sqlite3`)
- Plain HTML/CSS, no front-end framework
- **liboqs** ([Open Quantum Safe](https://openquantumsafe.org/)):
  - Browser: `liboqs-wasm` / `oqs.js` WebAssembly build, with bundled
    `public/ml-kem.js` FIPS 203 fallback (same KAT-verified logic, `mlkem` npm package)
  - Server: `liboqs-python` (`oqs.KeyEncapsulation("ML-KEM-768")`, fallback `"Kyber768"`)
- **Browser Web Crypto API** (`crypto.subtle`) for HKDF-SHA256 + AES-256-GCM
- Python [`cryptography`](https://cryptography.io/) (`AESGCM`) for server-side AES-256-GCM

---

## Getting Started

1. Create and activate a virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies (requires system `liboqs`; see below):

   ```bash
   pip install -r requirements.txt
   # = Flask + liboqs-python + cryptography
   ```

   System liboqs (Ubuntu/Debian example):

   ```bash
   # liboqs 0.16.0 installed to /usr/local in this environment
   cmake -S /path/to/liboqs -B /tmp/liboqs-build -DCMAKE_INSTALL_PREFIX=/usr/local
   cmake --build /tmp/liboqs-build -j && sudo cmake --install /tmp/liboqs-build
   sudo ldconfig
   ```

3. (Optional, browser bundle rebuild) The checked-in `public/ml-kem.js` is a
   minified IIFE bundle of the [`mlkem`](https://www.npmjs.com/package/mlkem)
   FIPS 203 implementation (liboqs-compatible). Rebuild with:

   ```bash
   npm install            # installs mlkem ^2.7.0
   npx esbuild entry-pqc.js --bundle --format=iife --platform=browser --outfile=public/ml-kem.js --minify
   ```

4. Start the server:

   ```bash
   python app.py
   ```

5. Open your browser to [http://localhost:3000](http://localhost:3000)

> **Important:** Use `http://localhost:3000` or `http://127.0.0.1:3000` for full browser-side
> PQC crypto support. The server-side liboqs fallback handles non-localhost access automatically.

The database (`classmates.db`) is created automatically the first time you run the app,
with sample accounts to log in with.

---

## Sample Accounts

| Username | Password |
|----------|----------|
| `arjun`  | `Football123` |
| `meera`  | `SummerFun2024` |
| `kabir`  | `ChessMaster9` |
| `zara`   | `RainbowUnicorn` |
| `vedant` | `12345678` |

---

## Project Structure

```
assignment-1-group-3/
├── app.py                 # Flask app — all routes + PQC helpers (liboqs ML-KEM-768, HKDF, AES-GCM)
├── requirements.txt       # Flask + liboqs-python + cryptography
├── db.py                  # Database setup & schema (Python)
├── views.py               # Shared HTML page template (Python)
├── test_app.py            # Unit tests (Python)
├── server.js              # Express app entry point (Node.js — original)
├── db.js                  # Database setup (Node.js — original)
├── views.js               # Shared page template (Node.js — original)
├── routes/
│   ├── login.js           # Login & logout routes (Node.js)
│   ├── account.js         # Account page + PQC file decrypt UI (Node.js)
│   ├── message.js         # PQC encrypt file page (Node.js)
│   └── password.js        # Change password (Node.js)
└── public/
    ├── ml-kem.js          # Browser ML-KEM-768 bundle (liboqs-wasm compatible, FIPS 203)
    ├── crypto.js          # Browser PQC hybrid helpers (KEM encap/decap + HKDF + AES-GCM)
    └── style.css          # Styling
```

---

## Configuration

By default the app runs on port `3000`. To use a different port, set the `PORT`
environment variable before starting:

```bash
PORT=8080 python app.py
```

---

## Security Notes

- The **private (secret) key never leaves the browser** during normal operation.
  Key generation, KEM encapsulation and decapsulation occur client-side via
  liboqs-wasm / ml-kem.js; only `ciphertext`, `iv` and `kem_ciphertext`
  (`encrypted_key`) are POSTed to `/set-message`.
- The server only stores the **encrypted ciphertext**, **KEM ciphertext**, and
  **IV** — it cannot decrypt the file without the private key.
- The server-side fallback (`/generate-keys`, `/encrypt-file`, `/decrypt-file`)
  uses **liboqs-python** (`oqs`) for ML-KEM-768 + `cryptography` AESGCM — no custom
  cryptography is implemented from scratch, and no RSA/OpenSSL PKE remains.
- Wire format: `POST /set-message { ciphertext, iv, encrypted_key (= kem_ct), filename }`
  with `ciphertext = base64(AES-GCM(ct || tag))`, `iv = base64(12 B)`,
  `encrypted_key = base64(ML-KEM-768 ct, 1088 B)`.
