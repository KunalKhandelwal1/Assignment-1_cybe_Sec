# CS_Lab_1 — Classmate Hub (Post-Quantum Edition)

Video demonstration: https://drive.google.com/file/d/1GXxJ4OALZJAgupHLm78vAKwjd7UZBaZX/view?usp=sharing

A simple class portal where students can log in, encrypt files using **Post-Quantum
ML-KEM-768** keys (via **liboqs**), and decrypt them using their private key —
all processed locally in the browser.

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

---

# 🎓 VIVA Q&A GUIDE (question-by-question)

Every Q below maps to code you can point at. File names + line anchors in brackets.

## A. Conceptual / "why PQC"

**Q1. Why did you replace RSA with PQC? What is the threat?**
A classical public-key systems (RSA, DH, ECC) are broken by Shor's algorithm on a
large-enough quantum computer: factoring/discrete-log become easy. AES-256 and
SHA-256 stay quantum-safe (Grover only halves their strength, so 256-bit keys are
still ~128-bit post-quantum). So we swapped only the ASYMMETRIC layer
(RSA-OAEP-2048 → ML-KEM-768) and kept AES-256-GCM. [app.py header "VIVA MAP",
README Encryption Algorithm table]

**Q2. What does ML-KEM mean? What is ML-KEM-768?**
ML = Module-Lattice (the lattice type underlying the construction).
KEM = Key Encapsulation Mechanism. 768 = the parameter set (k=3),
giving NIST security level 3 and a 1088-byte ciphertext. It is the final
FIPS 203 standardization of CRYSTALS-Kyber (so "Kyber768" is just the older
alias we keep as fallback). Backed by Module-Learning-With-Errors (MLWE),
assumed hard for both classical and quantum computers.
[app.py: PQC_KEM_ALGORITHMS comment, ML_KEM_768_* constants]

**Q3. What is a KEM? How is it different from Public-Key Encryption (PKE)?**
- PKE (old RSA flow): Encrypt(msg, pk) → ciphertext; Decrypt(ct, sk) → msg.
  We used it to encrypt a random AES key.
- KEM (new flow): Encap(pk) → (ciphertext, shared_secret) produced by the
  SENDER; Decap(ciphertext, sk) → the SAME shared_secret at the receiver.
  A KEM does not encrypt arbitrary data at all — it only transfers one fresh
  32-byte secret. The "message" (file) is always encrypted with AES-GCM
  using a key derived from that secret. This is why we needed HKDF. [crypto.js:
  "Hybrid KEM flow" doc block; encryptFile/decryptFile doc comments]

**Q4. Why still a "hybrid"? Why not just KEM alone?**
KEMs only carry a small secret (~32 bytes), not megabyte files, and they are
not authenticated-encryption for bulk data. So the standard construction is
KEM + DEM (Data Encapsulation Mechanism): KEM agrees a key, DEM = AES-256-GCM
encrypts the payload with integrity. Same reason RSA+AES existed — we only
changed the transport of the key. [README "Encryption Algorithm" table]

**Q5. What are the concrete sizes? (Very likely)**
pk = 1184 B, sk/secret key = 2400 B, KEM ciphertext = 1088 B,
shared secret = 32 B, AES key = 32 B, IV = 12 B, GCM tag = 16 B (appended to ct).
PEM of public key ≈ 1678 chars, private ≈ 3325 chars.
[app.py constants; crypto.js sizes object]

**Q6. Kyber vs ML-KEM-768 — are they the same?**
Same family; Kyber was the round-3 NIST candidate, standardized with small
tweaks as ML-KEM in FIPS 203 (Aug 2024). liboqs 0.16 exposes both names; we
prefer "ML-KEM-768" and fall back to "Kyber768".
[app.py _resolve_kem_algorithm docstring]

## B. Your actual code flow

**Q7. Walk me through encryption step by step, pointing at code.**
1. UI `/set-message` reads the pasted/selected `.pqc` public key
   [app.py get_set_message inline JS → ClassmateCrypto.encryptFile].
2. crypto.js `encryptFile()`: `parsePublicKeyPem` validates 1184 B
   [crypto.js encryptFile].
3. `kem.encap(publicKeyBytes)` → `kemCiphertext` (1088 B) + `sharedSecret` (32 B).
4. `deriveAesKey(sharedSecret)` → HKDF-SHA256 → 32-byte AES key
   [crypto.js deriveAesKey + hkdfSha256].
5. `crypto.getRandomValues(12)` → IV; `crypto.subtle.encrypt({name:"AES-GCM"...})`
   → ct||tag.
6. Returns base64 {ciphertext, iv, encryptedKey=kem_ct}; form auto-POSTs to
   `/set-message` which UPDATEs 4 TEXT columns [app.py post_set_message].

**Q8. Walk me through decryption.**
`/account` embeds the 4 blobs as data-* attributes [app.py account()]; user
loads private_key.pqc; `ClassmateCrypto.decryptFile(ciphertext, iv, encryptedKey, privateKeyPem)`:
validate kem_ct=1088 B and sk=2400 B → `kem.decap(kemCiphertext, secretKeyBytes)`
→ shared_secret → HKDF → AES-GCM `subtle.decrypt` (fails if wrong key/tag).
Output shown as text or downloadable. [crypto.js decryptFile; app.py account inline JS]

**Q9. Where exactly does the private key live? Can the server read it?**
Browser RAM only: generated in `generateKeyPair()` [crypto.js], used inside
`decryptFile()` in memory, optionally saved by the user as `private_key.pqc`
via the download button. It is NEVER part of any fetch body — /set-message only
receives ciphertext/iv/encrypted_key/filename. Verify: DevTools → Network →
click Decrypt → no request carries the key. The ONLY exception is the explicit
plain-HTTP FALLBACK (Q12).

**Q10. Why HKDF? Direct 32-byte secret as AES key would work, right?**
Correct — FIPS 203 already outputs 32 uniform bytes, so direct use is compliant.
HKDF adds domain separation: the fixed `info`
("ClassmateHub-ML-KEM-768-AES-256-GCM-v1") binds the derived key to THIS app/
context, so a secret reused elsewhere yields a different AES key. Both sides
MUST use the identical info: compare `HKDF_INFO` [app.py] with
`HKDF_INFO_STRING` [crypto.js] — same string. HKDF = Extract (HMAC with salt)
+ Expand (chained HMACs with info‖counter); empty salt = 32 zero bytes per
RFC 5869. [app.py hkdf_sha256 docstring]

**Q11. Why a random IV per file? What if IV repeats?**
GCM is a CTR mode: same (key, IV) stream twice → XOR of two plaintexts leaks
and the authentication is broken (nonces must be unique per key). 96-bit
random nonce gives negligible collision risk at our volumes. 12 bytes is the
standard GCM nonce size. [crypto.js iv = getRandomValues(12);
app.py secrets.token_bytes(12)]

**Q12. When does the SERVER do crypto? Isn't that against your claim?**
Normal path (localhost/HTTPS): NEVER — all crypto client-side. Fallback path:
`crypto.subtle` is unavailable on plain-HTTP non-localhost pages, so
crypto.js detects it (`hasSubtleCrypto()`) and POSTs to `/generate-keys`,
`/encrypt-file`, `/decrypt-file`, which run the IDENTICAL KEM+HKDF+AES flow
in Python using liboqs-python (`oqs.KeyEncapsulation`) + `cryptography.AESGCM`.
On that fallback the server transiently sees the secret key — we state this
tradeoff honestly [app.py generate_keys docstring]. Same flow = same sizes =
cross-compatible (a browser key decodes server ciphertexts and vice versa —
tested both directions).

**Q13. Why liboqs on BOTH sides? Why a bundled ml-kem.js?**
liboqs is the reference C implementation (openquantumsafe). Server: system
liboqs via `liboqs-python`. Browser: true liboqs-WASM is heavy and its global
API varies, so crypto.js FIRST looks for `window.OQS/liboqs/oqs` (real
liboqs-wasm if present) and otherwise uses `public/ml-kem.js` — a 25 KB IIFE
bundle of the KAT-verified FIPS 203 `mlkem` package. Decisive fact: we proved
byte-for-byte interop with liboqs (JS-encap → Python-decap = same 32 B secret
and Python-encap → JS-decap = same secret). [crypto.js resolveKem +
tryWrapLiboqsWasm]

**Q14. Python and JS HKDF — how do you guarantee they match?**
Same algorithm (RFC 5869), same salt treatment (empty → 32 zero bytes; HMAC
with empty key pads to the same thing), same info bytes, length 32.
We verified with a fixed test vector: IKM = 00..1f both sides produce
`90c6d88f...a7a1f8`. [app.py hkdf_sha256; crypto.js hkdfSha256]

## C. Crypto-detail questions the examiner likes

**Q15. Is ML-KEM-768 CCA-secure? What problem underlies it?**
Yes — ML-KEM is IND-CCA2 (FIPS 203), built from an IND-CPA Module-LWE/MLWE
PKE plus a Fujisaki-Okamoto-style transform. liboqs reports
`is_ind_cca = true`, NIST level 3. (KyberSlash timing bug was fixed before
standardization; the `mlkem` bundle is patched/KAT-tested.)

**Q16. AES-GCM properties?**
Authenticated encryption: confidentiality (CTR) + integrity/authenticity
(GHASH tag). Tampering 1 bit → decrypt throws. 256-bit key, 96-bit IV,
128-bit tag. Failed auth is why the UI shows "Invalid Private Key or
corrupted file" on any mismatch. [app.py _aes_gcm_*; crypto.js subtle.decrypt try/catch]

**Q17. What if I encrypt twice with the same public key?**
KEM randomness makes kem_ct + shared_secret differ EVERY encapsulation, and IV
is fresh per file. No ciphertext-relationship leak. (This is a key DIFFERENCE
from re-using an RSA session: RSA-OAEP is randomized too, but the KEM model
explicitly guarantees fresh secrets.)

**Q18. PEM format — is it real X.509?**
No. Same *wrapper* convention (BEGIN/END, base64, 64-col lines) but the
payload is RAW ML-KEM key bytes, not ASN.1/DER. The parser strips any
accepted header and validates LENGTH (1184/2400) — that length check is the
real "is this an ML-KEM key" test; an RSA PEM would fail it immediately.
[app.py _pem_encode/_pem_decode/_parse_pqc_*]

**Q19. Post-quantum security level of ML-KEM-768 in one line?**
NIST Level 3 ≈ AES-192 classical brute force ≈ 2^192 work, i.e. quantum
attacks still need ~2^128 Grover-with-Shor lattice work — comfortable margin.

**Q20. What is "hybrid encryption" here vs "hybrid PQC"?**
Layout is unchanged (small-key layer + bulk-data layer). What changed is the
small-key layer: RSA-PKE encrypts → ML-KEM encapsulates + HKDF derives.
before.png / after.png show exactly this swap.

## D. Implementation / web-security questions

**Q21. Isn't login insecure?**
Demo-grade, deliberately kept: cookie "username" (no session/HMAC) and the
login SQL is a concatenation mirroring the original Express code. We know;
the assignment focus is the crypto layer. `/account` and `/set-message`
DO use parameterized queries. [app.py login docstring]

**Q22. Where is the schema? What do you store?**
4 nullable TEXT columns: message_ciphertext, message_iv,
message_encrypted_key (= base64 KEM ct), message_filename — created/ALTERed
idempotently, demo accounts upserted with COALESCE so restarts keep saved
blobs. NO keys, NO plaintext ever touch SQLite.
[db.py init_db]

**Q23. Tests?**
`venv/bin/python test_app.py` — unittest + Flask test_client:
login success/failure, /set-message blob embedding as data-* attributes,
password persistence via direct SQL, logout, static CSS/JS reachable (crypto.js
and ml-kem.js load through static_url_path="/public"). Real crypto roundtrips
verified separately via /generate-keys → /encrypt-file → /decrypt-file.
[test_app.py]

**Q24. Why TWO backends (Flask AND Express)?**
Original submission was Express; the graded runtime is Flask sharing the same
SQLite schema + the same browser bundle. Only one runs at a time.
[server.js/db.js header comments]

**Q25. How do I run it? / demo script for the viva?**
```
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt          # Flask + liboqs-python + cryptography
python app.py                            # http://localhost:3000
```
Demo in 60 s: login `arjun/Football123` → Encrypt New File →
Generate ML-KEM-768 Key Pair → save both `.pqc` → pick any file →
Encrypt & Save File → back on account → load `private_key.pqc` →
Decrypt File → (Download). Mention sizes + "private key never left the
browser" while doing it.

**Q26. What did YOU change vs the reference (diff-style answer)?**
- public/crypto.js: RSA-OAEP generateKey/import/encrypt/decrypt → ML-KEM-768
  keygen/encap/decap + HKDF (AES-GCM part unchanged).
- app.py: /generate-keys (openssl genrsa) → oqs.KeyEncapsulation; /encrypt-file
  and /decrypt-file (openssl rsautl/enc) → oqs encap/decap + HKDF + AESGCM;
  added PQC helper block + constants.
- public/ml-kem.js: new FIPS 203 browser bundle.
- routes/*.js + inline UI: labels/placeholders/.pqc accept list + ml-kem.js
  script tag. style.css/views untouched → identical look.
- package.json += mlkem; requirements.txt new (liboqs-python, cryptography).
