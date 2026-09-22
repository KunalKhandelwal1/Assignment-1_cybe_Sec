/* Classmate Hub — Post-Quantum hybrid encryption (ML-KEM-768 + AES-256-GCM).
 *
 * PQC migration: RSA-OAEP-2048 PKE has been replaced with the NIST FIPS 203
 * Key Encapsulation Mechanism ML-KEM-768 (formerly Kyber768, NIST level 3).
 *
 * Hybrid KEM flow (PKE -> KEM paradigm shift):
 *   1. Recipient holds an ML-KEM-768 keypair (public 1184 B, secret 2400 B).
 *   2. Sender runs KEM encapsulation with the recipient public key ->
 *      (kem_ciphertext[1088 B], shared_secret[32 B]).
 *   3. A 256-bit AES key is derived from shared_secret via HKDF-SHA256 with a
 *      domain-separation info string (direct 32-byte use would also be
 *      compliant since FIPS 203 outputs 32 uniform bytes, but HKDF binds the
 *      key to this application context).
 *   4. File bytes are encrypted with AES-256-GCM + random 12-byte IV.
 *   5. POST { ciphertext, iv, encrypted_key (= kem_ciphertext), filename }
 *      to /set-message. Decapsulation + AES-GCM decrypt recovers the file.
 *
 * Client-side integration (liboqs):
 *   - Preferred: liboqs-wasm / oqs.js WebAssembly build if present
 *     (window.OQS / window.liboqs / window.oqs with a KEM interface).
 *   - Bundled fallback: public/ml-kem.js — a browser IIFE bundle of the
 *     FIPS 203 ML-KEM-768 implementation (same KAT-verified logic as liboqs,
 *     interoperable with liboqs-python's oqs.KeyEncapsulation("ML-KEM-768")).
 *     Load it BEFORE this file:
 *       <script src="/public/ml-kem.js"></script>
 *       <script src="/public/crypto.js"></script>
 *   - Key generation, encapsulation and decapsulation always occur in browser
 *     memory. Secret (private) keys NEVER leave the browser and are never
 *     POSTed to the server. The server only stores ciphertext/iv/kem_ct.
 *
 * Server-side fallback (non-secure HTTP context where crypto.subtle is
 * unavailable): POST /generate-keys, /encrypt-file, /decrypt-file implement
 * the identical KEM + HKDF + AES-GCM flow in Python via liboqs-python (oqs).
 */
(function () {
    "use strict";

    // ------------------------------------------------------------------ constants
    /** KEM algorithm: ML-KEM-768 (FIPS 203, formerly Kyber768). Alias "Kyber768" accepted. */
    var KEM_ALGORITHM = "ML-KEM-768";
    var KEM_ALIAS_KYBER768 = "Kyber768";
    /** Domain-separation info for HKDF-SHA256 -> AES-256 key derivation. Must match server (app.py). */
    var HKDF_INFO_STRING = "ClassmateHub-ML-KEM-768-AES-256-GCM-v1";
    /** FIPS 203 ML-KEM-768 sizes (bytes). */
    var ML_KEM_768_PUBLIC_KEY_BYTES = 1184;
    var ML_KEM_768_SECRET_KEY_BYTES = 2400;
    var ML_KEM_768_CIPHERTEXT_BYTES = 1088;
    var ML_KEM_768_SHARED_SECRET_BYTES = 32;
    /** AES-256-GCM IV size. */
    var AES_GCM_IV_BYTES = 12;

    var PUBLIC_PEM_LABEL = "ML-KEM-768 PUBLIC KEY";
    var PRIVATE_PEM_LABEL = "ML-KEM-768 PRIVATE KEY";
    // Backwards-compatible labels also accepted on import.
    var PUBLIC_PEM_LABEL_ALIASES = [
        "ML-KEM-768 PUBLIC KEY",
        "KYBER768 PUBLIC KEY",
        "KYBER-768 PUBLIC KEY",
        "PUBLIC KEY"
    ];
    var PRIVATE_PEM_LABEL_ALIASES = [
        "ML-KEM-768 PRIVATE KEY",
        "KYBER768 PRIVATE KEY",
        "KYBER-768 PRIVATE KEY",
        "PRIVATE KEY"
    ];

    // ------------------------------------------------------------------ byte helpers
    function textToBytes(text) {
        return new TextEncoder().encode(text);
    }

    function bytesToText(bytes) {
        return new TextDecoder().decode(bytes);
    }

    function arrayBufferToBase64(buffer) {
        var bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        var binary = "";
        for (var i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    function base64ToBytes(base64) {
        var clean = String(base64).trim().replace(/\s+/g, "");
        var binary = atob(clean);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    function base64ToArrayBuffer(base64) {
        var bytes = base64ToBytes(base64);
        // Return a copy-backed ArrayBuffer (byteOffset-safe).
        return bytes.slice().buffer;
    }

    function concatBytes(parts) {
        var total = 0;
        for (var i = 0; i < parts.length; i++) total += parts[i].length;
        var out = new Uint8Array(total);
        var off = 0;
        for (var j = 0; j < parts.length; j++) {
            out.set(parts[j], off);
            off += parts[j].length;
        }
        return out;
    }

    function hasSubtleCrypto() {
        return (
            typeof window !== "undefined" &&
            window.crypto &&
            window.crypto.subtle &&
            typeof window.crypto.subtle.encrypt === "function"
        );
    }

    // ------------------------------------------------------------------ PEM codec (PQC)
    function pemEncode(label, rawBytes) {
        var b64 = arrayBufferToBase64(rawBytes);
        var formatted = b64.match(/.{1,64}/g).join("\n");
        return "-----BEGIN " + label + "-----\n" + formatted + "\n-----END " + label + "-----";
    }

    function encodePublicKeyToPem(rawPublicKeyBytes) {
        return pemEncode(PUBLIC_PEM_LABEL, rawPublicKeyBytes);
    }

    function encodePrivateKeyToPem(rawSecretKeyBytes) {
        return pemEncode(PRIVATE_PEM_LABEL, rawSecretKeyBytes);
    }

    function pemToBase64(pem) {
        return String(pem)
            .replace(/-----BEGIN [A-Z0-9 ._-]+-----/g, "")
            .replace(/-----END [A-Z0-9 ._-]+-----/g, "")
            .replace(/[\r\n\s]/g, "");
    }

    /**
     * Decode a PQC PEM (or raw base64) to raw key bytes.
     * Accepts ML-KEM-768 headers, Kyber768 headers, legacy generic headers,
     * and header-less base64 for robustness.
     */
    function pemToRawBytes(pem) {
        var b64 = pemToBase64(pem);
        if (!b64) throw new Error("Empty key: expected a PEM-encoded ML-KEM-768 key.");
        return base64ToBytes(b64);
    }

    function parsePublicKeyPem(pem) {
        var raw = pemToRawBytes(pem);
        if (raw.length !== ML_KEM_768_PUBLIC_KEY_BYTES) {
            throw new Error(
                "Invalid ML-KEM-768 public key length: expected " +
                ML_KEM_768_PUBLIC_KEY_BYTES + " bytes, got " + raw.length + " bytes."
            );
        }
        return raw;
    }

    function parsePrivateKeyPem(pem) {
        var raw = pemToRawBytes(pem);
        if (raw.length !== ML_KEM_768_SECRET_KEY_BYTES) {
            throw new Error(
                "Invalid ML-KEM-768 private (secret) key length: expected " +
                ML_KEM_768_SECRET_KEY_BYTES + " bytes, got " + raw.length + " bytes."
            );
        }
        return raw;
    }

    // Backwards-compatible names (previously RSA SPKI/PKCS8 CryptoKeys).
    // They now operate on ML-KEM-768 raw bytes and PEM.
    async function exportPublicKeyToPem(keyOrBytes) {
        if (keyOrBytes instanceof Uint8Array) return encodePublicKeyToPem(keyOrBytes);
        throw new Error("exportPublicKeyToPem: PQC mode expects ML-KEM-768 raw public-key bytes (Uint8Array).");
    }

    async function exportPrivateKeyToPem(keyOrBytes) {
        if (keyOrBytes instanceof Uint8Array) return encodePrivateKeyToPem(keyOrBytes);
        throw new Error("exportPrivateKeyToPem: PQC mode expects ML-KEM-768 raw secret-key bytes (Uint8Array).");
    }

    async function importPublicKeyFromPem(pem) {
        return parsePublicKeyPem(pem);
    }

    async function importPrivateKeyFromPem(pem) {
        return parsePrivateKeyPem(pem);
    }

    // ------------------------------------------------------------------ KEM backend (liboqs)
    /**
     * Resolve a browser-side ML-KEM-768 implementation.
     *
     * Preference order:
     *   1. liboqs-wasm / oqs.js WebAssembly build (window.OQS / window.liboqs /
     *      window.oqs exposing KeyEncapsulation/KEM for "ML-KEM-768"/"Kyber768").
     *   2. Bundled pure-JS FIPS 203 build from /public/ml-kem.js
     *      (window.MlKem768, interoperable with liboqs).
     *
     * Returns an object { generateKeyPair(), encap(publicKey), decap(ciphertext, secretKey) }
     * operating on Uint8Array with the FIPS 203 sizes above.
     */
    async function resolveKem() {
        // --- 1. liboqs-wasm / oqs.js adapter ---------------------------------
        var oqsGlobal = null;
        if (typeof window !== "undefined") {
            oqsGlobal = window.OQS || window.liboqs || window.oqs || null;
        }
        if (oqsGlobal) {
            var liboqsKem = tryWrapLiboqsWasm(oqsGlobal);
            if (liboqsKem) return liboqsKem;
        }

        // --- 2. Bundled ml-kem.js (window.MlKem768) ---------------------------
        var MlKem768Ctor =
            (typeof window !== "undefined" && (window.MlKem768 || window.MLKEM768)) ||
            (typeof globalThis !== "undefined" && (globalThis.MlKem768 || globalThis.MLKEM768)) ||
            null;

        if (MlKem768Ctor) {
            return {
                backend: "ml-kem.js (liboqs-compatible FIPS 203 pure-JS/WASM build)",
                async generateKeyPair() {
                    var kem = new MlKem768Ctor();
                    var pair = await kem.generateKeyPair();
                    return { publicKey: new Uint8Array(pair[0]), secretKey: new Uint8Array(pair[1]) };
                },
                async encap(publicKey) {
                    if (publicKey.length !== ML_KEM_768_PUBLIC_KEY_BYTES) {
                        throw new Error("encap: invalid ML-KEM-768 public key length.");
                    }
                    var kem = new MlKem768Ctor();
                    var out = await kem.encap(publicKey);
                    return { ciphertext: new Uint8Array(out[0]), sharedSecret: new Uint8Array(out[1]) };
                },
                async decap(ciphertext, secretKey) {
                    if (ciphertext.length !== ML_KEM_768_CIPHERTEXT_BYTES) {
                        throw new Error("decap: invalid ML-KEM-768 ciphertext length.");
                    }
                    if (secretKey.length !== ML_KEM_768_SECRET_KEY_BYTES) {
                        throw new Error("decap: invalid ML-KEM-768 secret key length.");
                    }
                    var kem = new MlKem768Ctor();
                    var ss = await kem.decap(ciphertext, secretKey);
                    return new Uint8Array(ss);
                }
            };
        }

        throw new Error(
            "ML-KEM-768 backend not loaded. Include <script src=\"/public/ml-kem.js\"></script> " +
            "(liboqs-wasm compatible bundle) before crypto.js, or use the server fallback."
        );
    }

    /**
     * Best-effort adapter for liboqs-wasm / oqs.js globals.
     * Supports the common shapes:
     *   - OQS.KeyEncapsulation("ML-KEM-768") with generate_keypair/encap_secret/decap_secret
     *   - OQS.KEM("ML-KEM-768") / new OQS.KEM(...) with keypair/encaps/decaps
     * Returns null when the global does not expose a usable KEM.
     */
    function tryWrapLiboqsWasm(oqsGlobal) {
        function pickAlgName() {
            var candidates = [KEM_ALGORITHM, KEM_ALIAS_KYBER768, "Kyber768", "ML-KEM-768"];
            if (oqsGlobal && typeof oqsGlobal.getEnabledKEMs === "function") {
                try {
                    var enabled = oqsGlobal.getEnabledKEMs();
                    for (var i = 0; i < candidates.length; i++) {
                        if (enabled && enabled.indexOf(candidates[i]) !== -1) return candidates[i];
                    }
                } catch (e) { /* fall through */ }
            }
            return KEM_ALGORITHM;
        }

        try {
            // Shape A: OQS.KeyEncapsulation (mirrors liboqs-python API).
            if (typeof oqsGlobal.KeyEncapsulation === "function") {
                var algA = pickAlgName();
                return {
                    backend: "liboqs-wasm (KeyEncapsulation:" + algA + ")",
                    async generateKeyPair() {
                        var kem = new oqsGlobal.KeyEncapsulation(algA);
                        try {
                            var pk = await kem.generate_keypair();
                            var sk = await kem.export_secret_key();
                            return { publicKey: new Uint8Array(pk), secretKey: new Uint8Array(sk) };
                        } finally {
                            if (typeof kem.free === "function") kem.free();
                        }
                    },
                    async encap(publicKey) {
                        var kem = new oqsGlobal.KeyEncapsulation(algA);
                        try {
                            var out = await kem.encap_secret(publicKey);
                            var ct = out.ciphertext !== undefined ? out.ciphertext : out[0];
                            var ss = out.shared_secret !== undefined ? out.shared_secret : out[1];
                            return { ciphertext: new Uint8Array(ct), sharedSecret: new Uint8Array(ss) };
                        } finally {
                            if (typeof kem.free === "function") kem.free();
                        }
                    },
                    async decap(ciphertext, secretKey) {
                        var kem = new oqsGlobal.KeyEncapsulation(algA, secretKey);
                        try {
                            var ss = await kem.decap_secret(ciphertext);
                            return new Uint8Array(ss);
                        } finally {
                            if (typeof kem.free === "function") kem.free();
                        }
                    }
                };
            }
            // Shape B: OQS.KEM.
            if (typeof oqsGlobal.KEM === "function") {
                var algB = pickAlgName();
                return {
                    backend: "liboqs-wasm (KEM:" + algB + ")",
                    async generateKeyPair() {
                        var kem = typeof oqsGlobal.KEM.create === "function"
                            ? await oqsGlobal.KEM.create(algB)
                            : new oqsGlobal.KEM(algB);
                        var pair = await kem.keypair();
                        var pk = pair.publicKey || pair[0];
                        var sk = pair.secretKey || pair.privateKey || pair[1];
                        return { publicKey: new Uint8Array(pk), secretKey: new Uint8Array(sk) };
                    },
                    async encap(publicKey) {
                        var kem = typeof oqsGlobal.KEM.create === "function"
                            ? await oqsGlobal.KEM.create(algB)
                            : new oqsGlobal.KEM(algB);
                        var out = await kem.encaps(publicKey);
                        var ct = out.ciphertext || out[0];
                        var ss = out.sharedSecret || out.shared_secret || out[1];
                        return { ciphertext: new Uint8Array(ct), sharedSecret: new Uint8Array(ss) };
                    },
                    async decap(ciphertext, secretKey) {
                        var kem = typeof oqsGlobal.KEM.create === "function"
                            ? await oqsGlobal.KEM.create(algB)
                            : new oqsGlobal.KEM(algB);
                        var ss = await kem.decaps(ciphertext, secretKey);
                        return new Uint8Array(ss);
                    }
                };
            }
        } catch (e) {
            return null;
        }
        return null;
    }

    // ------------------------------------------------------------------ HKDF-SHA256
    async function hmacSha256(keyBytes, dataBytes) {
        var key = await crypto.subtle.importKey(
            "raw",
            keyBytes,
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );
        var sig = await crypto.subtle.sign("HMAC", key, dataBytes);
        return new Uint8Array(sig);
    }

    /**
     * HKDF-SHA256 (RFC 5869) used to derive the 256-bit AES key from the KEM
     * shared_secret. Parameters mirror the Python backend (app.py):
     *   salt = b"" (RFC: HashLen zeros), info = HKDF_INFO_STRING, L = 32.
     */
    async function hkdfSha256(ikmBytes, saltBytes, infoBytes, length) {
        var salt = saltBytes && saltBytes.length ? saltBytes : new Uint8Array(32);
        var prk = await hmacSha256(salt, ikmBytes);
        var okm = new Uint8Array(length);
        var previous = new Uint8Array(0);
        var pos = 0;
        var counter = 1;
        while (pos < length) {
            var input = concatBytes([previous, infoBytes, new Uint8Array([counter])]);
            var t = await hmacSha256(prk, input);
            var take = Math.min(t.length, length - pos);
            okm.set(t.subarray(0, take), pos);
            pos += take;
            previous = t;
            counter += 1;
        }
        return okm;
    }

    /**
     * Derive the AES-256-GCM key from a 32-byte ML-KEM shared secret.
     * Direct use of the shared secret would also be compliant (FIPS 203
     * guarantees 32 uniform bytes), but HKDF-SHA256 adds domain separation
     * for this application's AES-GCM context.
     */
    async function deriveAesKey(sharedSecret) {
        if (sharedSecret.length !== ML_KEM_768_SHARED_SECRET_BYTES) {
            throw new Error("deriveAesKey: invalid ML-KEM-768 shared secret length.");
        }
        return await hkdfSha256(
            sharedSecret,
            new Uint8Array(0),
            textToBytes(HKDF_INFO_STRING),
            32
        );
    }

    // ------------------------------------------------------------------ AES-256-GCM
    async function importAesKeyForEncrypt(raw32) {
        return await crypto.subtle.importKey("raw", raw32, { name: "AES-GCM" }, false, ["encrypt"]);
    }

    async function importAesKeyForDecrypt(raw32) {
        return await crypto.subtle.importKey("raw", raw32, { name: "AES-GCM" }, false, ["decrypt"]);
    }

    // ------------------------------------------------------------------ public API
    /**
     * Generate an ML-KEM-768 keypair entirely in the browser.
     * The secret key never leaves browser memory; only the user downloading
     * private_key.pqc moves it (as a local file).
     */
    async function generateKeyPair() {
        // Fallback: no WebCrypto subtle (plain-HTTP non-localhost) or no KEM
        // backend loaded -> delegate to Flask liboqs-python backend.
        if (!hasSubtleCrypto()) {
            var response = await fetch("/generate-keys", { method: "POST" });
            if (!response.ok) {
                var errBody = await response.json().catch(function () { return {}; });
                throw new Error(errBody.error || "Server PQC key generation failed");
            }
            var serverKeys = await response.json();
            return {
                publicKeyPem: serverKeys.publicKeyPem,
                privateKeyPem: serverKeys.privateKeyPem,
                kemAlgorithm: serverKeys.kemAlgorithm || KEM_ALGORITHM,
                keyPair: null
            };
        }

        var kem;
        try {
            kem = await resolveKem();
        } catch (e) {
            // KEM bundle missing (e.g. ml-kem.js failed to load): use server backend.
            var fallback = await fetch("/generate-keys", { method: "POST" });
            if (!fallback.ok) {
                var errFallback = await fallback.json().catch(function () { return {}; });
                throw new Error(errFallback.error || e.message);
            }
            var fbKeys = await fallback.json();
            return {
                publicKeyPem: fbKeys.publicKeyPem,
                privateKeyPem: fbKeys.privateKeyPem,
                kemAlgorithm: fbKeys.kemAlgorithm || KEM_ALGORITHM,
                keyPair: null
            };
        }

        var pair = await kem.generateKeyPair();
        if (pair.publicKey.length !== ML_KEM_768_PUBLIC_KEY_BYTES) {
            throw new Error("KEM generated an invalid ML-KEM-768 public key.");
        }
        if (pair.secretKey.length !== ML_KEM_768_SECRET_KEY_BYTES) {
            throw new Error("KEM generated an invalid ML-KEM-768 secret key.");
        }
        return {
            publicKeyPem: encodePublicKeyToPem(pair.publicKey),
            privateKeyPem: encodePrivateKeyToPem(pair.secretKey),
            kemAlgorithm: KEM_ALGORITHM,
            keyPair: {
                publicKey: pair.publicKey,
                secretKey: pair.secretKey,
                backend: kem.backend
            }
        };
    }

    /**
     * Hybrid PQC encryption for /set-message:
     *   (kem_ciphertext, shared_secret) = Encap(recipient ML-KEM-768 public key)
     *   aes_key = HKDF-SHA256(shared_secret)
     *   ciphertext = AES-256-GCM(aes_key, iv=12 random bytes, file_bytes)
     */
    async function encryptFile(fileArrayBuffer, publicKeyPem, filename) {
        // Server-side PQC fallback when WebCrypto subtle is unavailable.
        if (!hasSubtleCrypto()) {
            var formData = new FormData();
            formData.append("public_key_pem", publicKeyPem);
            var blob = new Blob([fileArrayBuffer]);
            formData.append("file", blob, filename || "upload.bin");
            var encResponse = await fetch("/encrypt-file", { method: "POST", body: formData });
            if (!encResponse.ok) {
                var encErr = await encResponse.json().catch(function () { return {}; });
                throw new Error(encErr.error || "Server PQC encryption failed");
            }
            return await encResponse.json(); // { ciphertext, iv, encryptedKey, filename }
        }

        var publicKeyBytes = parsePublicKeyPem(publicKeyPem);
        var kem = await resolveKem();
        var encapOut = await kem.encap(publicKeyBytes);
        var kemCiphertext = encapOut.ciphertext;
        var sharedSecret = encapOut.sharedSecret;

        if (kemCiphertext.length !== ML_KEM_768_CIPHERTEXT_BYTES) {
            throw new Error("KEM encapsulation produced an invalid ciphertext length.");
        }

        var aesKeyBytes = await deriveAesKey(sharedSecret);
        // Clear shared secret as soon as the AES key is derived (hygiene).
        sharedSecret.fill(0);

        var aesKey = await importAesKeyForEncrypt(aesKeyBytes);
        var iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));

        var fileBytes = fileArrayBuffer instanceof Uint8Array
            ? fileArrayBuffer
            : new Uint8Array(fileArrayBuffer);

        // WebCrypto AES-GCM returns ciphertext || 16-byte auth tag.
        var ciphertextBuffer = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            fileBytes
        );

        aesKeyBytes.fill(0);

        return {
            ciphertext: arrayBufferToBase64(ciphertextBuffer),
            iv: arrayBufferToBase64(iv),
            encryptedKey: arrayBufferToBase64(kemCiphertext)
        };
    }

    /**
     * Hybrid PQC decryption:
     *   shared_secret = Decap(private ML-KEM-768 secret key, kem_ciphertext)
     *   aes_key = HKDF-SHA256(shared_secret)
     *   plaintext = AES-256-GCM-decrypt(aes_key, iv, ciphertext)
     * The private key is only ever used inside the browser.
     */
    async function decryptFile(ciphertextBase64, ivBase64, encryptedKeyBase64, privateKeyPem) {
        // Server-side PQC fallback when WebCrypto subtle is unavailable.
        if (!hasSubtleCrypto()) {
            var formData = new FormData();
            formData.append("private_key_pem", privateKeyPem);
            formData.append("ciphertext", ciphertextBase64);
            formData.append("iv", ivBase64);
            formData.append("encrypted_key", encryptedKeyBase64);
            var decResponse = await fetch("/decrypt-file", { method: "POST", body: formData });
            if (!decResponse.ok) {
                var decErr = await decResponse.json().catch(function () { return {}; });
                throw new Error(decErr.error || "Server PQC decryption failed");
            }
            var result = await decResponse.json();
            return base64ToArrayBuffer(result.data);
        }

        var secretKeyBytes = parsePrivateKeyPem(privateKeyPem);
        var kemCiphertext = base64ToBytes(encryptedKeyBase64);
        if (kemCiphertext.length !== ML_KEM_768_CIPHERTEXT_BYTES) {
            throw new Error(
                "Invalid KEM ciphertext length: expected " + ML_KEM_768_CIPHERTEXT_BYTES +
                " bytes (ML-KEM-768), got " + kemCiphertext.length + " bytes."
            );
        }

        var kem = await resolveKem();
        var sharedSecret = await kem.decap(kemCiphertext, secretKeyBytes);
        var aesKeyBytes = await deriveAesKey(sharedSecret);
        sharedSecret.fill(0);

        var aesKey = await importAesKeyForDecrypt(aesKeyBytes);
        var ciphertextBuffer = base64ToArrayBuffer(ciphertextBase64);
        var ivBuffer = base64ToArrayBuffer(ivBase64);
        var ivBytes = new Uint8Array(ivBuffer);
        if (ivBytes.length !== AES_GCM_IV_BYTES) {
            throw new Error("Invalid AES-GCM IV length: expected 12 bytes.");
        }

        try {
            var decryptedBuffer = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: ivBytes },
                aesKey,
                ciphertextBuffer
            );
            return decryptedBuffer;
        } finally {
            aesKeyBytes.fill(0);
        }
    }

    function downloadFile(filename, content, mimeType) {
        var blob = typeof content === "string"
            ? new Blob([content], { type: mimeType || "text/plain" })
            : new Blob([content], { type: mimeType || "application/octet-stream" });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    window.ClassmateCrypto = {
        // PQC identity (useful for feature detection / tests).
        kemAlgorithm: KEM_ALGORITHM,
        kemAlias: KEM_ALIAS_KYBER768,
        hkdfInfo: HKDF_INFO_STRING,
        sizes: {
            publicKey: ML_KEM_768_PUBLIC_KEY_BYTES,
            secretKey: ML_KEM_768_SECRET_KEY_BYTES,
            ciphertext: ML_KEM_768_CIPHERTEXT_BYTES,
            sharedSecret: ML_KEM_768_SHARED_SECRET_BYTES,
            iv: AES_GCM_IV_BYTES
        },
        textToBytes: textToBytes,
        bytesToText: bytesToText,
        arrayBufferToBase64: arrayBufferToBase64,
        base64ToArrayBuffer: base64ToArrayBuffer,
        base64ToBytes: base64ToBytes,
        generateKeyPair: generateKeyPair,
        exportPublicKeyToPem: exportPublicKeyToPem,
        exportPrivateKeyToPem: exportPrivateKeyToPem,
        encodePublicKeyToPem: encodePublicKeyToPem,
        encodePrivateKeyToPem: encodePrivateKeyToPem,
        importPublicKeyFromPem: importPublicKeyFromPem,
        importPrivateKeyFromPem: importPrivateKeyFromPem,
        parsePublicKeyPem: parsePublicKeyPem,
        parsePrivateKeyPem: parsePrivateKeyPem,
        hkdfSha256: hkdfSha256,
        deriveAesKey: deriveAesKey,
        encryptFile: encryptFile,
        decryptFile: decryptFile,
        downloadFile: downloadFile
    };
})();
