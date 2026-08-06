(function () {
    function textToBytes(text) {
        return new TextEncoder().encode(text);
    }

    function bytesToText(bytes) {
        return new TextDecoder().decode(bytes);
    }

    function bytesToBase64(bytes) {
        let binary = "";
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    function base64ToBytes(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    async function hashPassword(password) {
        return crypto.subtle.digest("SHA-256", textToBytes(password));
    }

    async function importAesKeyFromHash(hashBuffer) {
        return crypto.subtle.importKey("raw", hashBuffer, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    }

    async function importAesKeyFromPassword(password) {
        const hash = await hashPassword(password);
        return crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    }

    function randomIv() {
        return crypto.getRandomValues(new Uint8Array(12));
    }

    async function encryptMessage(message, password) {
        const hash = await hashPassword(password);
        const key = await importAesKeyFromHash(hash);
        const iv = randomIv();
        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            textToBytes(message)
        );

        return {
            ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
            iv: bytesToBase64(iv)
        };
    }

    async function decryptMessage(ciphertextBase64, ivBase64, password) {
        const hash = await hashPassword(password);
        const key = await importAesKeyFromHash(hash);
        const plaintext = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: base64ToBytes(ivBase64) },
            key,
            base64ToBytes(ciphertextBase64)
        );

        return bytesToText(new Uint8Array(plaintext));
    }

    window.ClassmateCrypto = {
        textToBytes,
        bytesToText,
        bytesToBase64,
        base64ToBytes,
        hashPassword,
        importAesKeyFromHash,
        importAesKeyFromPassword,
        randomIv,
        encryptMessage,
        decryptMessage
    };
})();
