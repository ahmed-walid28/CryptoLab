/**
 * CryptoLab - Modern AES Module (Advanced Encryption Standard)
 * Implements AES-GCM (Galois/Counter Mode) via Browser-Native Web Crypto API
 */

window.CryptoLab = window.CryptoLab || {};
window.CryptoLab.ciphers = window.CryptoLab.ciphers || {};

window.CryptoLab.ciphers.aes = {
    id: 'aes',
    name: 'AES (Advanced Encryption Standard)',
    category: 'modern',
    type: 'Symmetric Block Cipher (AEAD Mode: AES-GCM)',
    formula: 'C, Tag = AES-GCM-Encrypt(K, IV, Plaintext) | P = AES-GCM-Decrypt(K, IV, C, Tag)',
    keyType: 'Symmetric Key: 128-bit, 192-bit, or 256-bit (or PBKDF2 Passphrase)',
    securityLevel: 'Current Global Gold Standard (NIST FIPS 197). Quantum-resistant with 256-bit keys.',
    purpose: 'Standard symmetric cipher used globally for protecting classified data, TLS/HTTPS, and disk encryption.',
    about: {
        description: 'Adopted by NIST in 2001 to replace DES, the Advanced Encryption Standard (AES) is a symmetric block cipher (Rijndael algorithm) operating on 128-bit blocks through multiple rounds of substitution and permutation (10 rounds for 128-bit, 12 for 192-bit, 14 for 256-bit). In Galois/Counter Mode (GCM), it simultaneously provides data confidentiality and cryptographic authenticity (AEAD).',
        advantages: [
            'Extremely strong security: no practical cryptanalytic attacks exist against full-round AES.',
            'Hardware acceleration (AES-NI) available on modern CPUs enabling gigabytes/second throughput.',
            'AES-GCM mode detects any message tampering or transmission errors via a 128-bit authentication tag.',
            'Uses a 96-bit Initialization Vector (IV/Nonce) to ensure identical plaintexts produce completely different ciphertexts.'
        ],
        limitations: [
            'Symmetric key distribution problem: both sender and recipient must share the secret key beforehand.',
            'Reusing the same (Key, IV) pair in GCM mode catastrophically destroys authenticity and compromises confidentiality.',
            'Requires secure key management and generation.'
        ],
        history: 'Selected through a five-year open international competition organized by NIST, won by Belgian cryptographers Joan Daemen and Vincent Rijmen.'
    },
    example: {
        plaintext: 'Confidential University Examination Records: CS-402 Top Secret',
        key: 'generate' // indicator to auto-generate
    },

    // Utility: ArrayBuffer to Hex string
    bufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    // Utility: Hex string to Uint8Array
    hexToBuffer(hexString) {
        const clean = hexString.replace(/[^0-9a-fA-F]/g, '');
        if (clean.length % 2 !== 0) {
            throw new Error('Hex string must have an even length.');
        }
        const bytes = new Uint8Array(clean.length / 2);
        for (let i = 0; i < clean.length; i += 2) {
            bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
        }
        return bytes;
    },

    // Utility: ArrayBuffer to Base64 string
    bufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    },

    // Utility: Base64 string to Uint8Array
    base64ToBuffer(base64) {
        const binary = window.atob(base64.trim());
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    },

    /**
     * Generate a new random AES-GCM CryptoKey
     */
    async generateKey(lengthBits = 256) {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error('Web Crypto API is not supported in this browser environment.');
        }
        const key = await window.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: lengthBits },
            true,
            ['encrypt', 'decrypt']
        );
        const raw = await window.crypto.subtle.exportKey('raw', key);
        return {
            cryptoKey: key,
            hex: this.bufferToHex(raw),
            base64: this.bufferToBase64(raw),
            length: lengthBits
        };
    },

    /**
     * Import a raw key from Hex, Base64, or derive from Passphrase
     */
    async importKey(keyInput, lengthBits = 256) {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error('Web Crypto API is not supported in this browser environment.');
        }

        const trimmed = (keyInput || '').trim();
        if (!trimmed) {
            throw new Error('AES Key or Passphrase is required.');
        }

        // Check if raw hex of appropriate length (32, 48, or 64 hex chars = 16, 24, 32 bytes)
        const isHex = /^[0-9a-fA-F]+$/.test(trimmed);
        if (isHex && (trimmed.length === 32 || trimmed.length === 48 || trimmed.length === 64)) {
            const rawBytes = this.hexToBuffer(trimmed);
            const cryptoKey = await window.crypto.subtle.importKey(
                'raw',
                rawBytes,
                { name: 'AES-GCM' },
                true,
                ['encrypt', 'decrypt']
            );
            return { cryptoKey, rawBytes, format: 'Raw Hex Key' };
        }

        // Derive key from passphrase via PBKDF2
        const encoder = new TextEncoder();
        const passphraseBytes = encoder.encode(trimmed);
        const salt = encoder.encode('CryptoLab-Static-Salt-2026'); // Static deterministic salt for educational reproduction
        const baseKey = await window.crypto.subtle.importKey(
            'raw',
            passphraseBytes,
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        const cryptoKey = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            baseKey,
            { name: 'AES-GCM', length: lengthBits },
            true,
            ['encrypt', 'decrypt']
        );

        const exported = await window.crypto.subtle.exportKey('raw', cryptoKey);
        return {
            cryptoKey,
            rawBytes: new Uint8Array(exported),
            format: 'PBKDF2 (100,000 rounds of SHA-256 derived key)'
        };
    },

    /**
     * Encrypt Plaintext using AES-GCM (96-bit IV)
     */
    async encrypt(plaintext, keyInput, options = {}) {
        if (!plaintext || plaintext.trim() === '') {
            throw new Error('Plaintext input cannot be empty.');
        }

        const lengthBits = options.keyLength || 256;
        const keyData = await this.importKey(keyInput, lengthBits);

        // Generate 12-byte (96-bit) cryptographic random IV
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoder = new TextEncoder();
        const dataBytes = encoder.encode(plaintext);

        // Perform AES-GCM encryption
        const encryptedBuffer = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128 // 128-bit authentication tag
            },
            keyData.cryptoKey,
            dataBytes
        );

        // The encryptedBuffer contains Ciphertext + 16-byte Auth Tag
        const encryptedBytes = new Uint8Array(encryptedBuffer);
        const ciphertextLen = encryptedBytes.length - 16;
        const cipherOnlyBytes = encryptedBytes.slice(0, ciphertextLen);
        const tagBytes = encryptedBytes.slice(ciphertextLen);

        // Pack full payload: [12-byte IV] + [Ciphertext + Tag]
        const fullPayload = new Uint8Array(iv.length + encryptedBytes.length);
        fullPayload.set(iv, 0);
        fullPayload.set(encryptedBytes, iv.length);

        const payloadBase64 = this.bufferToBase64(fullPayload.buffer);
        const payloadHex = this.bufferToHex(fullPayload.buffer);

        return {
            output: payloadBase64,
            payloadBase64: payloadBase64,
            payloadHex: payloadHex,
            keyHex: this.bufferToHex(keyData.rawBytes.buffer),
            ivHex: this.bufferToHex(iv.buffer),
            ciphertextHex: this.bufferToHex(cipherOnlyBytes.buffer),
            tagHex: this.bufferToHex(tagBytes.buffer),
            keyDerivation: keyData.format,
            summary: `AES-${lengthBits}-GCM Encrypted successfully. 96-bit random IV and 128-bit GCM Authentication Tag generated.`
        };
    },

    /**
     * Decrypt Payload using AES-GCM
     */
    async decrypt(payloadInput, keyInput, options = {}) {
        if (!payloadInput || payloadInput.trim() === '') {
            throw new Error('Ciphertext payload input cannot be empty.');
        }

        const lengthBits = options.keyLength || 256;
        const keyData = await this.importKey(keyInput, lengthBits);

        let payloadBytes;
        const trimmed = payloadInput.trim();

        // Check if Hex or Base64 format
        if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
            payloadBytes = this.hexToBuffer(trimmed);
        } else {
            try {
                payloadBytes = this.base64ToBuffer(trimmed);
            } catch (e) {
                throw new Error('Invalid ciphertext format. Must be Base64 or Hex encoded AES-GCM bundle.');
            }
        }

        if (payloadBytes.length < 12 + 16) {
            throw new Error('Payload too short. AES-GCM bundle requires at least 12 bytes IV + 16 bytes Auth Tag.');
        }

        // Extract 12-byte IV and the encrypted body
        const iv = payloadBytes.slice(0, 12);
        const encryptedData = payloadBytes.slice(12);

        try {
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128
                },
                keyData.cryptoKey,
                encryptedData
            );

            const decoder = new TextDecoder();
            const plaintext = decoder.decode(decryptedBuffer);

            return {
                output: plaintext,
                ivHex: this.bufferToHex(iv.buffer),
                keyDerivation: keyData.format,
                summary: `AES-${lengthBits}-GCM Decrypted & Authenticated successfully. Authentication tag verified perfectly.`
            };
        } catch (err) {
            throw new Error('Decryption Failed: Authentication Tag verification failed or incorrect key. The ciphertext may have been tampered with or corrupted.');
        }
    }
};
