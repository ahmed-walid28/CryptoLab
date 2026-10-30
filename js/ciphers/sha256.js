/**
 * CryptoLab - SHA-256 Cryptographic Hash Module
 * Implements NIST FIPS 180-4 SHA-256 via Web Crypto API with Integrity & Avalanche Analysis
 */

window.CryptoLab = window.CryptoLab || {};
window.CryptoLab.ciphers = window.CryptoLab.ciphers || {};

window.CryptoLab.ciphers.sha256 = {
    id: 'sha256',
    name: 'SHA-256 Cryptographic Hash',
    category: 'modern',
    type: 'Cryptographic Hash Function (One-Way Digest)',
    formula: 'H = SHA-256(M) -> 256-bit (32-byte / 64-hex character) Fixed Digest',
    keyType: 'Keyless (Deterministic One-Way Function)',
    securityLevel: 'Cryptographically Secure (128-bit collision resistance, 256-bit preimage resistance).',
    purpose: 'Data integrity verification, password storage (with salt), digital signatures, blockchain proof-of-work.',
    about: {
        description: 'Designed by the United States National Security Agency (NSA) and published by NIST in 2001 under FIPS 180-4, SHA-256 (Secure Hash Algorithm 256-bit) is a member of the SHA-2 family. It processes arbitrary-length input messages through 64 rounds of bitwise operations (Ch, Maj, Σ, σ) to produce a unique, fixed-size 256-bit fingerprint.',
        advantages: [
            'One-Way Preimage Resistance: Mathematically infeasible to reconstruct the original message from its hash.',
            'Strong Collision Resistance: Practically impossible to find two distinct inputs that produce the identical hash output.',
            'Pronounced Avalanche Effect: Altering even a single bit of the input changes approximately 50% of the output bits randomly.',
            'Deterministic and lightning-fast verification.'
        ],
        limitations: [
            'One-Way Function: NOT an encryption algorithm; data CANNOT be decrypted or recovered.',
            'Susceptible to Length Extension Attacks when used in naive MAC constructions (mitigated by HMAC-SHA256).',
            'Raw hashing without salt/key stretching (like bcrypt/argon2) is vulnerable to rainbow table lookups for simple passwords.'
        ],
        history: 'Replaced SHA-1 after collision attacks were demonstrated against SHA-1 in 2017 (SHAttered attack).'
    },
    example: {
        plaintext: 'The quick brown fox jumps over the lazy dog',
        ciphertext: 'd7a8fbb307d7809469ca9abb0082e4f8d5651e46d3cdb762d02d0bf37c9e592e'
    },

    bufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    /**
     * Compute SHA-256 hash using Web Crypto API
     */
    async hash(text) {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error('Web Crypto API is not supported in this browser.');
        }

        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
        const hex = this.bufferToHex(hashBuffer);

        return {
            output: hex,
            hex: hex,
            byteLength: hashBuffer.byteLength,
            bitLength: hashBuffer.byteLength * 8,
            summary: `Computed 256-bit (64 hex characters) cryptographic digest for input of length ${text.length} character(s).`
        };
    },

    /**
     * Compare input text hash against expected target hash (Integrity Check)
     */
    async verify(text, expectedHash) {
        const computed = await this.hash(text);
        const cleanExpected = (expectedHash || '').trim().toLowerCase();
        const matches = computed.hex.toLowerCase() === cleanExpected;

        return {
            computedHash: computed.hex,
            expectedHash: cleanExpected,
            verified: matches,
            message: matches
                ? 'INTEGRITY VERIFIED: The hash exactly matches the expected digest. The data is intact and authentic.'
                : 'INTEGRITY MISMATCH: The computed hash does NOT match the expected digest. The data has been altered or corrupted!'
        };
    },

    /**
     * Demonstrate the Avalanche Effect: Compare Hash(text) with Hash(text with 1 character modified)
     */
    async testAvalanche(text) {
        if (!text || text.length === 0) {
            text = 'Security';
        }

        // Alter 1 character
        const modifiedText = text.slice(0, -1) + (text.slice(-1) === '!' ? '?' : '!');
        const hash1 = (await this.hash(text)).hex;
        const hash2 = (await this.hash(modifiedText)).hex;

        // Count bit differences (Hamming Distance)
        let bitDifferences = 0;
        for (let i = 0; i < hash1.length; i += 2) {
            const b1 = parseInt(hash1.substr(i, 2), 16);
            const b2 = parseInt(hash2.substr(i, 2), 16);
            let xor = b1 ^ b2;
            while (xor > 0) {
                if (xor & 1) bitDifferences++;
                xor >>= 1;
            }
        }

        const percentage = ((bitDifferences / 256) * 100).toFixed(2);

        return {
            originalText: text,
            modifiedText: modifiedText,
            hash1: hash1,
            hash2: hash2,
            bitDifferences: bitDifferences,
            totalBits: 256,
            percentage: percentage
        };
    }
};
