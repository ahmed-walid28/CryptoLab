/**
 * CryptoLab - Affine Cipher Module
 * Formula: E(x) = (ax + b) mod 26, D(x) = a^-1(x - b) mod 26
 */

window.CryptoLab = window.CryptoLab || {};
window.CryptoLab.ciphers = window.CryptoLab.ciphers || {};

window.CryptoLab.ciphers.affine = {
    id: 'affine',
    name: 'Affine Cipher',
    category: 'classical',
    type: 'Monoalphabetic Linear Substitution Cipher',
    formula: 'E(x) = (a·x + b) mod 26 | D(x) = a⁻¹(x - b) mod 26',
    keyType: 'Key Pair (a, b) where gcd(a, 26) = 1 and 0 ≤ b ≤ 25',
    securityLevel: 'Insecure (Only 12 × 26 = 312 possible keys; easily broken via frequency analysis).',
    purpose: 'Combines multiplicative and additive modular arithmetic into a single transformation.',
    about: {
        description: 'The Affine Cipher is a type of monoalphabetic substitution cipher where each letter in an alphabet is mapped to its numeric equivalent, encrypted using a simple linear mathematical function (ax + b) mod 26, and converted back to a letter. It generalizes both the Caesar cipher (a = 1) and the pure multiplicative cipher (b = 0).',
        advantages: [
            'Expands Caesar key space from 26 to 12 × 26 = 312 distinct keys.',
            'Elegant mathematical structure introducing both modular addition and modular multiplication.',
            'Fast O(n) execution speed.'
        ],
        limitations: [
            'Still a monoalphabetic substitution cipher: preserves all single-letter frequency characteristics.',
            'Easily broken using two known plaintext-ciphertext letter pairs to solve a system of linear congruences.',
            'Key "a" is restricted to integers coprime to 26 (12 valid choices).'
        ],
        history: 'Developed as a formal algebraic generalization of classical substitution ciphers in modern cryptography curricula.'
    },
    example: {
        plaintext: 'AFFINE CIPHER EXAMPLE',
        key: { a: 5, b: 8 }, // a=5 (gcd(5,26)=1, a^-1=21), b=8
        ciphertext: 'IHHWVC KWDPCZ CTIAPLC'
    },

    gcd(a, b) {
        a = Math.abs(a);
        b = Math.abs(b);
        while (b !== 0) {
            const t = b;
            b = a % b;
            a = t;
        }
        return a;
    },

    modInverse(a, m = 26) {
        a = ((a % m) + m) % m;
        for (let x = 1; x < m; x++) {
            if ((a * x) % m === 1) {
                return x;
            }
        }
        return null;
    },

    validateKeys(a, b) {
        const numA = parseInt(a, 10);
        const numB = parseInt(b, 10);

        if (isNaN(numA)) {
            return { valid: false, error: 'Key "a" (multiplicative factor) must be a valid integer.' };
        }
        if (isNaN(numB)) {
            return { valid: false, error: 'Key "b" (additive shift) must be a valid integer.' };
        }

        const normA = ((numA % 26) + 26) % 26;
        const normB = ((numB % 26) + 26) % 26;

        const g = this.gcd(normA, 26);
        if (g !== 1) {
            return {
                valid: false,
                error: `Key "a" = ${numA} is INVALID. gcd(${normA}, 26) = ${g} ≠ 1. Key "a" must be coprime to 26 so that a modular inverse exists. Valid values for "a" mod 26 are: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25.`
            };
        }

        const aInv = this.modInverse(normA, 26);
        return {
            valid: true,
            a: normA,
            b: normB,
            aInv: aInv
        };
    },

    encrypt(text, key, options = {}) {
        let a, b;
        if (typeof key === 'object' && key !== null) {
            a = key.a; b = key.b;
        } else if (typeof key === 'string') {
            const parts = key.split(/[\s,]+/).map(p => p.trim()).filter(Boolean);
            if (parts.length >= 2) {
                a = parts[0]; b = parts[1];
            } else {
                throw new Error('Key must provide both "a" and "b" values (e.g. "5, 8").');
            }
        }

        const keyVal = this.validateKeys(a, b);
        if (!keyVal.valid) {
            throw new Error(keyVal.error);
        }
        if (!text || text.trim() === '') {
            throw new Error('Plaintext input cannot be empty.');
        }

        const kA = keyVal.a;
        const kB = keyVal.b;
        let result = '';
        const steps = [];

        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            const code = char.charCodeAt(0);
            const isUpper = code >= 65 && code <= 90;
            const isLower = code >= 97 && code <= 122;

            if (isUpper || isLower) {
                const base = isUpper ? 65 : 97;
                const p = code - base;
                const c = (kA * p + kB) % 26;
                const transformed = String.fromCharCode(c + base);

                result += transformed;
                steps.push({
                    index: i + 1,
                    original: char,
                    pVal: p,
                    formula: `(${kA} × ${p} + ${kB}) mod 26 = ${c} [${transformed.toUpperCase()}]`,
                    resultChar: transformed,
                    isAlpha: true
                });
            } else {
                result += char;
                steps.push({
                    index: i + 1,
                    original: char,
                    formula: 'Non-alphabetic character (passed unchanged)',
                    resultChar: char,
                    isAlpha: false
                });
            }
        }

        return {
            output: result,
            a: kA,
            b: kB,
            aInv: keyVal.aInv,
            steps: steps,
            summary: `Encrypted using E(x) = (${kA}x + ${kB}) mod 26 with a⁻¹ = ${keyVal.aInv}. Processed ${text.length} characters.`
        };
    },

    decrypt(text, key, options = {}) {
        let a, b;
        if (typeof key === 'object' && key !== null) {
            a = key.a; b = key.b;
        } else if (typeof key === 'string') {
            const parts = key.split(/[\s,]+/).map(p => p.trim()).filter(Boolean);
            if (parts.length >= 2) {
                a = parts[0]; b = parts[1];
            } else {
                throw new Error('Key must provide both "a" and "b" values (e.g. "5, 8").');
            }
        }

        const keyVal = this.validateKeys(a, b);
        if (!keyVal.valid) {
            throw new Error(keyVal.error);
        }
        if (!text || text.trim() === '') {
            throw new Error('Ciphertext input cannot be empty.');
        }

        const kA = keyVal.a;
        const kB = keyVal.b;
        const aInv = keyVal.aInv;
        let result = '';
        const steps = [];

        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            const code = char.charCodeAt(0);
            const isUpper = code >= 65 && code <= 90;
            const isLower = code >= 97 && code <= 122;

            if (isUpper || isLower) {
                const base = isUpper ? 65 : 97;
                const c = code - base;
                const p = (aInv * (((c - kB) % 26) + 26)) % 26;
                const transformed = String.fromCharCode(p + base);

                result += transformed;
                steps.push({
                    index: i + 1,
                    original: char,
                    cVal: c,
                    formula: `${aInv} × (${c} - ${kB}) mod 26 = ${p} [${transformed.toUpperCase()}]`,
                    resultChar: transformed,
                    isAlpha: true
                });
            } else {
                result += char;
                steps.push({
                    index: i + 1,
                    original: char,
                    formula: 'Non-alphabetic character (passed unchanged)',
                    resultChar: char,
                    isAlpha: false
                });
            }
        }

        return {
            output: result,
            a: kA,
            b: kB,
            aInv: aInv,
            steps: steps,
            summary: `Decrypted using D(x) = ${aInv} · (x - ${kB}) mod 26. Processed ${text.length} characters.`
        };
    }
};
