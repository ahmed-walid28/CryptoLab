/**
 * CryptoLab - Caesar Cipher Module
 * Formula: C = (P + K) mod 26, P = (C - K) mod 26
 */

window.CryptoLab = window.CryptoLab || {};
window.CryptoLab.ciphers = window.CryptoLab.ciphers || {};

window.CryptoLab.ciphers.caesar = {
    id: 'caesar',
    name: 'Caesar Cipher',
    category: 'classical',
    type: 'Monoalphabetic Substitution Cipher',
    formula: 'C = (P + K) mod 26 | P = (C - K) mod 26',
    keyType: 'Integer Shift (0 - 25)',
    securityLevel: 'Insecure (Easily broken via frequency analysis or brute force of 25 shifts)',
    purpose: 'Educational introduction to substitution ciphers and modular arithmetic.',
    about: {
        description: 'The Caesar Cipher is one of the earliest and simplest known encryption techniques, named after Julius Caesar who used it to communicate securely with his generals. It operates by replacing each letter in the plaintext with a letter a fixed number of positions down the alphabet.',
        advantages: [
            'Extremely simple to understand and implement manually or in code.',
            'Forms the foundational basis for understanding modular arithmetic in cryptography.',
            'Minimal computational complexity: O(n) time and O(1) auxiliary space.'
        ],
        limitations: [
            'Tiny key space of only 25 non-trivial keys; vulnerable to instantaneous brute-force search.',
            'Preserves exact letter frequency patterns of natural language (E, T, A remain most frequent).',
            'Completely insecure for protecting any sensitive data.'
        ],
        history: 'Used by the Roman military circa 50 BC with a traditional shift of 3 (A -> D).'
    },
    example: {
        plaintext: 'HELLO CRYPTOGRAPHY WORLD',
        key: '3',
        ciphertext: 'KHOOR FUBSWRJUDSKB ZRUOG'
    },

    validateKey(key) {
        if (key === '' || key === null || key === undefined) {
            return { valid: false, error: 'Shift key is required. Please enter an integer.' };
        }
        const shift = parseInt(key, 10);
        if (isNaN(shift)) {
            return { valid: false, error: 'Shift key must be a valid integer.' };
        }
        const normalizedShift = ((shift % 26) + 26) % 26;
        return { valid: true, shift: normalizedShift, rawShift: shift };
    },

    encrypt(text, key, options = {}) {
        const keyValidation = this.validateKey(key);
        if (!keyValidation.valid) {
            throw new Error(keyValidation.error);
        }
        if (!text || text.trim() === '') {
            throw new Error('Plaintext input cannot be empty.');
        }

        const k = keyValidation.shift;
        let result = '';
        const steps = [];

        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            const code = char.charCodeAt(0);

            if (code >= 65 && code <= 90) { // Uppercase A-Z
                const p = code - 65;
                const c = (p + k) % 26;
                const transformed = String.fromCharCode(c + 65);
                result += transformed;
                steps.push({
                    index: i + 1,
                    original: char,
                    pVal: p,
                    formula: `(${p} + ${k}) mod 26 = ${c}`,
                    resultChar: transformed,
                    isAlpha: true
                });
            } else if (code >= 97 && code <= 122) { // Lowercase a-z
                const p = code - 97;
                const c = (p + k) % 26;
                const transformed = String.fromCharCode(c + 97);
                result += transformed;
                steps.push({
                    index: i + 1,
                    original: char,
                    pVal: p,
                    formula: `(${p} + ${k}) mod 26 = ${c}`,
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
            steps: steps,
            summary: `Shifted by ${k} position(s) (mod 26). Processed ${text.length} characters.`
        };
    },

    decrypt(text, key, options = {}) {
        const keyValidation = this.validateKey(key);
        if (!keyValidation.valid) {
            throw new Error(keyValidation.error);
        }
        if (!text || text.trim() === '') {
            throw new Error('Ciphertext input cannot be empty.');
        }

        const k = keyValidation.shift;
        let result = '';
        const steps = [];

        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            const code = char.charCodeAt(0);

            if (code >= 65 && code <= 90) { // Uppercase A-Z
                const c = code - 65;
                const p = (c - k + 26) % 26;
                const transformed = String.fromCharCode(p + 65);
                result += transformed;
                steps.push({
                    index: i + 1,
                    original: char,
                    cVal: c,
                    formula: `(${c} - ${k} + 26) mod 26 = ${p}`,
                    resultChar: transformed,
                    isAlpha: true
                });
            } else if (code >= 97 && code <= 122) { // Lowercase a-z
                const c = code - 97;
                const p = (c - k + 26) % 26;
                const transformed = String.fromCharCode(p + 97);
                result += transformed;
                steps.push({
                    index: i + 1,
                    original: char,
                    cVal: c,
                    formula: `(${c} - ${k} + 26) mod 26 = ${p}`,
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
            steps: steps,
            summary: `Reverse shifted by ${k} position(s) (mod 26). Processed ${text.length} characters.`
        };
    }
};
