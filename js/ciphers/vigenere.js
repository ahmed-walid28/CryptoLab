/**
 * CryptoLab - Vigenère Cipher Module
 * Formula: C = (P + K) mod 26, P = (C - K) mod 26
 */

window.CryptoLab = window.CryptoLab || {};
window.CryptoLab.ciphers = window.CryptoLab.ciphers || {};

window.CryptoLab.ciphers.vigenere = {
    id: 'vigenere',
    name: 'Vigenère Cipher',
    category: 'classical',
    type: 'Polyalphabetic Substitution Cipher',
    formula: 'C[i] = (P[i] + K[i]) mod 26 | P[i] = (C[i] - K[i]) mod 26',
    keyType: 'Alphabetic Keyword / Keyphrase',
    securityLevel: 'Vulnerable to Kasiski examination, Friedman test, and index of coincidence analysis.',
    purpose: 'Demonstrates polyalphabetic substitution to flatten single-letter frequency spikes.',
    about: {
        description: 'Invented by Giovan Battista Bellaso in 1553 and later misattributed to Blaise de Vigenère, this polyalphabetic cipher uses a repeating keyword to shift successive plaintext letters by different amounts, effectively employing multiple interwoven Caesar ciphers.',
        advantages: [
            'Resists simple single-character frequency analysis by mapping the same letter to different cipher characters depending on its position.',
            'Key can be any easy-to-remember word or phrase.',
            'Considered "le chiffre indéchiffrable" (the indecipherable cipher) for nearly three centuries.'
        ],
        limitations: [
            'Periodic repetition of the keyword introduces patterns discoverable via Kasiski examination.',
            'Once key length is determined, it reduces to N independent Caesar ciphers which are trivial to solve.',
            'Requires secret key sharing equal in secrecy to the message.'
        ],
        history: 'Remained unbroken until Charles Babbage and Friedrich Kasiski independently developed cryptanalytic methods in the 19th century.'
    },
    example: {
        plaintext: 'ATTACK AT DAWN SILENTLY',
        key: 'KEY',
        ciphertext: 'KXRKGI KX BYAL WGVCRDVCI'
    },

    validateKey(key) {
        if (!key || typeof key !== 'string' || key.trim() === '') {
            return { valid: false, error: 'Keyword is required. Please enter an alphabetic string.' };
        }
        const cleanedKey = key.toUpperCase().replace(/[^A-Z]/g, '');
        if (cleanedKey.length === 0) {
            return { valid: false, error: 'Keyword must contain at least one alphabetic letter (A-Z).' };
        }
        return { valid: true, key: cleanedKey };
    },

    encrypt(text, key, options = {}) {
        const keyVal = this.validateKey(key);
        if (!keyVal.valid) {
            throw new Error(keyVal.error);
        }
        if (!text || text.trim() === '') {
            throw new Error('Plaintext input cannot be empty.');
        }

        const kStr = keyVal.key;
        let result = '';
        let keyIndex = 0;
        const steps = [];
        let repeatedKeyDisplay = '';
        let alignedPlainDisplay = '';

        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            const code = char.charCodeAt(0);
            const isUpper = code >= 65 && code <= 90;
            const isLower = code >= 97 && code <= 122;

            if (isUpper || isLower) {
                const base = isUpper ? 65 : 97;
                const p = code - base;
                const keyChar = kStr[keyIndex % kStr.length];
                const k = keyChar.charCodeAt(0) - 65;
                const c = (p + k) % 26;
                const transformed = String.fromCharCode(c + base);

                result += transformed;
                repeatedKeyDisplay += keyChar;
                alignedPlainDisplay += char.toUpperCase();

                steps.push({
                    index: i + 1,
                    original: char,
                    keyChar: keyChar,
                    pVal: p,
                    kVal: k,
                    formula: `(${p} [${char.toUpperCase()}] + ${k} [${keyChar}]) mod 26 = ${c} [${transformed.toUpperCase()}]`,
                    resultChar: transformed,
                    isAlpha: true
                });

                keyIndex++;
            } else {
                result += char;
                repeatedKeyDisplay += ' ';
                alignedPlainDisplay += char;
                steps.push({
                    index: i + 1,
                    original: char,
                    formula: 'Non-alphabetic character (passed unchanged, key not advanced)',
                    resultChar: char,
                    isAlpha: false
                });
            }
        }

        return {
            output: result,
            steps: steps,
            alignedPlain: alignedPlainDisplay,
            repeatedKey: repeatedKeyDisplay,
            summary: `Encrypted using key "${kStr}" of length ${kStr.length}. Total alphabetic shifts applied: ${keyIndex}.`
        };
    },

    decrypt(text, key, options = {}) {
        const keyVal = this.validateKey(key);
        if (!keyVal.valid) {
            throw new Error(keyVal.error);
        }
        if (!text || text.trim() === '') {
            throw new Error('Ciphertext input cannot be empty.');
        }

        const kStr = keyVal.key;
        let result = '';
        let keyIndex = 0;
        const steps = [];
        let repeatedKeyDisplay = '';
        let alignedCipherDisplay = '';

        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            const code = char.charCodeAt(0);
            const isUpper = code >= 65 && code <= 90;
            const isLower = code >= 97 && code <= 122;

            if (isUpper || isLower) {
                const base = isUpper ? 65 : 97;
                const c = code - base;
                const keyChar = kStr[keyIndex % kStr.length];
                const k = keyChar.charCodeAt(0) - 65;
                const p = (c - k + 26) % 26;
                const transformed = String.fromCharCode(p + base);

                result += transformed;
                repeatedKeyDisplay += keyChar;
                alignedCipherDisplay += char.toUpperCase();

                steps.push({
                    index: i + 1,
                    original: char,
                    keyChar: keyChar,
                    cVal: c,
                    kVal: k,
                    formula: `(${c} [${char.toUpperCase()}] - ${k} [${keyChar}] + 26) mod 26 = ${p} [${transformed.toUpperCase()}]`,
                    resultChar: transformed,
                    isAlpha: true
                });

                keyIndex++;
            } else {
                result += char;
                repeatedKeyDisplay += ' ';
                alignedCipherDisplay += char;
                steps.push({
                    index: i + 1,
                    original: char,
                    formula: 'Non-alphabetic character (passed unchanged, key not advanced)',
                    resultChar: char,
                    isAlpha: false
                });
            }
        }

        return {
            output: result,
            steps: steps,
            alignedCipher: alignedCipherDisplay,
            repeatedKey: repeatedKeyDisplay,
            summary: `Decrypted using key "${kStr}" of length ${kStr.length}. Total alphabetic shifts applied: ${keyIndex}.`
        };
    }
};
