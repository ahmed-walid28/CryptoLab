/**
 * CryptoLab - Atbash Cipher Module
 * Formula: C = (25 - P) mod 26 (Self-reciprocal cipher)
 */

window.CryptoLab = window.CryptoLab || {};
window.CryptoLab.ciphers = window.CryptoLab.ciphers || {};

window.CryptoLab.ciphers.atbash = {
    id: 'atbash',
    name: 'Atbash Cipher',
    category: 'classical',
    type: 'Monoalphabetic Inversion / Substitution Cipher',
    formula: 'C = 25 - P (A ↔ Z, B ↔ Y, C ↔ X, ...)',
    keyType: 'Keyless (Fixed Alphabet Reversal)',
    securityLevel: 'Zero security (Trivially reversible without any secret key).',
    purpose: 'Demonstrates self-reciprocal (involutory) monoalphabetic substitution.',
    about: {
        description: 'The Atbash Cipher is an ancient Hebrew monoalphabetic substitution cipher originally used for the Hebrew alphabet. It maps the first letter of the alphabet to the last, the second to the second-to-last, and so on. Because it is symmetric, the exact same operation performs both encryption and decryption.',
        advantages: [
            'Extremely simple: requires zero key exchange or key memorization.',
            'Involutory property: applying the cipher twice restores the original plaintext (E(E(x)) = x).',
            'Historical significance as one of the oldest recorded cryptographic systems in religious literature.'
        ],
        limitations: [
            'Fixed mapping provides zero secrecy against anyone aware that Atbash was used.',
            'No key parameter; identical plaintext will always produce identical ciphertext.',
            'Vulnerable to immediate letter frequency substitution.'
        ],
        history: 'Used extensively in biblical manuscripts, such as the Book of Jeremiah where "Babel" is encoded as "Sheshach".'
    },
    example: {
        plaintext: 'SECURITY AND CRYPTOGRAPHY',
        key: 'N/A (Keyless)',
        ciphertext: 'HVXFIRGB ZMW XIBKGLTIZKSB'
    },

    encrypt(text, key, options = {}) {
        if (!text || text.trim() === '') {
            throw new Error('Plaintext input cannot be empty.');
        }

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
                const c = 25 - p;
                const transformed = String.fromCharCode(c + base);

                result += transformed;
                steps.push({
                    index: i + 1,
                    original: char,
                    pVal: p,
                    formula: `25 - ${p} [${char.toUpperCase()}] = ${c} [${transformed.toUpperCase()}]`,
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
            summary: `Atbash inverted ${text.length} character(s). Same algorithm can be rerun on output to decrypt.`
        };
    },

    decrypt(text, key, options = {}) {
        // Atbash is self-inverting
        return this.encrypt(text, key, options);
    }
};
