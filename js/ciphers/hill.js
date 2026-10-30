/**
 * CryptoLab - Hill Cipher Module (2x2 Matrix)
 * Formula: C = (K * P) mod 26, P = (K^-1 * C) mod 26
 */

window.CryptoLab = window.CryptoLab || {};
window.CryptoLab.ciphers = window.CryptoLab.ciphers || {};

window.CryptoLab.ciphers.hill = {
    id: 'hill',
    name: 'Hill Cipher (2x2)',
    category: 'classical',
    type: 'Polygraphic Linear Algebraic Substitution Cipher',
    formula: 'C = (K · P) mod 26 | P = (K⁻¹ · C) mod 26',
    keyType: '2×2 Invertible Matrix [a, b; c, d] mod 26',
    securityLevel: 'Vulnerable to known-plaintext attacks via solving linear system of equations.',
    purpose: 'Introduces linear algebra, matrix multiplication, determinants, and modular inverse in cryptography.',
    about: {
        description: 'Invented in 1929 by mathematician Lester S. Hill, the Hill Cipher was the first polygraphic cipher capable of operating on more than two symbols at once using linear algebra. Plaintext blocks are represented as vectors and multiplied by an invertible key matrix modulo 26.',
        advantages: [
            'Completely conceals single-letter and digraph frequencies for larger block sizes.',
            'First polygraphic cipher based on rigorous mathematical principles of linear algebra.',
            'High throughput and uniform mathematical structure.'
        ],
        limitations: [
            'Completely linear; completely vulnerable to known-plaintext attacks with just m plaintext-ciphertext vector pairs.',
            'Requires the key matrix to have a determinant coprime to 26; non-invertible matrices cannot decrypt.',
            'Manual computation is tedious and error-prone.'
        ],
        history: 'Lester Hill designed an ingenious mechanical apparatus with gears to perform matrix multiplication automatically for military use.'
    },
    example: {
        plaintext: 'HELP',
        key: { a: 3, b: 3, c: 2, d: 5 }, // det = 15 - 6 = 9, gcd(9, 26) = 1, inv = 3
        ciphertext: 'HIAT'
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

    validateMatrix(a, b, c, d) {
        const numA = parseInt(a, 10);
        const numB = parseInt(b, 10);
        const numC = parseInt(c, 10);
        const numD = parseInt(d, 10);

        if (isNaN(numA) || isNaN(numB) || isNaN(numC) || isNaN(numD)) {
            return { valid: false, error: 'All 4 matrix values [a, b, c, d] must be valid integers.' };
        }

        const mA = ((numA % 26) + 26) % 26;
        const mB = ((numB % 26) + 26) % 26;
        const mC = ((numC % 26) + 26) % 26;
        const mD = ((numD % 26) + 26) % 26;

        const det = ((mA * mD - mB * mC) % 26 + 26) % 26;
        const g = this.gcd(det, 26);

        if (g !== 1) {
            return {
                valid: false,
                error: `Matrix determinant Δ = (${mA}×${mD} - ${mB}×${mC}) mod 26 = ${det}. Since gcd(${det}, 26) = ${g} ≠ 1, this matrix is NOT invertible modulo 26 and cannot be used for encryption/decryption.`,
                det: det,
                gcd: g
            };
        }

        const detInv = this.modInverse(det, 26);
        // Adjugate matrix: [ d, -b; -c, a ] mod 26
        const adjA = mD;
        const adjB = (26 - (mB % 26)) % 26;
        const adjC = (26 - (mC % 26)) % 26;
        const adjD = mA;

        // Inverse matrix: detInv * Adjugate mod 26
        const invA = (detInv * adjA) % 26;
        const invB = (detInv * adjB) % 26;
        const invC = (detInv * adjC) % 26;
        const invD = (detInv * adjD) % 26;

        return {
            valid: true,
            matrix: { a: mA, b: mB, c: mC, d: mD },
            det: det,
            detInv: detInv,
            invMatrix: { a: invA, b: invB, c: invC, d: invD }
        };
    },

    encrypt(text, key, options = {}) {
        let a, b, c, d;
        if (typeof key === 'object' && key !== null) {
            a = key.a; b = key.b; c = key.c; d = key.d;
        } else if (typeof key === 'string') {
            const parts = key.split(/[\s,]+/).map(p => p.trim()).filter(Boolean);
            if (parts.length === 4) {
                [a, b, c, d] = parts;
            } else {
                throw new Error('Key must contain 4 integers [a, b, c, d] for 2x2 matrix.');
            }
        }

        const val = this.validateMatrix(a, b, c, d);
        if (!val.valid) {
            throw new Error(val.error);
        }
        if (!text || text.trim() === '') {
            throw new Error('Plaintext input cannot be empty.');
        }

        const K = val.matrix;
        let cleaned = text.toUpperCase().replace(/[^A-Z]/g, '');
        if (cleaned.length === 0) {
            throw new Error('Plaintext must contain at least one alphabetic letter.');
        }

        let paddingAdded = false;
        if (cleaned.length % 2 !== 0) {
            cleaned += 'X';
            paddingAdded = true;
        }

        let result = '';
        const steps = [];

        for (let i = 0; i < cleaned.length; i += 2) {
            const char1 = cleaned[i];
            const char2 = cleaned[i + 1];
            const p1 = char1.charCodeAt(0) - 65;
            const p2 = char2.charCodeAt(0) - 65;

            const c1 = (K.a * p1 + K.b * p2) % 26;
            const c2 = (K.c * p1 + K.d * p2) % 26;

            const out1 = String.fromCharCode(c1 + 65);
            const out2 = String.fromCharCode(c2 + 65);

            result += out1 + out2;

            steps.push({
                index: (i / 2) + 1,
                pair: `${char1}${char2}`,
                pVec: `[${p1}, ${p2}]ᵀ`,
                calculation: `[${K.a}×${p1} + ${K.b}×${p2}] mod 26 = ${c1} [${out1}], [${K.c}×${p1} + ${K.d}×${p2}] mod 26 = ${c2} [${out2}]`,
                cVec: `[${c1}, ${c2}]ᵀ`,
                outputPair: `${out1}${out2}`
            });
        }

        return {
            output: result,
            matrix: K,
            det: val.det,
            detInv: val.detInv,
            invMatrix: val.invMatrix,
            steps: steps,
            paddingAdded: paddingAdded,
            summary: `Encrypted ${cleaned.length / 2} block(s) of 2 letters. Determinant Δ = ${val.det} (coprime to 26).${paddingAdded ? ' Added trailing "X" padding.' : ''}`
        };
    },

    decrypt(text, key, options = {}) {
        let a, b, c, d;
        if (typeof key === 'object' && key !== null) {
            a = key.a; b = key.b; c = key.c; d = key.d;
        } else if (typeof key === 'string') {
            const parts = key.split(/[\s,]+/).map(p => p.trim()).filter(Boolean);
            if (parts.length === 4) {
                [a, b, c, d] = parts;
            } else {
                throw new Error('Key must contain 4 integers [a, b, c, d] for 2x2 matrix.');
            }
        }

        const val = this.validateMatrix(a, b, c, d);
        if (!val.valid) {
            throw new Error(val.error);
        }
        if (!text || text.trim() === '') {
            throw new Error('Ciphertext input cannot be empty.');
        }

        const K_inv = val.invMatrix;
        const cleaned = text.toUpperCase().replace(/[^A-Z]/g, '');
        if (cleaned.length === 0) {
            throw new Error('Ciphertext must contain at least one alphabetic letter.');
        }
        if (cleaned.length % 2 !== 0) {
            throw new Error('Hill ciphertext length must be an even number of characters (pairs of 2).');
        }

        let result = '';
        const steps = [];

        for (let i = 0; i < cleaned.length; i += 2) {
            const char1 = cleaned[i];
            const char2 = cleaned[i + 1];
            const c1 = char1.charCodeAt(0) - 65;
            const c2 = char2.charCodeAt(0) - 65;

            const p1 = (K_inv.a * c1 + K_inv.b * c2) % 26;
            const p2 = (K_inv.c * c1 + K_inv.d * c2) % 26;

            const out1 = String.fromCharCode(p1 + 65);
            const out2 = String.fromCharCode(p2 + 65);

            result += out1 + out2;

            steps.push({
                index: (i / 2) + 1,
                pair: `${char1}${char2}`,
                cVec: `[${c1}, ${c2}]ᵀ`,
                calculation: `[${K_inv.a}×${c1} + ${K_inv.b}×${c2}] mod 26 = ${p1} [${out1}], [${K_inv.c}×${c1} + ${K_inv.d}×${c2}] mod 26 = ${p2} [${out2}]`,
                pVec: `[${p1}, ${p2}]ᵀ`,
                outputPair: `${out1}${out2}`
            });
        }

        return {
            output: result,
            matrix: val.matrix,
            det: val.det,
            detInv: val.detInv,
            invMatrix: K_inv,
            steps: steps,
            summary: `Decrypted ${cleaned.length / 2} block(s) using modular inverse matrix K⁻¹ = [${K_inv.a}, ${K_inv.b}; ${K_inv.c}, ${K_inv.d}].`
        };
    }
};
