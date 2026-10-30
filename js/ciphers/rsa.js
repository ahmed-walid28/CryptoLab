/**
 * CryptoLab - RSA Module (Rivest–Shamir–Adleman)
 * Supports Dual Modes:
 * 1. Educational Step-by-Step Mathematical RSA (BigInt arbitrary-precision arithmetic)
 * 2. Industry-Standard RSA-OAEP 2048-bit via Browser Web Crypto API
 */

window.CryptoLab = window.CryptoLab || {};
window.CryptoLab.ciphers = window.CryptoLab.ciphers || {};

window.CryptoLab.ciphers.rsa = {
    id: 'rsa',
    name: 'RSA (Rivest–Shamir–Adleman)',
    category: 'modern',
    type: 'Asymmetric (Public-Key) Cryptosystem',
    formula: 'Keygen: n = p·q, φ(n) = (p-1)(q-1), e·d ≡ 1 (mod φ(n)) | Encrypt: C = Mᵉ mod n | Decrypt: M = Cᵈ mod n',
    keyType: 'Asymmetric Key Pair: Public Key (e, n) & Private Key (d, n)',
    securityLevel: '2048-bit / 4096-bit keys currently secure against classical computers. Vulnerable to Shor’s algorithm on quantum computers.',
    purpose: 'Underpins digital signatures, key encapsulation mechanisms (KEM), and secure public key exchange.',
    about: {
        description: 'Introduced in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman at MIT, RSA is the most widely deployed asymmetric cryptosystem. Its security rests on the computational hardness of the Integer Factorization Problem: while multiplying two large prime numbers p and q is instantaneous, factoring their composite product n back into p and q is practically infeasible with classical computers.',
        advantages: [
            'Solves the classical key distribution problem: the public key can be freely published over untrusted channels.',
            'Supports both public-key encryption and digital signatures (integrity and non-repudiation).',
            'Solid, time-tested mathematical foundations rooted in Euler\'s Totient Theorem.'
        ],
        limitations: [
            'Computationally intensive: orders of magnitude slower than symmetric ciphers like AES.',
            'In modern protocols, RSA is used only for hybrid encryption (encrypting a symmetric AES session key).',
            'Textbook RSA without padding (e.g. OAEP) is malleable and vulnerable to chosen-ciphertext attacks.'
        ],
        history: 'First publicly described in 1977, though Clifford Cocks at the British intelligence agency GCHQ had conceived an equivalent system in 1973 (classified until 1997).'
    },
    example: {
        plaintext: 'SECRET',
        key: { p: '61', q: '53', e: '17' } // n = 3233, phi = 3120, d = 2753
    },

    // --- Mathematical Educational Mode Utilities ---

    gcdBigInt(a, b) {
        a = a < 0n ? -a : a;
        b = b < 0n ? -b : b;
        while (b !== 0n) {
            const t = b;
            b = a % b;
            a = t;
        }
        return a;
    },

    // Extended Euclidean Algorithm for BigInt modular inverse
    extGcdBigInt(a, m) {
        let [m0, x0, x1] = [m, 0n, 1n];
        if (m === 1n) return 0n;
        while (a > 1n) {
            if (m === 0n) return null;
            const q = a / m;
            let t = m;
            m = a % m;
            a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if (x1 < 0n) x1 += m0;
        return x1;
    },

    // Modular Exponentiation: (base^exp) mod mod
    modExpBigInt(base, exp, mod) {
        let res = 1n;
        base = base % mod;
        while (exp > 0n) {
            if (exp % 2n === 1n) res = (res * base) % mod;
            base = (base * base) % mod;
            exp = exp / 2n;
        }
        return res;
    },

    // Primality check (Miller-Rabin for educational primes)
    isPrimeBigInt(n) {
        if (n <= 1n) return false;
        if (n <= 3n) return true;
        if (n % 2n === 0n || n % 3n === 0n) return false;
        for (let i = 5n; i * i <= n; i += 6n) {
            if (n % i === 0n || n % (i + 2n) === 0n) return false;
        }
        return true;
    },

    /**
     * Compute Educational RSA Parameters from primes p, q and exponent e
     */
    computeEducationalKeyParams(pStr, qStr, eStr) {
        try {
            const p = BigInt(pStr.trim());
            const q = BigInt(qStr.trim());
            const e = BigInt(eStr.trim());

            if (!this.isPrimeBigInt(p)) {
                return { valid: false, error: `Parameter p = ${p} is NOT a prime number.` };
            }
            if (!this.isPrimeBigInt(q)) {
                return { valid: false, error: `Parameter q = ${q} is NOT a prime number.` };
            }
            if (p === q) {
                return { valid: false, error: 'Parameters p and q must be distinct primes.' };
            }

            const n = p * q;
            const phi = (p - 1n) * (q - 1n);

            if (e <= 1n || e >= phi) {
                return { valid: false, error: `Public exponent e = ${e} must satisfy 1 < e < φ(n) (${phi}).` };
            }

            const g = this.gcdBigInt(e, phi);
            if (g !== 1n) {
                return { valid: false, error: `Public exponent e = ${e} is not coprime to φ(n) = ${phi} (gcd = ${g}). Choose an odd prime like 3, 17, 65537.` };
            }

            const d = this.extGcdBigInt(e, phi);
            if (d === null) {
                return { valid: false, error: 'Modular inverse d could not be computed.' };
            }

            return {
                valid: true,
                p, q, n, phi, e, d,
                publicKeyDisplay: `(e = ${e}, n = ${n})`,
                privateKeyDisplay: `(d = ${d}, n = ${n})`
            };
        } catch (err) {
            return { valid: false, error: 'Invalid prime or exponent format: ' + err.message };
        }
    },

    /**
     * Educational RSA Encryption: C = M^e mod n per character or block
     */
    encryptMath(text, pStr, qStr, eStr) {
        const keyInfo = this.computeEducationalKeyParams(pStr, qStr, eStr);
        if (!keyInfo.valid) {
            throw new Error(keyInfo.error);
        }
        if (!text || text.trim() === '') {
            throw new Error('Plaintext input cannot be empty.');
        }

        const { n, e, phi, d, p, q } = keyInfo;
        const cipherNumbers = [];
        const steps = [];

        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            const m = BigInt(char.charCodeAt(0));

            if (m >= n) {
                throw new Error(`Character "${char}" ASCII value (${m}) is ≥ modulus n (${n}). Choose larger primes p and q such that n > 255.`);
            }

            const c = this.modExpBigInt(m, e, n);
            cipherNumbers.push(c.toString());

            steps.push({
                index: i + 1,
                char: char,
                mVal: m.toString(),
                formula: `C = (${m} ^ ${e}) mod ${n} = ${c}`,
                cVal: c.toString()
            });
        }

        const cipherString = cipherNumbers.join(' ');

        return {
            output: cipherString,
            cipherNumbers: cipherNumbers,
            keyInfo: {
                p: p.toString(),
                q: q.toString(),
                n: n.toString(),
                phi: phi.toString(),
                e: e.toString(),
                d: d.toString()
            },
            steps: steps,
            summary: `Educational RSA Encrypted: n = ${n}, φ(n) = ${phi}, public exponent e = ${e}, private key d = ${d}.`
        };
    },

    /**
     * Educational RSA Decryption: M = C^d mod n
     */
    decryptMath(cipherInput, pStr, qStr, eStr) {
        const keyInfo = this.computeEducationalKeyParams(pStr, qStr, eStr);
        if (!keyInfo.valid) {
            throw new Error(keyInfo.error);
        }
        if (!cipherInput || cipherInput.trim() === '') {
            throw new Error('Ciphertext numbers input cannot be empty.');
        }

        const { n, d, phi, e, p, q } = keyInfo;
        const tokens = cipherInput.trim().split(/[\s,]+/).filter(Boolean);
        let recoveredText = '';
        const steps = [];

        for (let i = 0; i < tokens.length; i++) {
            const token = tokens[i];
            let c;
            try {
                c = BigInt(token);
            } catch {
                throw new Error(`Invalid ciphertext number "${token}" at position ${i + 1}.`);
            }

            if (c >= n) {
                throw new Error(`Ciphertext number ${c} cannot be ≥ modulus n (${n}).`);
            }

            const m = this.modExpBigInt(c, d, n);
            const char = String.fromCharCode(Number(m));
            recoveredText += char;

            steps.push({
                index: i + 1,
                cVal: c.toString(),
                formula: `M = (${c} ^ ${d}) mod ${n} = ${m}`,
                mVal: m.toString(),
                char: char
            });
        }

        return {
            output: recoveredText,
            keyInfo: {
                p: p.toString(),
                q: q.toString(),
                n: n.toString(),
                phi: phi.toString(),
                e: e.toString(),
                d: d.toString()
            },
            steps: steps,
            summary: `Educational RSA Decrypted using private exponent d = ${d}. Reconstructed ${recoveredText.length} character(s).`
        };
    },

    // --- Web Crypto API 2048-bit RSA-OAEP Mode ---

    /**
     * Generate 2048-bit RSA-OAEP Keypair
     */
    async generateWebCryptoKeyPair() {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error('Web Crypto API is not supported in this browser.');
        }

        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]), // 65537
                hash: 'SHA-256'
            },
            true,
            ['encrypt', 'decrypt']
        );

        const spkiExport = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const pkcs8Export = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

        const pubBase64 = this.arrayBufferToBase64(spkiExport);
        const privBase64 = this.arrayBufferToBase64(pkcs8Export);

        const pubPem = `-----BEGIN PUBLIC KEY-----\n${this.formatPem(pubBase64)}\n-----END PUBLIC KEY-----`;
        const privPem = `-----BEGIN PRIVATE KEY-----\n${this.formatPem(privBase64)}\n-----END PRIVATE KEY-----`;

        return {
            publicKey: keyPair.publicKey,
            privateKey: keyPair.privateKey,
            publicKeyPem: pubPem,
            privateKeyPem: privPem
        };
    },

    formatPem(base64) {
        return base64.match(/.{1,64}/g).join('\n');
    },

    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    },

    base64ToArrayBuffer(base64) {
        const clean = base64.replace(/-----BEGIN[^-]+-----/g, '').replace(/-----END[^-]+-----/g, '').replace(/\s+/g, '');
        const binary = window.atob(clean);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    },

    async importWebCryptoPublicKey(pem) {
        const buffer = this.base64ToArrayBuffer(pem);
        return await window.crypto.subtle.importKey(
            'spki',
            buffer,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            true,
            ['encrypt']
        );
    },

    async importWebCryptoPrivateKey(pem) {
        const buffer = this.base64ToArrayBuffer(pem);
        return await window.crypto.subtle.importKey(
            'pkcs8',
            buffer,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            true,
            ['decrypt']
        );
    },

    async encryptWebCrypto(plaintext, publicKeyPem) {
        if (!plaintext || plaintext.trim() === '') {
            throw new Error('Plaintext input cannot be empty.');
        }
        if (!publicKeyPem || publicKeyPem.trim() === '') {
            throw new Error('RSA Public Key (PEM format) is required.');
        }

        const pubKey = await this.importWebCryptoPublicKey(publicKeyPem);
        const encoder = new TextEncoder();
        const dataBytes = encoder.encode(plaintext);

        const encrypted = await window.crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            pubKey,
            dataBytes
        );

        const base64Cipher = this.arrayBufferToBase64(encrypted);
        return {
            output: base64Cipher,
            summary: `RSA-OAEP 2048-bit Encrypted with SHA-256 optimal asymmetric encryption padding.`
        };
    },

    async decryptWebCrypto(cipherBase64, privateKeyPem) {
        if (!cipherBase64 || cipherBase64.trim() === '') {
            throw new Error('Ciphertext Base64 input cannot be empty.');
        }
        if (!privateKeyPem || privateKeyPem.trim() === '') {
            throw new Error('RSA Private Key (PEM format) is required.');
        }

        const privKey = await this.importWebCryptoPrivateKey(privateKeyPem);
        const cipherBuffer = this.base64ToArrayBuffer(cipherBase64);

        try {
            const decrypted = await window.crypto.subtle.decrypt(
                { name: 'RSA-OAEP' },
                privKey,
                cipherBuffer
            );
            const decoder = new TextDecoder();
            const text = decoder.decode(decrypted);
            return {
                output: text,
                summary: `RSA-OAEP 2048-bit Decrypted successfully.`
            };
        } catch (err) {
            throw new Error('RSA Decryption Failed: Ciphertext invalid or private key does not match the public key.');
        }
    }
};
