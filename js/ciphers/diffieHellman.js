/**
 * CryptoLab - Diffie-Hellman Key Exchange Simulator
 * Demonstrates Public-Key Key Agreement protocol & Discrete Logarithm Problem
 */

window.CryptoLab = window.CryptoLab || {};
window.CryptoLab.ciphers = window.CryptoLab.ciphers || {};

window.CryptoLab.ciphers.diffieHellman = {
    id: 'diffieHellman',
    name: 'Diffie-Hellman Key Exchange',
    category: 'modern',
    type: 'Asymmetric Key Agreement Protocol',
    formula: 'Alice: A = gᵃ mod p -> Bob: B = gᵇ mod p -> Shared Secret: S = Bᵃ mod p = Aᵇ mod p = gᵃᵇ mod p',
    keyType: 'Ephemeral Private Keys (a, b) + Public Parameters (p, g)',
    securityLevel: 'Modern RFC 3526 2048-bit / 3072-bit MODP groups secure against classical attacks. Elliptic Curve DH (ECDH) preferred today.',
    purpose: 'Allows two parties with no prior shared secret to agree on a symmetric encryption key over an insecure public channel.',
    about: {
        description: 'Published in 1976 by Whitfield Diffie and Martin Hellman (with foundational contributions from Ralph Merkle), the Diffie-Hellman Key Exchange was the first published practical method for establishing a shared secret over an unencrypted public communications channel. It relies on the computational difficulty of the Discrete Logarithm Problem (DLP) in finite cyclic groups.',
        advantages: [
            'Solves the foundational key exchange dilemma: no pre-shared secret required.',
            'Perfect Forward Secrecy (PFS): ephemeral DH keys ensure past communications remain secure even if long-term keys are compromised.',
            'Mathematically elegant and efficient to compute using modular exponentiation.'
        ],
        limitations: [
            'Lacks inherent authentication: vulnerable to active Man-in-the-Middle (MitM) attacks without digital certificates/signatures.',
            'Requires large prime numbers (minimum 2048-bit) to resist the Number Field Sieve (NFS) algorithm.',
            'Vulnerable to Shor\'s quantum algorithm for discrete logarithms.'
        ],
        history: 'Spawned the era of public-key cryptography and revolutionized secure internet communications (SSL/TLS, SSH, IPsec).'
    },
    example: {
        p: '23',
        g: '5',
        a: '6', // Alice private
        b: '15' // Bob private
    },

    modExp(base, exp, mod) {
        let res = 1n;
        base = base % mod;
        while (exp > 0n) {
            if (exp % 2n === 1n) res = (res * base) % mod;
            base = (base * base) % mod;
            exp = exp / 2n;
        }
        return res;
    },

    isPrime(n) {
        if (n <= 1n) return false;
        if (n <= 3n) return true;
        if (n % 2n === 0n || n % 3n === 0n) return false;
        for (let i = 5n; i * i <= n; i += 6n) {
            if (n % i === 0n || n % (i + 2n) === 0n) return false;
        }
        return true;
    },

    /**
     * Simulate Full Diffie-Hellman Protocol Exchange
     */
    simulateExchange(pInput, gInput, aInput, bInput) {
        try {
            const p = BigInt(String(pInput).trim());
            const g = BigInt(String(gInput).trim());
            const a = BigInt(String(aInput).trim());
            const b = BigInt(String(bInput).trim());

            if (p <= 2n) {
                return { valid: false, error: 'Prime modulus p must be an integer greater than 2.' };
            }
            if (!this.isPrime(p)) {
                return { valid: false, error: `Modulus p = ${p} is NOT a prime number. Diffie-Hellman requires a prime modulus.` };
            }
            if (g <= 1n || g >= p) {
                return { valid: false, error: `Base generator g = ${g} must be in the range 1 < g < p (${p}).` };
            }
            if (a <= 0n || a >= p) {
                return { valid: false, error: `Alice's private key a = ${a} must satisfy 1 ≤ a < p (${p}).` };
            }
            if (b <= 0n || b >= p) {
                return { valid: false, error: `Bob's private key b = ${b} must satisfy 1 ≤ b < p (${p}).` };
            }

            // Step 1: Alice computes public key A = g^a mod p
            const A = this.modExp(g, a, p);

            // Step 2: Bob computes public key B = g^b mod p
            const B = this.modExp(g, b, p);

            // Step 3: Alice computes shared secret: S_Alice = B^a mod p
            const sAlice = this.modExp(B, a, p);

            // Step 4: Bob computes shared secret: S_Bob = A^b mod p
            const sBob = this.modExp(A, b, p);

            const match = sAlice === sBob;

            return {
                valid: true,
                p: p.toString(),
                g: g.toString(),
                a: a.toString(),
                b: b.toString(),
                A: A.toString(),
                B: B.toString(),
                sAlice: sAlice.toString(),
                sBob: sBob.toString(),
                sharedSecret: sAlice.toString(),
                keysMatch: match,
                steps: [
                    {
                        step: 1,
                        actor: 'Public Channel Agreement',
                        action: 'Both parties agree publicly on global parameters',
                        details: `Prime Modulus p = ${p}, Base Generator g = ${g}`
                    },
                    {
                        step: 2,
                        actor: 'Alice (Private Execution)',
                        action: 'Chooses private secret "a" and computes public value A',
                        details: `Private key a = ${a} -> Public key A = (${g}^${a}) mod ${p} = ${A}`
                    },
                    {
                        step: 3,
                        actor: 'Bob (Private Execution)',
                        action: 'Chooses private secret "b" and computes public value B',
                        details: `Private key b = ${b} -> Public key B = (${g}^${b}) mod ${p} = ${B}`
                    },
                    {
                        step: 4,
                        actor: 'Insecure Public Network (Eve Watches)',
                        action: 'Alice and Bob exchange public values A and B over the wire',
                        details: `Exchanged: A = ${A}, B = ${B}. Eavesdropper Eve sees: (p=${p}, g=${g}, A=${A}, B=${B}) but CANNOT find 'a' or 'b' without solving Discrete Log!`
                    },
                    {
                        step: 5,
                        actor: 'Alice (Secret Derivation)',
                        action: 'Alice computes shared secret using Bob\'s public value B and her private key a',
                        details: `S_Alice = (${B}^${a}) mod ${p} = ${sAlice}`
                    },
                    {
                        step: 6,
                        actor: 'Bob (Secret Derivation)',
                        action: 'Bob computes shared secret using Alice\'s public value A and his private key b',
                        details: `S_Bob = (${A}^${b}) mod ${p} = ${sBob}`
                    }
                ],
                mathProof: `Mathematical Equality Proof:\nS_Alice = Bᵃ mod p = (gᵇ)ᵃ mod p = gᵃᵇ mod p\nS_Bob = Aᵇ mod p = (gᵃ)ᵇ mod p = gᵃᵇ mod p\nSince gᵃᵇ ≡ gᵃᵇ (mod p), both parties independently arrive at ${sAlice}!`
            };
        } catch (err) {
            return { valid: false, error: 'Calculation error: ' + err.message };
        }
    }
};
