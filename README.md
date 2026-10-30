# CryptoLab — Cryptography Learning & Encryption Tool
### *Classical & Modern Cryptography Web Application*

**CryptoLab** is an interactive, educational, and fully functional web application engineered for the university course **Computer Security and Cryptography**. It bridges the gap between historical encryption techniques and modern cryptographic standards through hands-on encryption, decryption, step-by-step mathematical breakdowns, and real-time visualizers.

---

## Key Features

1. **Complete Algorithm Suite**:
   - **8 Classical Ciphers**: Caesar, Vigenère, Playfair (5×5 matrix), Hill (2×2 linear algebra), Atbash, Affine, Rail Fence (zig-zag wave), and Columnar Transposition.
   - **4 Modern Standards**: AES (AES-GCM 256-bit AEAD), RSA (Dual Mode: 2048-bit WebCrypto + Step-by-Step BigInt Math), SHA-256 (Hashing, Verification, Avalanche Effect), and Diffie-Hellman Key Exchange simulator.
2. **Interactive Mathematical Breakdown**:
   - "Show Calculation Steps" toggle reveals exact ASCII translations, modular congruences, matrix products, modular inverses, and power reductions.
3. **Dedicated Visualizers**:
   - Live **Playfair 5×5 Matrix** preview.
   - **Rail Fence Zig-Zag Wave** ASCII/HTML canvas.
   - **Columnar Transposition** permutation grid table.
   - **Diffie-Hellman Protocol Exchange** visual flow with Alice, Bob, and Eve (insecure channel).
4. **Standards-Compliant Modern Cryptography**:
   - Uses browser-native **W3C Web Crypto API** (`crypto.subtle`) for secure, genuine 256-bit AES-GCM and 2048-bit RSA-OAEP encryption.
5. **Zero Backend Required**:
   - Runs 100% locally in any modern browser by simply opening `index.html`.
6. **Cybersecurity Aesthetic**:
   - Glassmorphic dark slate theme, neon cyan & emerald highlights, responsive sidebar, monospace cryptographic terminals, and animated toast feedback.

---

## Project Architecture

```
d:/CryptoLab/
├── index.html                  # Main application structure, sidebar, workspace, and modals
├── README.md                   # Comprehensive documentation, algorithm details, and test guide
├── css/
│   └── style.css               # Cybersecurity dark theme, glassmorphism, responsive grid
└── js/
    ├── app.js                  # Main controller, state manager, toast notifications, router
    └── ciphers/
        ├── caesar.js           # Caesar Cipher (C = (P + K) mod 26)
        ├── vigenere.js         # Vigenère Cipher (polyalphabetic substitution)
        ├── playfair.js         # Playfair Cipher (5×5 matrix digraph substitution)
        ├── hill.js             # Hill Cipher (2×2 matrix multiplication mod 26)
        ├── atbash.js           # Atbash Cipher (alphabet inversion A ↔ Z)
        ├── affine.js           # Affine Cipher (E(x) = (ax + b) mod 26)
        ├── railfence.js        # Rail Fence Cipher (zig-zag transposition)
        ├── columnar.js         # Columnar Transposition (grid permutation)
        ├── aes.js              # Modern AES-GCM (Web Crypto API + PBKDF2)
        ├── rsa.js              # Modern RSA-OAEP + Educational BigInt Math Mode
        ├── sha256.js           # SHA-256 Digest + Avalanche Analysis
        └── diffieHellman.js    # Diffie-Hellman Key Agreement Simulator
```

---

## How to Run the Application

Because CryptoLab is built with pure standard HTML5, CSS3, and ES6+ JavaScript, **no build tools, compilers, or server dependencies are required**.

### Method 1: Direct File Launch (Quickest)
1. Navigate to the project directory: `d:\CryptoLab`.
2. Double-click `index.html` or right-click and choose **Open With > Google Chrome / Microsoft Edge / Firefox**.

### Method 2: Local Static Web Server (Recommended for Web Crypto API)
To ensure optimal performance with the Web Crypto API, run a local lightweight server:

**Using Python:**
```bash
cd d:\CryptoLab
python -m http.server 8080
```
Then open `http://localhost:8080` in your web browser.

**Using Node.js:**
```bash
npx serve d:\CryptoLab
```

---

## Implemented Algorithms & Formulas

### 1. Caesar Cipher
- **Category**: Classical Monoalphabetic Substitution
- **Formula**: $C = (P + K) \pmod{26}$ | $P = (C - K + 26) \pmod{26}$
- **Key**: Integer Shift $K \in [0, 25]$
- **Features**: Live slider, ASCII character index translation table.

### 2. Vigenère Cipher
- **Category**: Classical Polyalphabetic Substitution
- **Formula**: $C_i = (P_i + K_i) \pmod{26}$ | $P_i = (C_i - K_i + 26) \pmod{26}$
- **Key**: Alphabetic keyword (e.g. `KEY`)
- **Features**: Automatic keyword repetition over plaintext, tabular step display.

### 3. Playfair Cipher
- **Category**: Classical Polygraphic (Digraphic) Substitution
- **Key**: Keyword constructing a 5×5 matrix (I/J combined, duplicates omitted).
- **Rules**:
  - *Same Row*: Shift right for encryption (mod 5), shift left for decryption.
  - *Same Column*: Shift down for encryption (mod 5), shift up for decryption.
  - *Rectangle*: Swap column indices.
  - *Pairing*: Identical letters split with 'X'; trailing single letters padded with 'X'.
- **Features**: Live 5×5 visual matrix grid, digraph pairing step breakdown.

### 4. Hill Cipher (2×2)
- **Category**: Classical Polygraphic Linear Algebra
- **Formula**: $\mathbf{C} = \mathbf{K} \cdot \mathbf{P} \pmod{26}$ | $\mathbf{P} = \mathbf{K}^{-1} \cdot \mathbf{C} \pmod{26}$
- **Key**: 2×2 Matrix $\begin{pmatrix} a & b \\ c & d \end{pmatrix}$
- **Validation**: Determinant $\Delta = (ad - bc) \pmod{26}$ must satisfy $\gcd(\Delta, 26) = 1$.
- **Features**: Determinant calculator, modular inverse computation $\Delta^{-1}$, adjugate matrix calculation, vector product steps.

### 5. Atbash Cipher
- **Category**: Classical Monoalphabetic Inversion
- **Formula**: $C = (25 - P) \pmod{26}$ ($A \leftrightarrow Z, B \leftrightarrow Y$)
- **Key**: Keyless (Symmetric Involutory Cipher)
- **Features**: Reversal verification, self-inverting demonstration.

### 6. Affine Cipher
- **Category**: Classical Linear Substitution
- **Formula**: $E(x) = (ax + b) \pmod{26}$ | $D(x) = a^{-1}(x - b) \pmod{26}$
- **Key**: Multiplier $a$ (where $\gcd(a, 26) = 1$) and shift $b \in [0, 25]$.
- **Features**: Coprimality validator, Extended Euclidean modular inverse $a^{-1}$.

### 7. Rail Fence Cipher
- **Category**: Classical Transposition (Permutation)
- **Formula**: Zig-zag oscillation across $d$ parallel rails; read row-by-row.
- **Key**: Rail depth integer $d \ge 2$.
- **Features**: 2D wave grid visualizer, rail-by-rail character breakdown.

### 8. Columnar Transposition Cipher
- **Category**: Classical Grid Permutation
- **Formula**: Plaintext written row-by-row in width $W = \text{len}(Key)$; columns read out in alphabetical order of key characters.
- **Key**: Alphabetic keyword (e.g. `GERMAN`).
- **Features**: Dynamic column rank table, complete matrix grid visualization.

### 9. AES (Advanced Encryption Standard)
- **Category**: Modern Symmetric Block Cipher (AEAD Mode: AES-GCM)
- **Formula**: $C, \text{Tag} = \text{AES-GCM}(K, \text{IV}, P)$
- **Key**: 128-bit / 256-bit symmetric key or PBKDF2 passphrase.
- **Features**: Native Web Crypto API execution, 96-bit cryptographic random IV generation, 128-bit authentication tag verification against ciphertext tampering.

### 10. RSA (Rivest–Shamir–Adleman)
- **Category**: Modern Asymmetric Cryptosystem
- **Modes**:
  - **Educational Math Mode**: Arbitrary precision ($n = pq$, $\phi(n) = (p-1)(q-1)$, $ed \equiv 1 \pmod{\phi(n)}$, $C = M^e \pmod n$, $M = C^d \pmod n$) with step-by-step modular exponentiation.
  - **WebCrypto 2048-bit Mode**: Industry-standard RSA-OAEP with SHA-256 padding and PEM export.

### 11. SHA-256 Cryptographic Hash
- **Category**: Modern Cryptographic Hash Function (FIPS 180-4)
- **Formula**: $H = \text{SHA-256}(M) \to \text{256-bit (64 hex characters) digest}$
- **Features**: One-way hashing, Integrity Verification tool (match/mismatch check), and **Avalanche Effect Simulator** (calculating Hamming distance bit flips).

### 12. Diffie-Hellman Key Exchange
- **Category**: Modern Asymmetric Key Agreement Protocol
- **Formula**: Alice $A = g^a \pmod p$, Bob $B = g^b \pmod p \implies S = B^a \pmod p = A^b \pmod p = g^{ab} \pmod p$.
- **Features**: Interactive simulator illustrating Alice, Public Insecure Channel (Eve), and Bob, with mathematical equality proof.

---

## Test Vectors & Verification

| Algorithm | Input Text | Key / Parameters | Expected Output |
| :--- | :--- | :--- | :--- |
| **Caesar** | `HELLO` | `3` | `KHOOR` |
| **Vigenère** | `ATTACK` | `KEY` | `KXRKGI` |
| **Playfair** | `HIDE THE GOLD` | `MONARCHY` | `BMODZBXDNABG` |
| **Hill (2×2)** | `HELP` | $a=3, b=3, c=2, d=5$ | `HIAT` |
| **Atbash** | `SECURITY` | Keyless | `HVXFIRGB` |
| **Affine** | `AFFINE` | $a=5, b=8$ | `IHHWVC` |
| **Rail Fence** | `WE ARE DISCOVERED` | `3` Rails | `WECRLTEERDSOEEFEAOCAIVDEN` (for full phrase) |
| **Columnar** | `DEFEND THE EAST WALL` | `GERMAN` | Transposed column output |
| **SHA-256** | `The quick brown fox jumps over the lazy dog` | None | `d7a8fbb307d7809469ca9abb0082e4f8d5651e46d3cdb762d02d0bf37c9e592e` |
| **Diffie-Hellman** | Any | $p=23, g=5, a=6, b=15$ | Shared Secret $S = 2$ |

---

## Security Notice

> **Educational Purpose**: Classical ciphers (Caesar, Vigenère, Playfair, Hill, Atbash, Affine, Rail Fence, Columnar) are provided strictly for **pedagogical instruction** and historical analysis. They are vulnerable to modern cryptanalysis (frequency analysis, Kasiski examination, linear equation solvers, brute force) and must **never** be used for securing sensitive real-world information. Modern production environments must rely exclusively on vetted cryptographic standards such as AES-256-GCM, RSA-4096 / Ed25519, and SHA-256 / SHA-3.

---

## Course Information

- **Course**: Computer Security and Cryptography
- **Project**: CryptoLab — Interactive Cryptographic Learning & Encryption Tool
- **Technologies**: HTML5, CSS3 (Vanilla Glassmorphism & Custom Properties), JavaScript (ES6+), W3C Web Crypto API
