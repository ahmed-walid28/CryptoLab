/**
 * CryptoLab - Playfair Cipher Module
 * 5x5 Matrix Digraph Substitution Cipher (Combining I/J)
 */

window.CryptoLab = window.CryptoLab || {};
window.CryptoLab.ciphers = window.CryptoLab.ciphers || {};

window.CryptoLab.ciphers.playfair = {
    id: 'playfair',
    name: 'Playfair Cipher',
    category: 'classical',
    type: 'Polygraphic (Digraphic) Substitution Cipher',
    formula: '5x5 Grid: Same Row (Shift Right/Left), Same Col (Shift Down/Up), Rectangle (Swap Cols)',
    keyType: 'Keyword / Keyphrase (Alphabet deduplicated into 5x5 grid)',
    securityLevel: 'Vulnerable to frequency analysis of digraphs and known-plaintext attacks.',
    purpose: 'First practical digraph substitution cipher; encrypts pairs of letters instead of singles.',
    about: {
        description: 'Invented in 1854 by Charles Wheatstone and promoted by Lord Playfair, the Playfair Cipher was the first practical system to encrypt pairs of letters (digraphs) simultaneously. By operating on 600 possible digraphs instead of 26 single letters, it significantly flattens frequency distribution.',
        advantages: [
            'Obscures single-letter frequency analysis (e.g. E is not always mapped to the same ciphertext letter).',
            'No specialized equipment required; easily performed with pen and paper using a 5x5 key matrix.',
            'Used by British forces in the Second Boer War and throughout World War I.'
        ],
        limitations: [
            'Leaves digraph frequency patterns intact (e.g. TH, HE, IN digraph frequencies can be analyzed).',
            'Reverse pairs map to reverse cipher pairs (if AB -> XY, then BA -> YX).',
            'Combining I and J creates minor ambiguity during decryption.'
        ],
        history: 'Rejected initially by the British Foreign Office as too complex, but later adopted by the military for tactical field security.'
    },
    example: {
        plaintext: 'HIDE THE GOLD IN THE TREE STUMP',
        key: 'MONARCHY',
        ciphertext: 'BMODZBXDNABEKGMODZCSVSUI'
    },

    generateMatrix(key) {
        const cleanedKey = (key || '').toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I');
        const alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'; // No 'J'
        const matrixChars = [];
        const seen = new Set();

        for (const ch of cleanedKey) {
            if (!seen.has(ch) && alphabet.includes(ch)) {
                seen.add(ch);
                matrixChars.push(ch);
            }
        }

        for (const ch of alphabet) {
            if (!seen.has(ch)) {
                seen.add(ch);
                matrixChars.push(ch);
            }
        }

        const grid = [];
        const posMap = {};

        for (let r = 0; r < 5; r++) {
            const row = [];
            for (let c = 0; c < 5; c++) {
                const char = matrixChars[r * 5 + c];
                row.push(char);
                posMap[char] = { row: r, col: c };
            }
            grid.push(row);
        }

        // Map 'J' to 'I' position for lookup
        posMap['J'] = posMap['I'];

        return { grid, posMap, flatList: matrixChars };
    },

    preparePlaintext(text) {
        const cleaned = (text || '').toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I');
        const pairs = [];
        let i = 0;

        while (i < cleaned.length) {
            const c1 = cleaned[i];
            let c2 = '';

            if (i + 1 < cleaned.length) {
                c2 = cleaned[i + 1];
                if (c1 === c2) {
                    // Duplicate letter in pair: insert 'X' (or 'Q' if c1 is 'X')
                    const filler = (c1 === 'X') ? 'Q' : 'X';
                    pairs.push({ p1: c1, p2: filler, insertedFiller: true });
                    i += 1;
                } else {
                    pairs.push({ p1: c1, p2: c2, insertedFiller: false });
                    i += 2;
                }
            } else {
                // Odd character remaining at the end
                const filler = (c1 === 'X') ? 'Q' : 'X';
                pairs.push({ p1: c1, p2: filler, insertedFiller: true, trailing: true });
                i += 1;
            }
        }

        return { cleaned, pairs };
    },

    prepareCiphertext(text) {
        const cleaned = (text || '').toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I');
        if (cleaned.length % 2 !== 0) {
            throw new Error('Playfair ciphertext must have an even number of letters.');
        }
        const pairs = [];
        for (let i = 0; i < cleaned.length; i += 2) {
            pairs.push({ c1: cleaned[i], c2: cleaned[i + 1] });
        }
        return { cleaned, pairs };
    },

    encrypt(text, key, options = {}) {
        if (!key || key.trim() === '') {
            throw new Error('Keyword is required to construct the 5x5 Playfair matrix.');
        }
        if (!text || text.trim() === '') {
            throw new Error('Plaintext input cannot be empty.');
        }

        const { grid, posMap } = this.generateMatrix(key);
        const { pairs } = this.preparePlaintext(text);
        let result = '';
        const steps = [];

        pairs.forEach((pair, idx) => {
            const { p1, p2 } = pair;
            const pos1 = posMap[p1];
            const pos2 = posMap[p2];

            let c1, c2, ruleName, ruleDesc;

            if (pos1.row === pos2.row) {
                // Same Row: shift right
                c1 = grid[pos1.row][(pos1.col + 1) % 5];
                c2 = grid[pos2.row][(pos2.col + 1) % 5];
                ruleName = 'Same Row';
                ruleDesc = `Shift right in row ${pos1.row + 1}: ${p1}(col ${pos1.col + 1}) -> ${c1}, ${p2}(col ${pos2.col + 1}) -> ${c2}`;
            } else if (pos1.col === pos2.col) {
                // Same Column: shift down
                c1 = grid[(pos1.row + 1) % 5][pos1.col];
                c2 = grid[(pos2.row + 1) % 5][pos2.col];
                ruleName = 'Same Column';
                ruleDesc = `Shift down in col ${pos1.col + 1}: ${p1}(row ${pos1.row + 1}) -> ${c1}, ${p2}(row ${pos2.row + 1}) -> ${c2}`;
            } else {
                // Rectangle: swap columns
                c1 = grid[pos1.row][pos2.col];
                c2 = grid[pos2.row][pos1.col];
                ruleName = 'Rectangle';
                ruleDesc = `Opposite corners: ${p1}(r${pos1.row + 1}, c${pos1.col + 1}) -> ${c1}(r${pos1.row + 1}, c${pos2.col + 1}), ${p2}(r${pos2.row + 1}, c${pos2.col + 1}) -> ${c2}(r${pos2.row + 1}, c${pos1.col + 1})`;
            }

            result += c1 + c2;
            steps.push({
                index: idx + 1,
                inputPair: p1 + p2,
                outputPair: c1 + c2,
                ruleName: ruleName,
                ruleDesc: ruleDesc,
                pos1: { r: pos1.row, c: pos1.col },
                pos2: { r: pos2.row, c: pos2.col }
            });
        });

        return {
            output: result,
            matrix: grid,
            steps: steps,
            preparedPairs: pairs.map(p => p.p1 + p.p2).join(' '),
            summary: `Encrypted ${pairs.length} digraph pair(s) using 5x5 matrix derived from "${key.trim()}".`
        };
    },

    decrypt(text, key, options = {}) {
        if (!key || key.trim() === '') {
            throw new Error('Keyword is required to construct the 5x5 Playfair matrix.');
        }
        if (!text || text.trim() === '') {
            throw new Error('Ciphertext input cannot be empty.');
        }

        const { grid, posMap } = this.generateMatrix(key);
        const { pairs } = this.prepareCiphertext(text);
        let result = '';
        const steps = [];

        pairs.forEach((pair, idx) => {
            const { c1, c2 } = pair;
            const pos1 = posMap[c1];
            const pos2 = posMap[c2];

            if (!pos1 || !pos2) {
                throw new Error(`Invalid characters in ciphertext: ${c1}${c2}`);
            }

            let p1, p2, ruleName, ruleDesc;

            if (pos1.row === pos2.row) {
                // Same Row: shift left (mod 5)
                p1 = grid[pos1.row][(pos1.col + 4) % 5];
                p2 = grid[pos2.row][(pos2.col + 4) % 5];
                ruleName = 'Same Row (Inverse)';
                ruleDesc = `Shift left in row ${pos1.row + 1}: ${c1}(col ${pos1.col + 1}) -> ${p1}, ${c2}(col ${pos2.col + 1}) -> ${p2}`;
            } else if (pos1.col === pos2.col) {
                // Same Column: shift up (mod 5)
                p1 = grid[(pos1.row + 4) % 5][pos1.col];
                p2 = grid[(pos2.row + 4) % 5][pos2.col];
                ruleName = 'Same Column (Inverse)';
                ruleDesc = `Shift up in col ${pos1.col + 1}: ${c1}(row ${pos1.row + 1}) -> ${p1}, ${c2}(row ${pos2.row + 1}) -> ${p2}`;
            } else {
                // Rectangle: swap columns (same rule as encryption)
                p1 = grid[pos1.row][pos2.col];
                p2 = grid[pos2.row][pos1.col];
                ruleName = 'Rectangle (Inverse)';
                ruleDesc = `Opposite corners: ${c1}(r${pos1.row + 1}, c${pos1.col + 1}) -> ${p1}(r${pos1.row + 1}, c${pos2.col + 1}), ${c2}(r${pos2.row + 1}, c${pos2.col + 1}) -> ${p2}(r${pos2.row + 1}, c${pos1.col + 1})`;
            }

            result += p1 + p2;
            steps.push({
                index: idx + 1,
                inputPair: c1 + c2,
                outputPair: p1 + p2,
                ruleName: ruleName,
                ruleDesc: ruleDesc,
                pos1: { r: pos1.row, c: pos1.col },
                pos2: { r: pos2.row, c: pos2.col }
            });
        });

        return {
            output: result,
            matrix: grid,
            steps: steps,
            preparedPairs: pairs.map(p => p.c1 + p.c2).join(' '),
            summary: `Decrypted ${pairs.length} digraph pair(s) using 5x5 matrix derived from "${key.trim()}". Note: Inverted 'I' may represent 'J', and inserted filler 'X' letters may need trimming.`
        };
    }
};
