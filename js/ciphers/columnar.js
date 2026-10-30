/**
 * CryptoLab - Columnar Transposition Cipher Module
 * Transposition Cipher with Keyword-driven Column Permutation
 */

window.CryptoLab = window.CryptoLab || {};
window.CryptoLab.ciphers = window.CryptoLab.ciphers || {};

window.CryptoLab.ciphers.columnar = {
    id: 'columnar',
    name: 'Columnar Transposition Cipher',
    category: 'classical',
    type: 'Transposition (Grid Permutation) Cipher',
    formula: 'Write row-by-row in W columns; read column-by-column in key alphabetical order',
    keyType: 'Alphabetic Keyword / Keyphrase',
    securityLevel: 'Vulnerable to multiple anagramming, digraph frequency analysis, and known-plaintext attacks.',
    purpose: 'Demonstrates key-ordered permutation matrices and diffusion principles.',
    about: {
        description: 'The Columnar Transposition Cipher writes plaintext into a grid of predetermined width (the length of a keyword) row by row, and then produces ciphertext by reading the columns out in the alphabetical order of the letters in the keyword.',
        advantages: [
            'Scrambles adjacent characters over large spans, providing good diffusion.',
            'Variable width determined by the keyword length creates flexible block sizes.',
            'Can be applied multiple times (Double Transposition) for significantly increased strength.'
        ],
        limitations: [
            'Preserves character frequency counts identical to original plaintext.',
            'Vulnerable to anagramming techniques where column strips are aligned to reconstruct common English digraphs.',
            'Vulnerable to known-plaintext attacks.'
        ],
        history: 'Used extensively in World War I and World War II by multiple intelligence services (e.g. the British SOE and German VIC cipher).'
    },
    example: {
        plaintext: 'DEFEND THE EAST WALL OF THE CASTLE',
        key: 'GERMAN',
        ciphertext: 'ETLESHLEFLTEFAWDAODNEATCSC'
    },

    getKeyOrder(key) {
        const cleanedKey = (key || '').toUpperCase().replace(/[^A-Z]/g, '');
        if (cleanedKey.length === 0) {
            return null;
        }

        // Pair each char with its original index
        const indexedKey = cleanedKey.split('').map((char, index) => ({ char, index }));

        // Stable sort alphabetically
        indexedKey.sort((a, b) => {
            if (a.char < b.char) return -1;
            if (a.char > b.char) return 1;
            return a.index - b.index;
        });

        // Assign rank 1..N
        const order = Array(cleanedKey.length);
        indexedKey.forEach((item, rank) => {
            order[item.index] = rank + 1;
        });

        return {
            key: cleanedKey,
            order: order, // rank of each column from left to right (1..N)
            sortedIndices: indexedKey.map(item => item.index) // original column indices in alphabetical order
        };
    },

    encrypt(text, key, options = {}) {
        if (!key || key.trim() === '') {
            throw new Error('Keyword is required for Columnar Transposition.');
        }
        if (!text || text.trim() === '') {
            throw new Error('Plaintext input cannot be empty.');
        }

        const keyInfo = this.getKeyOrder(key);
        if (!keyInfo) {
            throw new Error('Keyword must contain at least one alphabetic letter (A-Z).');
        }

        const numCols = keyInfo.key.length;
        const cleanedText = text.replace(/[\r\n\t]/g, ' ');
        const textLen = cleanedText.length;
        const numRows = Math.ceil(textLen / numCols);

        // Populate row-by-row grid
        const grid = [];
        let charIdx = 0;

        for (let r = 0; r < numRows; r++) {
            const row = [];
            for (let c = 0; c < numCols; c++) {
                if (charIdx < textLen) {
                    row.push(cleanedText[charIdx++]);
                } else {
                    row.push(''); // empty cell in irregular grid
                }
            }
            grid.push(row);
        }

        // Read out columns in alphabetical order of keyword letters
        let result = '';
        const columnBreakdown = [];

        keyInfo.sortedIndices.forEach((colIdx, rankIdx) => {
            let colStr = '';
            for (let r = 0; r < numRows; r++) {
                if (grid[r][colIdx] !== '') {
                    colStr += grid[r][colIdx];
                    result += grid[r][colIdx];
                }
            }
            columnBreakdown.push({
                rank: rankIdx + 1,
                colIndex: colIdx + 1,
                keyChar: keyInfo.key[colIdx],
                content: colStr
            });
        });

        return {
            output: result,
            key: keyInfo.key,
            order: keyInfo.order,
            sortedIndices: keyInfo.sortedIndices,
            numCols: numCols,
            numRows: numRows,
            grid: grid,
            columnBreakdown: columnBreakdown,
            summary: `Arranged in ${numRows} rows × ${numCols} columns (Keyword "${keyInfo.key}"). Read out in alphabetical order: [${keyInfo.order.join(', ')}].`
        };
    },

    decrypt(text, key, options = {}) {
        if (!key || key.trim() === '') {
            throw new Error('Keyword is required for Columnar Transposition.');
        }
        if (!text || text.trim() === '') {
            throw new Error('Ciphertext input cannot be empty.');
        }

        const keyInfo = this.getKeyOrder(key);
        if (!keyInfo) {
            throw new Error('Keyword must contain at least one alphabetic letter (A-Z).');
        }

        const numCols = keyInfo.key.length;
        const textLen = text.length;
        const numRows = Math.ceil(textLen / numCols);
        const fullColsCount = textLen % numCols === 0 ? numCols : textLen % numCols;
        const shortColLen = Math.floor(textLen / numCols);
        const longColLen = shortColLen + 1;

        // Calculate length for each column 0..numCols-1
        const colLengths = Array(numCols).fill(shortColLen);
        for (let c = 0; c < fullColsCount; c++) {
            colLengths[c] = longColLen;
        }

        // Fill columns in alphabetical key order
        const columns = Array.from({ length: numCols }, () => []);
        let textIdx = 0;
        const columnBreakdown = [];

        keyInfo.sortedIndices.forEach((colIdx, rankIdx) => {
            const lengthOfThisCol = colLengths[colIdx];
            let colStr = '';
            for (let i = 0; i < lengthOfThisCol; i++) {
                if (textIdx < textLen) {
                    const ch = text[textIdx++];
                    columns[colIdx].push(ch);
                    colStr += ch;
                }
            }
            columnBreakdown.push({
                rank: rankIdx + 1,
                colIndex: colIdx + 1,
                keyChar: keyInfo.key[colIdx],
                content: colStr
            });
        });

        // Reconstruct grid and read row by row
        const grid = [];
        let result = '';

        for (let r = 0; r < numRows; r++) {
            const row = [];
            for (let c = 0; c < numCols; c++) {
                if (r < columns[c].length) {
                    const ch = columns[c][r];
                    row.push(ch);
                    result += ch;
                } else {
                    row.push('');
                }
            }
            grid.push(row);
        }

        return {
            output: result,
            key: keyInfo.key,
            order: keyInfo.order,
            sortedIndices: keyInfo.sortedIndices,
            numCols: numCols,
            numRows: numRows,
            grid: grid,
            columnBreakdown: columnBreakdown,
            summary: `Reconstructed ${numRows}×${numCols} grid from column segments and read row-by-row.`
        };
    }
};
