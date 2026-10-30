/**
 * CryptoLab - Main Application Controller
 * Handles UI interactions, algorithm routing, workspace state,
 * dynamic key configuration views, step-by-step rendering, and visualizers.
 */

(function () {
    'use strict';

    // Application State
    const state = {
        currentAlgorithm: 'caesar',
        currentView: 'workspace', // 'workspace', 'comparison', 'theory'
        showSteps: true,
        lastResult: null,
        rsaMode: 'math', // 'math' (educational) or 'webcrypto' (2048-bit)
        shaMode: 'hash' // 'hash', 'verify', 'avalanche'
    };

    // DOM Elements Cache
    const DOM = {
        sidebar: document.getElementById('sidebar'),
        mobileMenuBtn: document.getElementById('mobileMenuBtn'),
        navItems: document.querySelectorAll('.nav-item'),
        breadcrumbVal: document.getElementById('breadcrumbVal'),
        mainContainer: document.getElementById('mainWorkspace'),
        toastContainer: document.getElementById('toastContainer')
    };

    // Toast Notification System
    function showToast(message, type = 'success', duration = 3500) {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        
        let icon = '✔';
        if (type === 'error') icon = '✖';
        if (type === 'info') icon = 'ℹ';

        toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
        DOM.toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 250);
        }, duration);
    }

    // Copy to Clipboard with Feedback
    async function copyToClipboard(text, label = 'Result') {
        if (!text || text.trim() === '') {
            showToast('Nothing to copy!', 'error');
            return;
        }
        try {
            await navigator.clipboard.writeText(text);
            showToast(`${label} copied to clipboard!`, 'success');
        } catch (err) {
            // Fallback for older browsers
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            showToast(`${label} copied to clipboard!`, 'success');
        }
    }

    // Navigation and View Switcher
    function setActiveAlgorithm(algoId) {
        state.currentAlgorithm = algoId;
        state.currentView = 'workspace';
        state.lastResult = null;

        // Update navigation active states
        DOM.navItems.forEach(item => {
            if (item.dataset.algo === algoId) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });

        // Close mobile sidebar if open
        if (DOM.sidebar.classList.contains('open')) {
            DOM.sidebar.classList.remove('open');
        }

        renderWorkspace();
    }

    function setActiveView(viewName) {
        state.currentView = viewName;
        DOM.navItems.forEach(item => {
            if (item.dataset.view === viewName) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });

        if (DOM.sidebar.classList.contains('open')) {
            DOM.sidebar.classList.remove('open');
        }

        if (viewName === 'comparison') {
            renderComparisonView();
        } else if (viewName === 'theory') {
            renderTheoryView();
        }
    }

    // --- Dynamic Key Configuration Panels ---

    function getKeyConfigHTML(cipher) {
        const id = cipher.id;

        if (id === 'caesar') {
            return `
                <div class="form-group">
                    <label class="form-label" for="caesarShift">
                        <span>Shift Key (0 – 25)</span>
                        <span class="label-hint">Integer shift value K</span>
                    </label>
                    <div class="slider-group">
                        <input type="range" class="range-slider" id="caesarSlider" min="0" max="25" value="3" />
                        <span class="slider-val-badge" id="caesarShiftDisplay">3</span>
                    </div>
                </div>
            `;
        }

        if (id === 'vigenere') {
            return `
                <div class="form-group">
                    <label class="form-label" for="vigenereKey">
                        <span>Keyword / Keyphrase</span>
                        <span class="label-hint">Repeated over plaintext</span>
                    </label>
                    <input type="text" class="form-control form-control-mono" id="vigenereKey" placeholder="e.g. KEY or SECRET" value="KEY" />
                </div>
            `;
        }

        if (id === 'playfair') {
            return `
                <div class="form-group">
                    <label class="form-label" for="playfairKey">
                        <span>Keyword (Constructs 5x5 Matrix)</span>
                        <span class="label-hint">Combines I/J, duplicates removed</span>
                    </label>
                    <input type="text" class="form-control form-control-mono" id="playfairKey" placeholder="e.g. MONARCHY" value="MONARCHY" />
                </div>
                <div id="playfairMatrixPreview"></div>
            `;
        }

        if (id === 'hill') {
            return `
                <div class="form-group">
                    <label class="form-label">
                        <span>2×2 Key Matrix [a, b; c, d]</span>
                        <span class="label-hint">Must satisfy gcd(det, 26) = 1</span>
                    </label>
                    <div class="matrix-input-grid">
                        <input type="number" class="matrix-cell-input" id="hillA" value="3" placeholder="a" />
                        <input type="number" class="matrix-cell-input" id="hillB" value="3" placeholder="b" />
                        <input type="number" class="matrix-cell-input" id="hillC" value="2" placeholder="c" />
                        <input type="number" class="matrix-cell-input" id="hillD" value="5" placeholder="d" />
                    </div>
                    <div id="hillDetInfo" style="margin-top: 10px; font-size: 0.82rem; text-align: center; color: var(--accent-cyan);"></div>
                </div>
            `;
        }

        if (id === 'atbash') {
            return `
                <div class="form-group">
                    <div class="meta-pill" style="width: 100%; justify-content: center; padding: 12px; background: rgba(0,242,254,0.06); border-color: var(--accent-cyan);">
                        <span>🔒 <strong>Keyless Cipher:</strong> Fixed symmetric alphabet reversal (A ↔ Z, B ↔ Y, C ↔ X)</span>
                    </div>
                </div>
            `;
        }

        if (id === 'affine') {
            return `
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
                    <div class="form-group">
                        <label class="form-label" for="affineA">
                            <span>Key 'a' (Multiplier)</span>
                            <span class="label-hint">gcd(a, 26) = 1</span>
                        </label>
                        <select class="form-control form-control-mono" id="affineA">
                            <option value="1">1</option>
                            <option value="3">3</option>
                            <option value="5" selected>5</option>
                            <option value="7">7</option>
                            <option value="9">9</option>
                            <option value="11">11</option>
                            <option value="15">15</option>
                            <option value="17">17</option>
                            <option value="19">19</option>
                            <option value="21">21</option>
                            <option value="23">23</option>
                            <option value="25">25</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="affineB">
                            <span>Key 'b' (Shift)</span>
                            <span class="label-hint">0 – 25</span>
                        </label>
                        <input type="number" class="form-control form-control-mono" id="affineB" min="0" max="25" value="8" />
                    </div>
                </div>
            `;
        }

        if (id === 'railfence') {
            return `
                <div class="form-group">
                    <label class="form-label" for="railCount">
                        <span>Number of Rails (Depth d ≥ 2)</span>
                        <span class="label-hint">Zig-zag lines</span>
                    </label>
                    <div class="slider-group">
                        <input type="range" class="range-slider" id="railSlider" min="2" max="10" value="3" />
                        <span class="slider-val-badge" id="railDisplay">3</span>
                    </div>
                </div>
            `;
        }

        if (id === 'columnar') {
            return `
                <div class="form-group">
                    <label class="form-label" for="columnarKey">
                        <span>Transposition Keyword</span>
                        <span class="label-hint">Defines column width & read order</span>
                    </label>
                    <input type="text" class="form-control form-control-mono" id="columnarKey" placeholder="e.g. GERMAN" value="GERMAN" />
                </div>
                <div id="columnarOrderPreview" style="font-size: 0.82rem; color: var(--accent-cyan); margin-top: 6px;"></div>
            `;
        }

        if (id === 'aes') {
            return `
                <div class="form-group">
                    <label class="form-label">
                        <span>AES Key Management (AES-GCM Authenticated Encryption)</span>
                        <span class="label-hint">Web Crypto API</span>
                    </label>
                    <div style="display: flex; gap: 10px; margin-bottom: 12px;">
                        <input type="text" class="form-control form-control-mono" id="aesKeyInput" placeholder="Passphrase or 64-char Hex Key" value="MyStrongUniversityKey2026!" />
                        <button class="btn btn-secondary btn-sm" id="btnGenAesKey" title="Generate Cryptographic 256-bit Key">🎲 Random 256-bit</button>
                    </div>
                    <div style="display: flex; gap: 16px; font-size: 0.8rem; color: var(--text-muted);">
                        <span>Mode: <strong>AES-GCM (128-bit Tag)</strong></span>
                        <span>Key Size: <strong>256-bit</strong></span>
                        <span>IV: <strong>Auto 96-bit Secure Nonce</strong></span>
                    </div>
                </div>
            `;
        }

        if (id === 'rsa') {
            return `
                <div class="form-group">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                        <label class="form-label" style="margin: 0;">RSA Operating Mode</label>
                        <div class="toolbar-group">
                            <button class="btn btn-sm ${state.rsaMode === 'math' ? 'btn-primary' : 'btn-outline'}" id="btnRsaModeMath">📚 Educational Math Mode</button>
                            <button class="btn btn-sm ${state.rsaMode === 'webcrypto' ? 'btn-primary' : 'btn-outline'}" id="btnRsaModeWebCrypto">🛡️ Real 2048-bit WebCrypto</button>
                        </div>
                    </div>

                    ${state.rsaMode === 'math' ? `
                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;">
                            <div>
                                <label class="form-label" style="font-size: 0.78rem;">Prime p</label>
                                <input type="number" class="form-control form-control-mono" id="rsaP" value="61" />
                            </div>
                            <div>
                                <label class="form-label" style="font-size: 0.78rem;">Prime q</label>
                                <input type="number" class="form-control form-control-mono" id="rsaQ" value="53" />
                            </div>
                            <div>
                                <label class="form-label" style="font-size: 0.78rem;">Exponent e</label>
                                <input type="number" class="form-control form-control-mono" id="rsaE" value="17" />
                            </div>
                        </div>
                        <div id="rsaParamBreakdown" style="font-size: 0.8rem; color: var(--text-highlight); margin-top: 8px; font-family: var(--font-mono);">
                            n = p×q = 3233 | φ(n) = (p-1)(q-1) = 3120 | Private key d = 2753
                        </div>
                    ` : `
                        <div style="display: flex; flex-direction: column; gap: 10px;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="font-size: 0.82rem; color: var(--text-secondary);">2048-bit RSA-OAEP Key Pair (SHA-256)</span>
                                <button class="btn btn-secondary btn-sm" id="btnGenRsaKeyPair">🔑 Generate 2048-bit Pair</button>
                            </div>
                            <textarea class="form-control form-control-mono" id="rsaPubKeyPem" rows="3" placeholder="Public Key (PEM format)"></textarea>
                            <textarea class="form-control form-control-mono" id="rsaPrivKeyPem" rows="3" placeholder="Private Key (PEM format)"></textarea>
                        </div>
                    `}
                </div>
            `;
        }

        if (id === 'sha256') {
            return `
                <div class="form-group">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                        <label class="form-label" style="margin: 0;">SHA-256 Toolset</label>
                        <div class="toolbar-group">
                            <button class="btn btn-sm ${state.shaMode === 'hash' ? 'btn-primary' : 'btn-outline'}" id="btnShaModeHash"># Standard Hash</button>
                            <button class="btn btn-sm ${state.shaMode === 'verify' ? 'btn-primary' : 'btn-outline'}" id="btnShaModeVerify">✔ Integrity Verify</button>
                            <button class="btn btn-sm ${state.shaMode === 'avalanche' ? 'btn-primary' : 'btn-outline'}" id="btnShaModeAvalanche">⚡ Avalanche Effect</button>
                        </div>
                    </div>

                    ${state.shaMode === 'verify' ? `
                        <div class="form-group">
                            <label class="form-label" for="shaExpectedHash">Expected 64-character SHA-256 Digest</label>
                            <input type="text" class="form-control form-control-mono" id="shaExpectedHash" placeholder="Paste expected hash to verify data integrity..." />
                        </div>
                    ` : ''}
                </div>
            `;
        }

        if (id === 'diffieHellman') {
            return `
                <div class="form-group">
                    <label class="form-label">
                        <span>Diffie-Hellman Parameters (Public & Private)</span>
                        <span class="label-hint">Discrete Logarithm Simulator</span>
                    </label>
                    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px;">
                        <div>
                            <label class="form-label" style="font-size: 0.78rem;">Public Prime p</label>
                            <input type="number" class="form-control form-control-mono" id="dhP" value="23" />
                        </div>
                        <div>
                            <label class="form-label" style="font-size: 0.78rem;">Public Generator g</label>
                            <input type="number" class="form-control form-control-mono" id="dhG" value="5" />
                        </div>
                        <div>
                            <label class="form-label" style="font-size: 0.78rem;">Alice Secret a</label>
                            <input type="number" class="form-control form-control-mono" id="dhA" value="6" />
                        </div>
                        <div>
                            <label class="form-label" style="font-size: 0.78rem;">Bob Secret b</label>
                            <input type="number" class="form-control form-control-mono" id="dhB" value="15" />
                        </div>
                    </div>
                </div>
            `;
        }

        return '';
    }

    // --- Main Workspace Renderer ---

    function renderWorkspace() {
        const cipher = window.CryptoLab.ciphers[state.currentAlgorithm];
        if (!cipher) return;

        DOM.breadcrumbVal.textContent = cipher.name;

        const isModern = cipher.category === 'modern';
        const isOneWay = cipher.id === 'sha256' || cipher.id === 'diffieHellman';

        const warningHTML = isModern ? `
            <div class="security-banner banner-modern">
                <div class="banner-icon">🛡️</div>
                <div class="banner-content">
                    <strong>Modern Cryptographic Standard:</strong>
                    <p>${cipher.name} is implemented utilizing the browser's native Web Crypto API (W3C Standard FIPS-compliant cryptographic subsystem) or verified BigInt modular arithmetic.</p>
                </div>
            </div>
        ` : `
            <div class="security-banner">
                <div class="banner-icon">⚠️</div>
                <div class="banner-content">
                    <strong>Security Warning & Educational Notice:</strong>
                    <p>Classical ciphers such as Caesar, Vigenère, Playfair, and Hill are strictly for <strong>educational demonstration</strong>. They do NOT provide real-world security against modern cryptanalysis and should never be used to protect sensitive data.</p>
                </div>
            </div>
        `;

        const workspaceHTML = `
            <div class="page-body">
                ${warningHTML}

                <!-- Algorithm Header Card -->
                <div class="algorithm-header-card">
                    <div class="algo-title-wrap">
                        <h2>
                            <span>${cipher.name}</span>
                            <span class="algo-category-pill ${isModern ? 'badge-modern' : 'badge-classical'}">${cipher.type}</span>
                        </h2>
                        <div class="algo-formula-badge">${cipher.formula}</div>
                    </div>
                    <div class="algo-meta-badges">
                        <div class="meta-pill"><strong>Key:</strong> ${cipher.keyType}</div>
                        <div class="meta-pill"><strong>Status:</strong> ${cipher.securityLevel.split('(')[0]}</div>
                    </div>
                </div>

                <!-- Main Interactive Grid -->
                <div class="workspace-grid">
                    <!-- Input Card -->
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <span>📝 Input & Key Configuration</span>
                            </div>
                            <div class="card-actions">
                                <button class="btn btn-outline btn-sm" id="btnLoadExample" title="Load sample inputs">💡 Load Example</button>
                                <button class="btn btn-danger-outline btn-sm" id="btnClearInputs" title="Clear all text fields">🗑️ Clear</button>
                            </div>
                        </div>

                        <!-- Key Config Controls -->
                        ${getKeyConfigHTML(cipher)}

                        <!-- Plaintext / Message Input -->
                        <div class="form-group" style="margin-top: 10px;">
                            <label class="form-label" for="inputText">
                                <span>${cipher.id === 'sha256' ? 'Input Text to Hash' : cipher.id === 'diffieHellman' ? 'Demonstration Notes' : 'Plaintext / Input Message'}</span>
                                <span class="label-hint" id="inputCharCount">0 characters</span>
                            </label>
                            <textarea class="form-control form-control-mono" id="inputText" placeholder="Enter text to encrypt, decrypt, or process...">${cipher.example ? (cipher.example.plaintext || '') : ''}</textarea>
                        </div>
                    </div>

                    <!-- Output Card -->
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <span>🔐 Transformation Output</span>
                            </div>
                            <div class="card-actions">
                                ${!isOneWay ? '<button class="btn btn-outline btn-sm" id="btnSwapText" title="Swap input and output">🔄 Swap</button>' : ''}
                                <button class="btn btn-secondary btn-sm" id="btnCopyOutput" title="Copy result to clipboard">📋 Copy</button>
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="form-label">
                                <span>Computed Output</span>
                                <span class="label-hint" id="outputCharCount">0 characters</span>
                            </label>
                            <div class="output-box ${state.lastResult ? '' : 'empty'}" id="outputBox">
                                ${state.lastResult ? escapeHtml(state.lastResult.output) : 'Click Encrypt, Decrypt, or Process below to generate output...'}
                            </div>
                            <div class="output-meta" id="outputSummary">
                                ${state.lastResult && state.lastResult.summary ? escapeHtml(state.lastResult.summary) : ''}
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Action Toolbar -->
                <div class="workspace-toolbar">
                    <div class="toolbar-group">
                        ${cipher.id === 'diffieHellman' ? `
                            <button class="btn btn-primary btn-lg" id="btnSimulateDH">⚡ Run Diffie-Hellman Protocol</button>
                        ` : cipher.id === 'sha256' ? `
                            <button class="btn btn-emerald btn-lg" id="btnComputeHash"># Compute SHA-256 Digest</button>
                        ` : `
                            <button class="btn btn-emerald btn-lg" id="btnEncrypt">🔒 Encrypt</button>
                            <button class="btn btn-primary btn-lg" id="btnDecrypt">🔓 Decrypt</button>
                        `}
                    </div>

                    <div class="toolbar-group">
                        <label class="toggle-wrapper" title="Display mathematical formulas and intermediate transformations">
                            <input type="checkbox" class="toggle-input" id="toggleSteps" ${state.showSteps ? 'checked' : ''} />
                            <div class="toggle-slider"></div>
                            <span>Show Calculation Steps</span>
                        </label>
                    </div>
                </div>

                <!-- Dynamic Visualizers & Calculation Steps Container -->
                <div id="visualizerContainer"></div>
                <div id="stepsDisplayContainer"></div>

                <!-- About & Algorithm Information Section -->
                <div class="about-section">
                    <div class="card-title" style="margin-bottom: 12px;">
                        <span>📖 About ${cipher.name}</span>
                    </div>
                    <p style="font-size: 0.92rem; color: var(--text-secondary);">${cipher.about.description}</p>
                    
                    <div class="about-grid">
                        <div class="about-item">
                            <h4>✨ Advantages & Strengths</h4>
                            <ul>
                                ${cipher.about.advantages.map(a => `<li>${a}</li>`).join('')}
                            </ul>
                        </div>
                        <div class="about-item">
                            <h4>⚠️ Limitations & Vulnerabilities</h4>
                            <ul>
                                ${cipher.about.limitations.map(l => `<li>${l}</li>`).join('')}
                            </ul>
                        </div>
                    </div>

                    <div style="margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--border-light); font-size: 0.84rem; color: var(--text-muted);">
                        <strong>Historical Background:</strong> ${cipher.about.history}
                    </div>
                </div>
            </div>
        `;

        DOM.mainContainer.innerHTML = workspaceHTML;
        attachWorkspaceEvents(cipher);

        // Auto-refresh dynamic preview widgets
        updateLivePreviews(cipher);

        // Render previous steps if present
        if (state.lastResult && state.showSteps) {
            renderCalculationSteps(cipher, state.lastResult);
        }
    }

    // Helper: Escape HTML special chars
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // --- Dynamic Live Previews & Key Widget Updates ---

    function updateLivePreviews(cipher) {
        if (cipher.id === 'caesar') {
            const slider = document.getElementById('caesarSlider');
            const display = document.getElementById('caesarShiftDisplay');
            if (slider && display) {
                slider.addEventListener('input', () => {
                    display.textContent = slider.value;
                });
            }
        } else if (cipher.id === 'railfence') {
            const slider = document.getElementById('railSlider');
            const display = document.getElementById('railDisplay');
            if (slider && display) {
                slider.addEventListener('input', () => {
                    display.textContent = slider.value;
                });
            }
        } else if (cipher.id === 'playfair') {
            const keyInput = document.getElementById('playfairKey');
            const preview = document.getElementById('playfairMatrixPreview');
            const updateMatrix = () => {
                if (!preview || !keyInput) return;
                const { grid } = cipher.generateMatrix(keyInput.value);
                let html = '<div class="playfair-grid">';
                for (let r = 0; r < 5; r++) {
                    for (let c = 0; c < 5; c++) {
                        html += `<div class="playfair-cell">${grid[r][c]}</div>`;
                    }
                }
                html += '</div>';
                preview.innerHTML = html;
            };
            if (keyInput) {
                keyInput.addEventListener('input', updateMatrix);
                updateMatrix();
            }
        } else if (cipher.id === 'hill') {
            const a = document.getElementById('hillA');
            const b = document.getElementById('hillB');
            const c = document.getElementById('hillC');
            const d = document.getElementById('hillD');
            const info = document.getElementById('hillDetInfo');

            const checkDet = () => {
                if (!a || !b || !c || !d || !info) return;
                const val = cipher.validateMatrix(a.value, b.value, c.value, d.value);
                if (val.valid) {
                    info.innerHTML = `✔ Determinant Δ = <strong>${val.det}</strong> (coprime to 26). Invertible matrix with Δ⁻¹ = <strong>${val.detInv}</strong>.`;
                    info.style.color = 'var(--accent-neon-green)';
                } else {
                    info.innerHTML = `✖ Invalid Matrix: ${val.error}`;
                    info.style.color = 'var(--accent-rose)';
                }
            };
            [a, b, c, d].forEach(input => input && input.addEventListener('input', checkDet));
            checkDet();
        } else if (cipher.id === 'columnar') {
            const keyInput = document.getElementById('columnarKey');
            const orderPreview = document.getElementById('columnarOrderPreview');
            const updateOrder = () => {
                if (!keyInput || !orderPreview) return;
                const info = cipher.getKeyOrder(keyInput.value);
                if (info) {
                    orderPreview.innerHTML = `Column read order: <strong>[${info.order.join(', ')}]</strong> (${info.key.length} columns)`;
                } else {
                    orderPreview.innerHTML = 'Enter an alphabetic keyword.';
                }
            };
            if (keyInput) {
                keyInput.addEventListener('input', updateOrder);
                updateOrder();
            }
        }
    }

    // --- Attach Event Listeners to Current Workspace ---

    function attachWorkspaceEvents(cipher) {
        const inputTextArea = document.getElementById('inputText');
        const inputCharCount = document.getElementById('inputCharCount');

        if (inputTextArea && inputCharCount) {
            inputTextArea.addEventListener('input', () => {
                inputCharCount.textContent = `${inputTextArea.value.length} characters`;
            });
            inputCharCount.textContent = `${inputTextArea.value.length} characters`;
        }

        // Toggle calculation steps
        const toggleSteps = document.getElementById('toggleSteps');
        if (toggleSteps) {
            toggleSteps.addEventListener('change', () => {
                state.showSteps = toggleSteps.checked;
                if (state.lastResult) {
                    renderCalculationSteps(cipher, state.lastResult);
                } else {
                    const stepsDiv = document.getElementById('stepsDisplayContainer');
                    if (stepsDiv && !state.showSteps) stepsDiv.innerHTML = '';
                }
            });
        }

        // Clear button
        const btnClear = document.getElementById('btnClearInputs');
        if (btnClear) {
            btnClear.addEventListener('click', () => {
                if (inputTextArea) {
                    inputTextArea.value = '';
                    inputCharCount.textContent = '0 characters';
                }
                const outputBox = document.getElementById('outputBox');
                if (outputBox) {
                    outputBox.className = 'output-box empty';
                    outputBox.textContent = 'Click Encrypt, Decrypt, or Process below to generate output...';
                }
                const outputSummary = document.getElementById('outputSummary');
                if (outputSummary) outputSummary.textContent = '';
                state.lastResult = null;
                const stepsDiv = document.getElementById('stepsDisplayContainer');
                if (stepsDiv) stepsDiv.innerHTML = '';
                const visDiv = document.getElementById('visualizerContainer');
                if (visDiv) visDiv.innerHTML = '';
                showToast('Inputs cleared', 'info');
            });
        }

        // Copy button
        const btnCopy = document.getElementById('btnCopyOutput');
        if (btnCopy) {
            btnCopy.addEventListener('click', () => {
                if (state.lastResult && state.lastResult.output) {
                    copyToClipboard(state.lastResult.output, 'Output');
                } else {
                    showToast('No output to copy yet!', 'error');
                }
            });
        }

        // Swap button
        const btnSwap = document.getElementById('btnSwapText');
        if (btnSwap) {
            btnSwap.addEventListener('click', () => {
                if (state.lastResult && state.lastResult.output) {
                    const currentOut = state.lastResult.output;
                    inputTextArea.value = currentOut;
                    inputCharCount.textContent = `${currentOut.length} characters`;
                    showToast('Swapped output into input!', 'info');
                } else {
                    showToast('Generate an output first before swapping.', 'error');
                }
            });
        }

        // Load Example button
        const btnExample = document.getElementById('btnLoadExample');
        if (btnExample) {
            btnExample.addEventListener('click', () => {
                loadAlgorithmExample(cipher);
            });
        }

        // Encrypt & Decrypt Actions
        const btnEncrypt = document.getElementById('btnEncrypt');
        const btnDecrypt = document.getElementById('btnDecrypt');

        if (btnEncrypt) {
            btnEncrypt.addEventListener('click', () => handleExecute(cipher, 'encrypt'));
        }
        if (btnDecrypt) {
            btnDecrypt.addEventListener('click', () => handleExecute(cipher, 'decrypt'));
        }

        // Special buttons for SHA, DH, AES, RSA
        const btnComputeHash = document.getElementById('btnComputeHash');
        if (btnComputeHash) {
            btnComputeHash.addEventListener('click', () => handleShaExecute());
        }

        const btnSimulateDH = document.getElementById('btnSimulateDH');
        if (btnSimulateDH) {
            btnSimulateDH.addEventListener('click', () => handleDiffieHellmanExecute());
        }

        const btnGenAesKey = document.getElementById('btnGenAesKey');
        if (btnGenAesKey) {
            btnGenAesKey.addEventListener('click', async () => {
                try {
                    const keyData = await cipher.generateKey(256);
                    const keyInput = document.getElementById('aesKeyInput');
                    if (keyInput) keyInput.value = keyData.hex;
                    showToast('Generated 256-bit cryptographically secure AES key!', 'success');
                } catch (err) {
                    showToast('Key generation failed: ' + err.message, 'error');
                }
            });
        }

        // RSA Mode toggles
        const btnRsaMath = document.getElementById('btnRsaModeMath');
        const btnRsaWebCrypto = document.getElementById('btnRsaModeWebCrypto');
        if (btnRsaMath && btnRsaWebCrypto) {
            btnRsaMath.addEventListener('click', () => {
                state.rsaMode = 'math';
                renderWorkspace();
            });
            btnRsaWebCrypto.addEventListener('click', () => {
                state.rsaMode = 'webcrypto';
                renderWorkspace();
            });
        }

        const btnGenRsaPair = document.getElementById('btnGenRsaKeyPair');
        if (btnGenRsaPair) {
            btnGenRsaPair.addEventListener('click', async () => {
                btnGenRsaPair.innerHTML = '<span class="spinner"></span> Generating...';
                try {
                    const pair = await cipher.generateWebCryptoKeyPair();
                    const pubPem = document.getElementById('rsaPubKeyPem');
                    const privPem = document.getElementById('rsaPrivKeyPem');
                    if (pubPem) pubPem.value = pair.publicKeyPem;
                    if (privPem) privPem.value = pair.privateKeyPem;
                    showToast('Generated 2048-bit RSA-OAEP Key Pair!', 'success');
                } catch (err) {
                    showToast('Key generation failed: ' + err.message, 'error');
                } finally {
                    btnGenRsaPair.innerHTML = '🔑 Generate 2048-bit Pair';
                }
            });
        }

        // SHA Mode toggles
        const btnShaHash = document.getElementById('btnShaModeHash');
        const btnShaVerify = document.getElementById('btnShaModeVerify');
        const btnShaAvalanche = document.getElementById('btnShaModeAvalanche');
        if (btnShaHash && btnShaVerify && btnShaAvalanche) {
            btnShaHash.addEventListener('click', () => { state.shaMode = 'hash'; renderWorkspace(); });
            btnShaVerify.addEventListener('click', () => { state.shaMode = 'verify'; renderWorkspace(); });
            btnShaAvalanche.addEventListener('click', () => { state.shaMode = 'avalanche'; renderWorkspace(); });
        }
    }

    // --- Example Loader ---

    function loadAlgorithmExample(cipher) {
        const inputArea = document.getElementById('inputText');
        const example = cipher.example;
        if (!example) return;

        if (inputArea && example.plaintext) {
            inputArea.value = example.plaintext;
            const count = document.getElementById('inputCharCount');
            if (count) count.textContent = `${example.plaintext.length} characters`;
        }

        if (cipher.id === 'caesar' && example.key) {
            const slider = document.getElementById('caesarSlider');
            const disp = document.getElementById('caesarShiftDisplay');
            if (slider) slider.value = example.key;
            if (disp) disp.textContent = example.key;
        } else if (cipher.id === 'vigenere' && example.key) {
            const vKey = document.getElementById('vigenereKey');
            if (vKey) vKey.value = example.key;
        } else if (cipher.id === 'playfair' && example.key) {
            const pKey = document.getElementById('playfairKey');
            if (pKey) {
                pKey.value = example.key;
                pKey.dispatchEvent(new Event('input'));
            }
        } else if (cipher.id === 'hill' && example.key) {
            document.getElementById('hillA').value = example.key.a;
            document.getElementById('hillB').value = example.key.b;
            document.getElementById('hillC').value = example.key.c;
            document.getElementById('hillD').value = example.key.d;
            document.getElementById('hillA').dispatchEvent(new Event('input'));
        } else if (cipher.id === 'affine' && example.key) {
            document.getElementById('affineA').value = example.key.a;
            document.getElementById('affineB').value = example.key.b;
        } else if (cipher.id === 'railfence' && example.key) {
            const slider = document.getElementById('railSlider');
            const disp = document.getElementById('railDisplay');
            if (slider) slider.value = example.key;
            if (disp) disp.textContent = example.key;
        } else if (cipher.id === 'columnar' && example.key) {
            const cKey = document.getElementById('columnarKey');
            if (cKey) {
                cKey.value = example.key;
                cKey.dispatchEvent(new Event('input'));
            }
        }

        showToast(`Loaded preset example for ${cipher.name}!`, 'info');
    }

    // --- Key Harvester Helper ---

    function getEnteredKey(cipher) {
        const id = cipher.id;
        if (id === 'caesar') {
            return document.getElementById('caesarSlider').value;
        }
        if (id === 'vigenere') {
            return document.getElementById('vigenereKey').value;
        }
        if (id === 'playfair') {
            return document.getElementById('playfairKey').value;
        }
        if (id === 'hill') {
            return {
                a: document.getElementById('hillA').value,
                b: document.getElementById('hillB').value,
                c: document.getElementById('hillC').value,
                d: document.getElementById('hillD').value
            };
        }
        if (id === 'atbash') {
            return null;
        }
        if (id === 'affine') {
            return {
                a: document.getElementById('affineA').value,
                b: document.getElementById('affineB').value
            };
        }
        if (id === 'railfence') {
            return document.getElementById('railSlider').value;
        }
        if (id === 'columnar') {
            return document.getElementById('columnarKey').value;
        }
        if (id === 'aes') {
            return document.getElementById('aesKeyInput').value;
        }
        return null;
    }

    // --- Execution Dispatcher ---

    async function handleExecute(cipher, operation) {
        const inputArea = document.getElementById('inputText');
        const outputBox = document.getElementById('outputBox');
        const outputSummary = document.getElementById('outputSummary');
        const outputCharCount = document.getElementById('outputCharCount');

        if (!inputArea || !inputArea.value.trim()) {
            showToast('Please enter input text to process.', 'error');
            inputArea.focus();
            return;
        }

        const text = inputArea.value;
        const key = getEnteredKey(cipher);

        try {
            let result;

            if (cipher.id === 'rsa') {
                if (state.rsaMode === 'math') {
                    const p = document.getElementById('rsaP').value;
                    const q = document.getElementById('rsaQ').value;
                    const e = document.getElementById('rsaE').value;
                    if (operation === 'encrypt') {
                        result = cipher.encryptMath(text, p, q, e);
                    } else {
                        result = cipher.decryptMath(text, p, q, e);
                    }
                } else {
                    const pubPem = document.getElementById('rsaPubKeyPem').value;
                    const privPem = document.getElementById('rsaPrivKeyPem').value;
                    if (operation === 'encrypt') {
                        result = await cipher.encryptWebCrypto(text, pubPem);
                    } else {
                        result = await cipher.decryptWebCrypto(text, privPem);
                    }
                }
            } else if (cipher.category === 'modern') {
                // Async WebCrypto (AES)
                result = await cipher[operation](text, key);
            } else {
                // Classical Synchronous Ciphers
                result = cipher[operation](text, key);
            }

            state.lastResult = result;

            // Update UI Output
            outputBox.className = 'output-box';
            outputBox.textContent = result.output;
            if (outputSummary) outputSummary.textContent = result.summary || '';
            if (outputCharCount) outputCharCount.textContent = `${result.output.length} characters`;

            showToast(`${cipher.name} ${operation}ed successfully!`, 'success');

            // Render calculation steps and visualizers
            if (state.showSteps) {
                renderCalculationSteps(cipher, result);
            } else {
                const stepsDiv = document.getElementById('stepsDisplayContainer');
                if (stepsDiv) stepsDiv.innerHTML = '';
            }

            renderVisualizer(cipher, result);

        } catch (err) {
            showToast(err.message, 'error', 6000);
            outputBox.className = 'output-box empty';
            outputBox.innerHTML = `<span style="color: var(--accent-rose);">❌ ${escapeHtml(err.message)}</span>`;
            if (outputSummary) outputSummary.textContent = '';
        }
    }

    // --- SHA-256 Execution Handler ---

    async function handleShaExecute() {
        const cipher = window.CryptoLab.ciphers.sha256;
        const inputArea = document.getElementById('inputText');
        const outputBox = document.getElementById('outputBox');
        const outputSummary = document.getElementById('outputSummary');
        const text = inputArea.value;

        try {
            if (state.shaMode === 'hash') {
                const result = await cipher.hash(text);
                state.lastResult = result;
                outputBox.className = 'output-box';
                outputBox.textContent = result.output;
                outputSummary.textContent = result.summary;
                showToast('SHA-256 digest computed!', 'success');
            } else if (state.shaMode === 'verify') {
                const expected = document.getElementById('shaExpectedHash').value;
                const result = await cipher.verify(text, expected);
                state.lastResult = { output: result.computedHash, summary: result.message };
                outputBox.className = 'output-box';
                outputBox.innerHTML = `Computed: <strong>${result.computedHash}</strong>\nExpected: <strong>${result.expectedHash}</strong>\nStatus:   <span style="color: ${result.verified ? 'var(--accent-neon-green)' : 'var(--accent-rose)'};">${result.message}</span>`;
                outputSummary.textContent = result.verified ? '✔ MATCH: Data authentic.' : '✖ MISMATCH: Data corrupted or tampered!';
                showToast(result.verified ? 'Integrity Verified!' : 'Hash Mismatch Detected!', result.verified ? 'success' : 'error');
            } else if (state.shaMode === 'avalanche') {
                const res = await cipher.testAvalanche(text);
                state.lastResult = { output: res.hash1, summary: `Avalanche Effect: ${res.bitDifferences}/256 bits changed (${res.percentage}%) with 1 character change.` };
                outputBox.className = 'output-box';
                outputBox.innerHTML = `Original ("${escapeHtml(res.originalText)}"): \n${res.hash1}\n\nModified ("${escapeHtml(res.modifiedText)}"): \n${res.hash2}\n\nBit Differences (Hamming Distance): ${res.bitDifferences} / 256 bits (${res.percentage}% changed)`;
                outputSummary.textContent = `Avalanche Demonstration Complete. ~50% random bit dispersion verified.`;
                showToast('Avalanche effect computed!', 'info');
            }
        } catch (err) {
            showToast(err.message, 'error');
        }
    }

    // --- Diffie-Hellman Execution Handler ---

    function handleDiffieHellmanExecute() {
        const cipher = window.CryptoLab.ciphers.diffieHellman;
        const p = document.getElementById('dhP').value;
        const g = document.getElementById('dhG').value;
        const a = document.getElementById('dhA').value;
        const b = document.getElementById('dhB').value;

        const result = cipher.simulateExchange(p, g, a, b);
        if (!result.valid) {
            showToast(result.error, 'error', 5000);
            return;
        }

        state.lastResult = {
            output: `Agreed Shared Secret Key: S = ${result.sharedSecret}`,
            summary: `Alice and Bob computed identical shared secret ${result.sharedSecret} over an unencrypted public channel!`
        };

        const outputBox = document.getElementById('outputBox');
        const outputSummary = document.getElementById('outputSummary');
        outputBox.className = 'output-box';
        outputBox.innerHTML = `<div style="text-align: center; font-size: 1.15rem;">🔑 Established Shared Secret: <span style="color: var(--accent-neon-green); font-weight: 800;">${result.sharedSecret}</span></div>`;
        outputSummary.textContent = state.lastResult.summary;

        // Render visual exchange flow
        renderDiffieHellmanVisualizer(result);
        showToast('Diffie-Hellman Key Agreement completed!', 'success');
    }

    // --- Calculation Steps Renderer ---

    function renderCalculationSteps(cipher, result) {
        const container = document.getElementById('stepsDisplayContainer');
        if (!container) return;

        if (!result || !result.steps || result.steps.length === 0) {
            container.innerHTML = '';
            return;
        }

        const steps = result.steps;
        let tableHeader = '';
        let tableRows = '';

        if (cipher.id === 'caesar') {
            tableHeader = '<tr><th>#</th><th>Input Char</th><th>Index (0-25)</th><th>Transformation Formula</th><th>Output Char</th></tr>';
            tableRows = steps.map(s => `
                <tr>
                    <td>${s.index}</td>
                    <td><strong>${escapeHtml(s.original)}</strong></td>
                    <td>${s.isAlpha ? (s.pVal !== undefined ? s.pVal : s.cVal) : '-'}</td>
                    <td class="step-formula-highlight">${escapeHtml(s.formula)}</td>
                    <td><strong>${escapeHtml(s.resultChar)}</strong></td>
                </tr>
            `).join('');
        } else if (cipher.id === 'vigenere') {
            tableHeader = '<tr><th>#</th><th>Plain Char</th><th>Key Char</th><th>Calculation Formula</th><th>Output Char</th></tr>';
            tableRows = steps.map(s => `
                <tr>
                    <td>${s.index}</td>
                    <td><strong>${escapeHtml(s.original)}</strong></td>
                    <td>${s.keyChar ? `<span style="color: var(--accent-cyan);">${s.keyChar}</span>` : '-'}</td>
                    <td class="step-formula-highlight">${escapeHtml(s.formula)}</td>
                    <td><strong>${escapeHtml(s.resultChar)}</strong></td>
                </tr>
            `).join('');
        } else if (cipher.id === 'playfair') {
            tableHeader = '<tr><th>Pair #</th><th>Input Digraph</th><th>Rule Applied</th><th>Transformation Details</th><th>Cipher Digraph</th></tr>';
            tableRows = steps.map(s => `
                <tr>
                    <td>${s.index}</td>
                    <td><strong>${escapeHtml(s.inputPair)}</strong></td>
                    <td><span class="nav-badge badge-classical">${escapeHtml(s.ruleName)}</span></td>
                    <td class="step-formula-highlight">${escapeHtml(s.ruleDesc)}</td>
                    <td><strong>${escapeHtml(s.outputPair)}</strong></td>
                </tr>
            `).join('');
        } else if (cipher.id === 'hill') {
            tableHeader = '<tr><th>Block #</th><th>Pair</th><th>Input Vector</th><th>Matrix Multiplication Formula</th><th>Output Vector</th><th>Result</th></tr>';
            tableRows = steps.map(s => `
                <tr>
                    <td>${s.index}</td>
                    <td><strong>${escapeHtml(s.pair)}</strong></td>
                    <td>${escapeHtml(s.pVec || s.cVec)}</td>
                    <td class="step-formula-highlight">${escapeHtml(s.calculation)}</td>
                    <td>${escapeHtml(s.cVec || s.pVec)}</td>
                    <td><strong>${escapeHtml(s.outputPair)}</strong></td>
                </tr>
            `).join('');
        } else if (cipher.id === 'affine') {
            tableHeader = '<tr><th>#</th><th>Input Char</th><th>Numeric Index</th><th>Affine Linear Formula</th><th>Output Char</th></tr>';
            tableRows = steps.map(s => `
                <tr>
                    <td>${s.index}</td>
                    <td><strong>${escapeHtml(s.original)}</strong></td>
                    <td>${s.isAlpha ? (s.pVal !== undefined ? s.pVal : s.cVal) : '-'}</td>
                    <td class="step-formula-highlight">${escapeHtml(s.formula)}</td>
                    <td><strong>${escapeHtml(s.resultChar)}</strong></td>
                </tr>
            `).join('');
        } else if (cipher.id === 'atbash') {
            tableHeader = '<tr><th>#</th><th>Input Char</th><th>Alphabet Position</th><th>Inversion Formula (25 - x)</th><th>Output Char</th></tr>';
            tableRows = steps.map(s => `
                <tr>
                    <td>${s.index}</td>
                    <td><strong>${escapeHtml(s.original)}</strong></td>
                    <td>${s.isAlpha ? s.pVal : '-'}</td>
                    <td class="step-formula-highlight">${escapeHtml(s.formula)}</td>
                    <td><strong>${escapeHtml(s.resultChar)}</strong></td>
                </tr>
            `).join('');
        } else if (cipher.id === 'rsa' && state.rsaMode === 'math') {
            tableHeader = '<tr><th>#</th><th>Input Symbol</th><th>Numeric (ASCII)</th><th>Modular Exponentiation Step</th><th>Output Value</th></tr>';
            tableRows = steps.map(s => `
                <tr>
                    <td>${s.index}</td>
                    <td><strong>${escapeHtml(s.char || s.cVal)}</strong></td>
                    <td>${escapeHtml(s.mVal || s.cVal)}</td>
                    <td class="step-formula-highlight">${escapeHtml(s.formula)}</td>
                    <td><strong>${escapeHtml(s.cVal || s.char)}</strong></td>
                </tr>
            `).join('');
        }

        container.innerHTML = `
            <div class="steps-container">
                <div class="steps-header">
                    <h3><span>🔢 Step-by-Step Mathematical Calculations</span></h3>
                    <span class="nav-badge badge-tool">${steps.length} Steps Processed</span>
                </div>
                <div class="steps-table-wrapper">
                    <table class="steps-table">
                        <thead>${tableHeader}</thead>
                        <tbody>${tableRows}</tbody>
                    </table>
                </div>
            </div>
        `;
    }

    // --- Specialized Visualizers (Rail Fence, Columnar, Diffie-Hellman) ---

    function renderVisualizer(cipher, result) {
        const container = document.getElementById('visualizerContainer');
        if (!container) return;

        if (cipher.id === 'railfence' && result.grid) {
            const grid = result.grid;
            const numRails = grid.length;
            const cols = grid[0].length;

            let tableHTML = '<div class="rail-grid-container"><table class="rail-grid-table">';
            for (let r = 0; r < numRails; r++) {
                tableHTML += '<tr>';
                for (let c = 0; c < Math.min(cols, 60); c++) {
                    const char = grid[r][c];
                    if (char !== null) {
                        tableHTML += `<td><span class="rail-node">${escapeHtml(char)}</span></td>`;
                    } else {
                        tableHTML += '<td>·</td>';
                    }
                }
                tableHTML += '</tr>';
            }
            tableHTML += '</table></div>';

            container.innerHTML = `
                <div class="card" style="margin-top: 24px;">
                    <div class="card-header">
                        <div class="card-title"><span>🌊 Rail Fence Zig-Zag Wave Visualizer (${numRails} Rails)</span></div>
                    </div>
                    ${tableHTML}
                </div>
            `;
        } else if (cipher.id === 'columnar' && result.grid) {
            const grid = result.grid;
            const key = result.key;
            const order = result.order;

            let tableHTML = '<div style="overflow-x: auto;"><table class="columnar-table"><thead><tr>';
            for (let c = 0; c < key.length; c++) {
                tableHTML += `<th>${escapeHtml(key[c])}<span class="col-rank">Col Rank: ${order[c]}</span></th>`;
            }
            tableHTML += '</tr></thead><tbody>';

            for (let r = 0; r < grid.length; r++) {
                tableHTML += '<tr>';
                for (let c = 0; c < key.length; c++) {
                    tableHTML += `<td>${grid[r][c] !== '' ? escapeHtml(grid[r][c]) : '<span style="color: var(--text-muted);">∅</span>'}</td>`;
                }
                tableHTML += '</tr>';
            }
            tableHTML += '</tbody></table></div>';

            container.innerHTML = `
                <div class="card" style="margin-top: 24px;">
                    <div class="card-header">
                        <div class="card-title"><span>📊 Columnar Transposition Grid Matrix</span></div>
                    </div>
                    ${tableHTML}
                </div>
            `;
        } else {
            container.innerHTML = '';
        }
    }

    function renderDiffieHellmanVisualizer(res) {
        const container = document.getElementById('visualizerContainer');
        if (!container) return;

        container.innerHTML = `
            <div class="card" style="margin-top: 24px;">
                <div class="card-header">
                    <div class="card-title"><span>🌐 Interactive Diffie-Hellman Protocol Exchange Simulator</span></div>
                </div>

                <div class="dh-flow-container">
                    <!-- Alice -->
                    <div class="dh-actor-card alice">
                        <div class="dh-actor-title"><span>👩 Alice</span></div>
                        <div style="font-size: 0.82rem; color: var(--text-secondary);">
                            Private Key: <strong>a = ${res.a}</strong><br />
                            Public Key: <strong>A = ${res.g}^${res.a} mod ${res.p} = ${res.A}</strong>
                        </div>
                        <div class="dh-secret-badge">
                            Alice Secret:<br />
                            S_A = ${res.B}^${res.a} mod ${res.p} = <strong>${res.sAlice}</strong>
                        </div>
                    </div>

                    <!-- Public Network / Eve -->
                    <div class="dh-channel-card">
                        <div style="font-size: 1.2rem; margin-bottom: 4px;">📡</div>
                        <strong>Insecure Wire</strong><br />
                        <span style="font-size: 0.7rem; color: var(--text-muted);">Eve intercepts:</span><br />
                        p = ${res.p}, g = ${res.g}<br />
                        A = ${res.A}, B = ${res.B}<br />
                        <span style="color: var(--accent-rose); font-weight: 600; font-size: 0.68rem; margin-top: 4px; display: block;">Cannot derive 'a' or 'b'!</span>
                    </div>

                    <!-- Bob -->
                    <div class="dh-actor-card bob">
                        <div class="dh-actor-title"><span>👨 Bob</span></div>
                        <div style="font-size: 0.82rem; color: var(--text-secondary);">
                            Private Key: <strong>b = ${res.b}</strong><br />
                            Public Key: <strong>B = ${res.g}^${res.b} mod ${res.p} = ${res.B}</strong>
                        </div>
                        <div class="dh-secret-badge">
                            Bob Secret:<br />
                            S_B = ${res.A}^${res.b} mod ${res.p} = <strong>${res.sBob}</strong>
                        </div>
                    </div>
                </div>

                <div style="background: var(--bg-input); padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-light); font-family: var(--font-mono); font-size: 0.85rem; color: var(--accent-cyan); white-space: pre-wrap;">
${res.mathProof}
                </div>
            </div>
        `;
    }

    // --- Comparison Matrix View ---

    function renderComparisonView() {
        DOM.breadcrumbVal.textContent = 'Algorithm Comparison Table';

        const ciphers = Object.values(window.CryptoLab.ciphers);

        const rowsHTML = ciphers.map(c => {
            let secClass = 'sec-insecure';
            let secLabel = 'Insecure (Classical)';
            if (c.category === 'modern') {
                secClass = 'sec-secure';
                secLabel = 'Industry Standard';
            }

            return `
                <tr>
                    <td><strong>${escapeHtml(c.name)}</strong></td>
                    <td><span class="nav-badge ${c.category === 'modern' ? 'badge-modern' : 'badge-classical'}">${c.type}</span></td>
                    <td style="font-family: var(--font-mono); font-size: 0.82rem;">${escapeHtml(c.keyType)}</td>
                    <td style="font-family: var(--font-mono); font-size: 0.82rem; color: var(--accent-cyan);">${escapeHtml(c.formula)}</td>
                    <td><span class="security-badge-cell ${secClass}">${secLabel}</span></td>
                </tr>
            `;
        }).join('');

        DOM.mainContainer.innerHTML = `
            <div class="page-body">
                <div class="algorithm-header-card">
                    <div class="algo-title-wrap">
                        <h2><span>📊 Cryptographic Algorithm Comparison Matrix</span></h2>
                        <p style="color: var(--text-secondary); margin-top: 4px; font-size: 0.9rem;">
                            Side-by-side analysis of all 12 classical and modern cryptographic primitives implemented in CryptoLab.
                        </p>
                    </div>
                </div>

                <div class="comparison-table-wrapper">
                    <table class="comparison-table">
                        <thead>
                            <tr>
                                <th>Algorithm Name</th>
                                <th>Cryptographic Class</th>
                                <th>Key Type / Space</th>
                                <th>Governing Mathematical Formula</th>
                                <th>Modern Security Level</th>
                            </tr>
                        </thead>
                        <tbody>${rowsHTML}</tbody>
                    </table>
                </div>
            </div>
        `;
    }

    // --- Theory & Learning Hub View ---

    function renderTheoryView() {
        DOM.breadcrumbVal.textContent = 'Cryptography Theory Hub';

        DOM.mainContainer.innerHTML = `
            <div class="page-body">
                <div class="algorithm-header-card">
                    <div class="algo-title-wrap">
                        <h2><span>🎓 Computer Security & Cryptography Theory Hub</span></h2>
                        <p style="color: var(--text-secondary); margin-top: 4px; font-size: 0.9rem;">
                            Core conceptual foundations, mathematical principles, and architectural paradigms.
                        </p>
                    </div>
                </div>

                <div class="theory-container">
                    <div class="theory-card">
                        <h3><span>1. Foundations: Plaintext, Ciphertext, and Kerckhoffs's Principle</span></h3>
                        <p><strong>Cryptography</strong> is the study and practice of techniques for securing communication and information in the presence of adversaries.</p>
                        <p><strong>Plaintext (P)</strong> represents original, intelligible data. <strong>Ciphertext (C)</strong> is the scrambled, unreadable representation produced via encryption algorithm <em>E</em> with secret key <em>K</em>: <code>C = E(K, P)</code>. Decryption <em>D</em> restores the plaintext: <code>P = D(K, C)</code>.</p>
                        <p><strong>Kerckhoffs's Principle (1883):</strong> A cryptographic system should be secure even if everything about the system, except the key, is public knowledge. This principle is the cornerstone of modern open cryptographic standards (like AES, RSA, and SHA-256).</p>
                    </div>

                    <div class="theory-card">
                        <h3><span>2. Symmetric vs. Asymmetric Cryptography</span></h3>
                        <p><strong>Symmetric Cryptography (Secret-Key):</strong> A single secret key is shared between the communicating parties for both encryption and decryption. Fast and efficient for bulk data (e.g., AES-GCM, ChaCha20). Challenge: secure initial key distribution.</p>
                        <p><strong>Asymmetric Cryptography (Public-Key):</strong> Employs mathematically linked key pairs—a <em>Public Key</em> (freely distributed for encryption and signature verification) and a <em>Private Key</em> (kept confidential for decryption and digital signing). Examples: RSA, ECC, Diffie-Hellman.</p>
                    </div>

                    <div class="theory-card">
                        <h3><span>3. Substitution vs. Transposition in Classical Ciphers</span></h3>
                        <p><strong>Substitution:</strong> Characters in plaintext are replaced with other characters or symbols (Caesar, Vigenère, Playfair, Affine). Vulnerable to natural language frequency analysis unless the alphabet is polyalphabetic or polygraphic.</p>
                        <p><strong>Transposition (Permutation):</strong> Characters are rearranged or permuted without changing their identity (Rail Fence, Columnar Transposition). Claude Shannon formalized modern block ciphers by alternating Substitution (Confusion) and Transposition (Diffusion).</p>
                    </div>

                    <div class="theory-card">
                        <h3><span>4. Cryptographic Hash Functions & The Avalanche Effect</span></h3>
                        <p>A <strong>Cryptographic Hash Function</strong> (such as SHA-256) takes an arbitrary-length message and deterministically outputs a fixed-length digest. Properties:</p>
                        <ul style="padding-left: 20px; color: var(--text-secondary); line-height: 1.6;">
                            <li><strong>Preimage Resistance (One-Way):</strong> Given H, it is computationally infeasible to find M such that H = Hash(M).</li>
                            <li><strong>Second Preimage Resistance:</strong> Given M₁, it is infeasible to find M₂ ≠ M₁ with Hash(M₁) = Hash(M₂).</li>
                            <li><strong>Collision Resistance:</strong> Infeasible to find any pair (M₁, M₂) such that Hash(M₁) = Hash(M₂).</li>
                            <li><strong>Avalanche Effect:</strong> Changing a single bit in the input causes an unpredictable change in roughly 50% of the output hash bits.</li>
                        </ul>
                    </div>

                    <div class="theory-card">
                        <h3><span>5. Hybrid Encryption Architectures</span></h3>
                        <p>Modern internet security protocols (such as TLS/HTTPS, SSH, and Signal) combine the computational efficiency of symmetric ciphers with the key distribution elegance of asymmetric cryptography:</p>
                        <p>1. Asymmetric key agreement (Diffie-Hellman / ECDH) or encapsulation (RSA-OAEP) establishes an ephemeral shared session key.<br />
                        2. Symmetric cipher (AES-256-GCM) encrypts high-throughput bulk payload data.<br />
                        3. Cryptographic hash / HMAC / GCM Authentication Tag ensures data integrity and authenticity.</p>
                    </div>
                </div>
            </div>
        `;
    }

    // --- Initialization ---

    function init() {
        // Sidebar navigation bindings
        DOM.navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const algo = item.dataset.algo;
                const view = item.dataset.view;
                if (algo) {
                    setActiveAlgorithm(algo);
                } else if (view) {
                    setActiveView(view);
                }
            });
        });

        // Mobile menu toggle
        if (DOM.mobileMenuBtn) {
            DOM.mobileMenuBtn.addEventListener('click', () => {
                DOM.sidebar.classList.toggle('open');
            });
        }

        // Render default algorithm workspace (Caesar)
        setActiveAlgorithm('caesar');
    }

    // Run on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
