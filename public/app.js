// ============================================
// State Management
// ============================================
const state = {
    currentAlgorithm: 'aes',
    currentTab: 'encrypt',
    signatureAlgorithm: 'rsa',
    outputFormat: 'base64',
    keys: {
        aes: { key: '' },
        rsa: { publicKey: '', privateKey: '' },
        chacha: { key: '' },
        blowfish: { key: '' },
        ecc: {
            senderPublicKey: '', senderPrivateKey: '',
            recipientPublicKey: '', recipientPrivateKey: ''
        }
    },
    fileKeys: { key: '' },
    signatureKeys: { publicKey: '', privateKey: '' },
    history: JSON.parse(localStorage.getItem('encryptionHistory') || '[]'),
    currentFile: null,
    encryptedFileData: null
};

// ============================================
// Algorithm Explanations
// ============================================
const explanations = {
    aes: {
        title: 'AES-256-GCM',
        description: `<p>AES is the <span class="highlight">gold standard</span> for symmetric encryption. It uses a <span class="highlight">Substitution-Permutation Network (SPN)</span> — your data is scrambled through a grid-based system. The "256" means a 256-bit key with 2<sup>256</sup> possible combinations.</p><p><span class="highlight">GCM mode</span> adds authentication, ensuring data hasn't been tampered with.</p>`,
        specs: [{ label: 'Key Size', value: '256 bits' }, { label: 'Block Size', value: '128 bits' }, { label: 'Type', value: 'Symmetric' }, { label: 'Mode', value: 'GCM' }]
    },
    rsa: {
        title: 'RSA-2048',
        description: `<p>RSA uses <span class="highlight">asymmetric</span> key pairs: public (encrypt) and private (decrypt). Security relies on <span class="highlight">factoring large prime numbers</span> — easy to multiply, nearly impossible to reverse.</p><p>Like a mailbox: anyone can drop in a letter, only the owner can retrieve it.</p>`,
        specs: [{ label: 'Key Size', value: '2048 bits' }, { label: 'Type', value: 'Asymmetric' }, { label: 'Based On', value: 'Primes' }, { label: 'Use Case', value: 'Key Exchange' }]
    },
    chacha: {
        title: 'ChaCha20-Poly1305',
        description: `<p>A <span class="highlight">modern stream cipher</span> designed for speed, especially on mobile devices. Uses <span class="highlight">arithmetic, XOR, and rotations</span> (the "ChaCha" dance) to generate a keystream.</p><p>Used by Google's TLS, WireGuard VPN, and many mobile apps.</p>`,
        specs: [{ label: 'Key Size', value: '256 bits' }, { label: 'Nonce', value: '192 bits' }, { label: 'Type', value: 'Stream' }, { label: 'Auth', value: 'Poly1305' }]
    },
    blowfish: {
        title: 'Blowfish',
        description: `<p>A <span class="highlight">legacy block cipher</span> from 1993 by Bruce Schneier. Uses a <span class="highlight">Feistel network</span> — data splits into halves processed through 16 rounds.</p><p>Still secure but superseded by AES. Included for educational comparison.</p>`,
        specs: [{ label: 'Key Size', value: '128 bits' }, { label: 'Block Size', value: '64 bits' }, { label: 'Rounds', value: '16' }, { label: 'Structure', value: 'Feistel' }]
    },
    ecc: {
        title: 'ECC Curve25519',
        description: `<p>Elliptic Curve Cryptography achieves <span class="highlight">RSA-equivalent security with smaller keys</span>. Based on <span class="highlight">elliptic curves</span> — finding points where the path is hard to reverse.</p><p>Curve25519 is designed for Diffie-Hellman key exchange.</p>`,
        specs: [{ label: 'Curve', value: 'Curve25519' }, { label: 'Key Size', value: '256 bits' }, { label: 'Security', value: '~128 bits' }, { label: 'Type', value: 'Key Exchange' }]
    }
};

// ============================================
// DOM Elements
// ============================================
const elements = {
    // Navigation
    navItems: document.querySelectorAll('.nav-item'),
    tabContents: document.querySelectorAll('.tab-content'),

    // Encrypt tab
    algorithmButtons: document.querySelectorAll('.algorithm-btn'),
    keysSection: document.getElementById('keysSection'),
    inputText: document.getElementById('inputText'),
    outputText: document.getElementById('outputText'),
    encryptBtn: document.getElementById('encryptBtn'),
    decryptBtn: document.getElementById('decryptBtn'),
    clearInput: document.getElementById('clearInput'),
    copyOutput: document.getElementById('copyOutput'),
    qrOutput: document.getElementById('qrOutput'),
    explanationCard: document.getElementById('explanationCard'),
    formatBtns: document.querySelectorAll('.format-btn'),

    // PBKDF2
    usePbkdf2: document.getElementById('usePbkdf2'),
    pbkdf2Inputs: document.getElementById('pbkdf2Inputs'),
    pbkdf2Password: document.getElementById('pbkdf2Password'),
    pbkdf2Iterations: document.getElementById('pbkdf2Iterations'),
    deriveKeyBtn: document.getElementById('deriveKeyBtn'),
    strengthBar: document.getElementById('strengthBar'),
    strengthLabel: document.getElementById('strengthLabel'),

    // Files tab
    fileDropzone: document.getElementById('fileDropzone'),
    fileInput: document.getElementById('fileInput'),
    fileInfo: document.getElementById('fileInfo'),
    fileName: document.getElementById('fileName'),
    fileSize: document.getElementById('fileSize'),
    fileEncryptionKey: document.getElementById('fileEncryptionKey'),
    generateFileKey: document.getElementById('generateFileKey'),
    encryptFileBtn: document.getElementById('encryptFileBtn'),
    decryptFileBtn: document.getElementById('decryptFileBtn'),
    fileResultSection: document.getElementById('fileResultSection'),
    resultFilename: document.getElementById('resultFilename'),
    resultSize: document.getElementById('resultSize'),
    downloadFileBtn: document.getElementById('downloadFileBtn'),

    // Signatures tab
    sigAlgoBtns: document.querySelectorAll('[data-sig-algo]'),
    sigPublicKey: document.getElementById('sigPublicKey'),
    sigPrivateKey: document.getElementById('sigPrivateKey'),
    generateSigKeys: document.getElementById('generateSigKeys'),
    sigMessage: document.getElementById('sigMessage'),
    signature: document.getElementById('signature'),
    signBtn: document.getElementById('signBtn'),
    verifyBtn: document.getElementById('verifyBtn'),
    verificationResult: document.getElementById('verificationResult'),
    verifyIcon: document.getElementById('verifyIcon'),
    verifyText: document.getElementById('verifyText'),

    // Hashing tab
    hashInput: document.getElementById('hashInput'),
    hashAlgoCheckboxes: document.querySelectorAll('.hash-algo-checkbox input'),
    generateHashBtn: document.getElementById('generateHashBtn'),
    hashResults: document.getElementById('hashResults'),
    hashResultsContainer: document.getElementById('hashResultsContainer'),

    // Tools tab
    qrInput: document.getElementById('qrInput'),
    generateQrBtn: document.getElementById('generateQrBtn'),
    qrDisplay: document.getElementById('qrDisplay'),
    qrImage: document.getElementById('qrImage'),
    downloadQrBtn: document.getElementById('downloadQrBtn'),
    compareInput: document.getElementById('compareInput'),
    compareBtn: document.getElementById('compareBtn'),
    comparisonResults: document.getElementById('comparisonResults'),
    benchmarkIterations: document.getElementById('benchmarkIterations'),
    runBenchmarkBtn: document.getElementById('runBenchmarkBtn'),
    benchmarkResults: document.getElementById('benchmarkResults'),
    exportKeysBtn: document.getElementById('exportKeysBtn'),
    importKeysBtn: document.getElementById('importKeysBtn'),
    importKeysInput: document.getElementById('importKeysInput'),

    // History tab
    historyList: document.getElementById('historyList'),
    historyEmpty: document.getElementById('historyEmpty'),
    clearHistoryBtn: document.getElementById('clearHistoryBtn'),

    // Global
    toast: document.getElementById('toast'),
    loadingOverlay: document.getElementById('loadingOverlay'),
    loadingText: document.getElementById('loadingText'),
    qrModal: document.getElementById('qrModal'),
    modalQrImage: document.getElementById('modalQrImage'),
    closeQrModal: document.getElementById('closeQrModal')
};

// ============================================
// Navigation
// ============================================
function switchTab(tabId) {
    state.currentTab = tabId;

    elements.navItems.forEach(item => {
        item.classList.toggle('active', item.dataset.tab === tabId);
    });

    elements.tabContents.forEach(content => {
        content.classList.toggle('active', content.id === `tab-${tabId}`);
    });
}

// ============================================
// Toast & Loading
// ============================================
function showToast(message, isError = false) {
    elements.toast.querySelector('.toast-message').textContent = message;
    elements.toast.querySelector('.toast-icon').textContent = isError ? '✗' : '✓';
    elements.toast.classList.toggle('error', isError);
    elements.toast.classList.add('show');
    setTimeout(() => elements.toast.classList.remove('show'), 3000);
}

function showLoading(text = 'Processing...') {
    elements.loadingText.textContent = text;
    elements.loadingOverlay.classList.add('show');
}

function hideLoading() {
    elements.loadingOverlay.classList.remove('show');
}

// ============================================
// Key Templates
// ============================================
function getSymmetricKeyHTML(algo, label = 'Secret Key') {
    const key = state.keys[algo]?.key || '';
    return `
        <h3>🔑 Key Management</h3>
        <div class="key-container">
            <label>🔐 ${label}</label>
            <textarea class="key-textarea" id="${algo}Key" placeholder="Generated key...">${key}</textarea>
        </div>
        <button class="btn btn-secondary" onclick="generateKey('${algo}')">⚡ Generate Key</button>
    `;
}

function getRSAKeyHTML() {
    return `
        <h3>🔑 Key Pair</h3>
        <div class="key-pair-container">
            <div class="key-container">
                <label>🔓 Public Key</label>
                <textarea class="key-textarea" id="rsaPublicKey">${state.keys.rsa.publicKey}</textarea>
            </div>
            <div class="key-container">
                <label>🔐 Private Key</label>
                <textarea class="key-textarea" id="rsaPrivateKey">${state.keys.rsa.privateKey}</textarea>
            </div>
        </div>
        <button class="btn btn-secondary" onclick="generateKey('rsa')">⚡ Generate Key Pair</button>
    `;
}

function getECCKeyHTML() {
    return `
        <h3>🔑 ECC Key Pairs</h3>
        <p style="color: var(--text-muted); margin-bottom: 1rem; font-size: 0.85rem;">For ECC, both sender and recipient need key pairs.</p>
        <div class="key-pair-container">
            <div>
                <h4 style="color: var(--accent-tertiary); margin-bottom: 0.5rem;">👤 Sender</h4>
                <div class="key-container">
                    <label>Public Key</label>
                    <textarea class="key-textarea" id="eccSenderPublicKey">${state.keys.ecc.senderPublicKey}</textarea>
                </div>
                <div class="key-container">
                    <label>Private Key</label>
                    <textarea class="key-textarea" id="eccSenderPrivateKey">${state.keys.ecc.senderPrivateKey}</textarea>
                </div>
            </div>
            <div>
                <h4 style="color: var(--accent-secondary); margin-bottom: 0.5rem;">👥 Recipient</h4>
                <div class="key-container">
                    <label>Public Key</label>
                    <textarea class="key-textarea" id="eccRecipientPublicKey">${state.keys.ecc.recipientPublicKey}</textarea>
                </div>
                <div class="key-container">
                    <label>Private Key</label>
                    <textarea class="key-textarea" id="eccRecipientPrivateKey">${state.keys.ecc.recipientPrivateKey}</textarea>
                </div>
            </div>
        </div>
        <button class="btn btn-secondary" onclick="generateKey('ecc')">⚡ Generate Both Key Pairs</button>
    `;
}

function updateKeysSection() {
    const algo = state.currentAlgorithm;
    let html = '';

    switch (algo) {
        case 'aes': html = getSymmetricKeyHTML('aes', 'AES-256 Key'); break;
        case 'rsa': html = getRSAKeyHTML(); break;
        case 'chacha': html = getSymmetricKeyHTML('chacha', 'ChaCha20 Key'); break;
        case 'blowfish': html = getSymmetricKeyHTML('blowfish', 'Blowfish Key'); break;
        case 'ecc': html = getECCKeyHTML(); break;
    }

    elements.keysSection.innerHTML = html;
}

function updateExplanation() {
    const info = explanations[state.currentAlgorithm];
    const specsHTML = info.specs.map(s => `<div class="spec-item"><span class="spec-label">${s.label}</span><span class="spec-value">${s.value}</span></div>`).join('');
    elements.explanationCard.innerHTML = `
        <div class="explanation-title">${info.title}</div>
        <div class="explanation-text">${info.description}</div>
        <div class="tech-specs">${specsHTML}</div>
    `;
}

function setActiveAlgorithm(algo) {
    state.currentAlgorithm = algo;
    elements.algorithmButtons.forEach(btn => btn.classList.toggle('active', btn.dataset.algorithm === algo));
    updateKeysSection();
    updateExplanation();
}

// ============================================
// API Functions
// ============================================
async function generateKey(algo) {
    showLoading('Generating key...');
    try {
        let endpoint = `/api/${algo}/generate-key${algo === 'rsa' || algo === 'ecc' ? 's' : ''}`;
        const response = await fetch(endpoint);
        const data = await response.json();

        if (!response.ok) throw new Error(data.error);

        if (algo === 'rsa') {
            state.keys.rsa = data;
        } else if (algo === 'ecc') {
            const response2 = await fetch(endpoint);
            const data2 = await response2.json();
            state.keys.ecc = {
                senderPublicKey: data.publicKey, senderPrivateKey: data.privateKey,
                recipientPublicKey: data2.publicKey, recipientPrivateKey: data2.privateKey
            };
        } else {
            state.keys[algo] = data;
        }

        updateKeysSection();
        showToast('Key generated!');
    } catch (e) {
        showToast(e.message, true);
    } finally {
        hideLoading();
    }
}

async function encrypt() {
    const text = elements.inputText.value.trim();
    if (!text) return showToast('Enter text to encrypt', true);

    showLoading('Encrypting...');
    try {
        const algo = state.currentAlgorithm;
        let endpoint = `/api/${algo}/encrypt`;
        let body = { text };

        switch (algo) {
            case 'aes':
                if (!state.keys.aes.key) throw new Error('Generate an AES key first');
                body.key = state.keys.aes.key;
                break;
            case 'rsa':
                if (!state.keys.rsa.publicKey) throw new Error('Generate RSA keys first');
                body.publicKey = state.keys.rsa.publicKey;
                break;
            case 'chacha':
                if (!state.keys.chacha.key) throw new Error('Generate a ChaCha key first');
                body.key = state.keys.chacha.key;
                break;
            case 'blowfish':
                if (!state.keys.blowfish.key) throw new Error('Generate a Blowfish key first');
                body.key = state.keys.blowfish.key;
                break;
            case 'ecc':
                if (!state.keys.ecc.senderPrivateKey) throw new Error('Generate ECC keys first');
                body.recipientPublicKey = state.keys.ecc.recipientPublicKey;
                body.senderPrivateKey = state.keys.ecc.senderPrivateKey;
                break;
        }

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error);

        elements.outputText.value = formatOutput(data.encrypted);
        addToHistory('encrypt', algo, text, data.encrypted);
        showToast('Encrypted!');
    } catch (e) {
        showToast(e.message, true);
    } finally {
        hideLoading();
    }
}

async function decrypt() {
    const encryptedText = elements.inputText.value.trim();
    if (!encryptedText) return showToast('Enter encrypted text', true);

    showLoading('Decrypting...');
    try {
        const algo = state.currentAlgorithm;
        let endpoint = `/api/${algo}/decrypt`;
        let body = { encryptedText };

        switch (algo) {
            case 'aes': body.key = state.keys.aes.key; break;
            case 'rsa': body.privateKey = state.keys.rsa.privateKey; break;
            case 'chacha': body.key = state.keys.chacha.key; break;
            case 'blowfish': body.key = state.keys.blowfish.key; break;
            case 'ecc':
                body.senderPublicKey = state.keys.ecc.senderPublicKey;
                body.recipientPrivateKey = state.keys.ecc.recipientPrivateKey;
                break;
        }

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error);

        elements.outputText.value = data.decrypted;
        addToHistory('decrypt', algo, encryptedText, data.decrypted);
        showToast('Decrypted!');
    } catch (e) {
        showToast(e.message, true);
    } finally {
        hideLoading();
    }
}

// ============================================
// Output Format
// ============================================
function formatOutput(data) {
    if (state.outputFormat === 'base64') return data;
    if (state.outputFormat === 'hex') {
        try {
            return btoa(atob(data).split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(''));
        } catch { return data; }
    }
    if (state.outputFormat === 'binary') {
        try {
            return atob(data).split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');
        } catch { return data; }
    }
    return data;
}

// ============================================
// PBKDF2
// ============================================
async function deriveKey() {
    const password = elements.pbkdf2Password.value;
    if (!password) return showToast('Enter a password', true);

    showLoading('Deriving key...');
    try {
        const response = await fetch('/api/derive-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                password,
                algorithm: state.currentAlgorithm,
                iterations: parseInt(elements.pbkdf2Iterations.value)
            })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error);

        state.keys[state.currentAlgorithm] = { key: data.key };
        updateKeysSection();
        showToast('Key derived from password!');
    } catch (e) {
        showToast(e.message, true);
    } finally {
        hideLoading();
    }
}

function updateKeyStrength() {
    const password = elements.pbkdf2Password.value;
    let score = 0;

    if (password.length >= 8) score += 20;
    if (password.length >= 12) score += 15;
    if (password.length >= 16) score += 10;
    if (/[a-z]/.test(password)) score += 10;
    if (/[A-Z]/.test(password)) score += 10;
    if (/[0-9]/.test(password)) score += 10;
    if (/[^a-zA-Z0-9]/.test(password)) score += 15;
    if (new Set(password).size >= password.length * 0.6) score += 10;

    score = Math.min(score, 100);

    const color = score < 40 ? '#ef4444' : score < 70 ? '#f59e0b' : '#10b981';
    const label = score < 40 ? 'Weak' : score < 70 ? 'Medium' : 'Strong';

    elements.strengthBar.style.setProperty('--strength', `${score}%`);
    elements.strengthBar.style.setProperty('--strength-color', color);
    elements.strengthLabel.textContent = label;
    elements.strengthLabel.style.color = color;
}

// ============================================
// File Encryption
// ============================================
function handleFileSelect(file) {
    if (!file) return;
    if (file.size > 50 * 1024 * 1024) {
        return showToast('File too large (max 50MB)', true);
    }

    state.currentFile = file;
    elements.fileInfo.style.display = 'flex';
    elements.fileName.textContent = file.name;
    elements.fileSize.textContent = formatFileSize(file.size);
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

async function encryptFile() {
    if (!state.currentFile) return showToast('Select a file first', true);

    const key = elements.fileEncryptionKey.value.trim();
    if (!key || key.length !== 64) return showToast('Enter a valid 64-character hex key', true);

    showLoading('Encrypting file...');
    try {
        const formData = new FormData();
        formData.append('file', state.currentFile);
        formData.append('key', key);

        const response = await fetch('/api/file/encrypt', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error);

        state.encryptedFileData = {
            data: data.encrypted,
            filename: data.filename + '.encrypted',
            isEncrypted: true
        };

        elements.fileResultSection.style.display = 'block';
        elements.resultFilename.textContent = state.encryptedFileData.filename;
        elements.resultSize.textContent = formatFileSize(data.encryptedSize);
        showToast('File encrypted!');
    } catch (e) {
        showToast(e.message, true);
    } finally {
        hideLoading();
    }
}

async function decryptFile() {
    if (!state.currentFile) return showToast('Select an encrypted file', true);

    const key = elements.fileEncryptionKey.value.trim();
    if (!key) return showToast('Enter the decryption key', true);

    showLoading('Decrypting file...');
    try {
        const reader = new FileReader();
        reader.onload = async (e) => {
            const base64Data = e.target.result.split(',')[1];

            const response = await fetch('/api/file/decrypt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    encryptedData: base64Data,
                    key,
                    filename: state.currentFile.name.replace('.encrypted', '')
                })
            });

            const data = await response.json();
            if (!response.ok) throw new Error(data.error);

            state.encryptedFileData = {
                data: data.decrypted,
                filename: data.filename,
                isEncrypted: false
            };

            elements.fileResultSection.style.display = 'block';
            elements.resultFilename.textContent = data.filename;
            elements.resultSize.textContent = formatFileSize(data.size);
            showToast('File decrypted!');
            hideLoading();
        };
        reader.readAsDataURL(state.currentFile);
    } catch (e) {
        showToast(e.message, true);
        hideLoading();
    }
}

function downloadFile() {
    if (!state.encryptedFileData) return;

    const byteCharacters = atob(state.encryptedFileData.data);
    const byteNumbers = new Array(byteCharacters.length);
    for (let i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteNumbers);
    const blob = new Blob([byteArray]);

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = state.encryptedFileData.filename;
    a.click();
    URL.revokeObjectURL(url);
}

async function generateFileKey() {
    showLoading('Generating key...');
    try {
        const response = await fetch('/api/aes/generate-key');
        const data = await response.json();
        elements.fileEncryptionKey.value = data.key;
        state.fileKeys.key = data.key;
        showToast('Key generated!');
    } catch (e) {
        showToast(e.message, true);
    } finally {
        hideLoading();
    }
}

// ============================================
// Digital Signatures
// ============================================
async function generateSignatureKeys() {
    showLoading('Generating keys...');
    try {
        const endpoint = state.signatureAlgorithm === 'rsa' ? '/api/rsa/generate-keys' : '/api/ecdsa/generate-keys';
        const response = await fetch(endpoint);
        const data = await response.json();

        if (!response.ok) throw new Error(data.error);

        state.signatureKeys = data;
        elements.sigPublicKey.value = data.publicKey;
        elements.sigPrivateKey.value = data.privateKey;
        showToast('Keys generated!');
    } catch (e) {
        showToast(e.message, true);
    } finally {
        hideLoading();
    }
}

async function signMessage() {
    const message = elements.sigMessage.value.trim();
    const privateKey = elements.sigPrivateKey.value.trim();

    if (!message || !privateKey) return showToast('Enter message and private key', true);

    showLoading('Signing...');
    try {
        const response = await fetch('/api/sign', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message, privateKey, algorithm: state.signatureAlgorithm })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error);

        elements.signature.value = data.signature;
        showToast('Message signed!');
    } catch (e) {
        showToast(e.message, true);
    } finally {
        hideLoading();
    }
}

async function verifySignature() {
    const message = elements.sigMessage.value.trim();
    const signature = elements.signature.value.trim();
    const publicKey = elements.sigPublicKey.value.trim();

    if (!message || !signature || !publicKey) return showToast('Enter message, signature, and public key', true);

    showLoading('Verifying...');
    try {
        const response = await fetch('/api/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message, signature, publicKey })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error);

        elements.verificationResult.style.display = 'flex';
        elements.verificationResult.className = `verification-result ${data.valid ? 'valid' : 'invalid'}`;
        elements.verifyIcon.textContent = data.valid ? '✓' : '✗';
        elements.verifyText.textContent = data.valid ? 'Signature is valid!' : 'Signature is invalid!';
    } catch (e) {
        showToast(e.message, true);
    } finally {
        hideLoading();
    }
}

// ============================================
// Hashing
// ============================================
async function generateHashes() {
    const text = elements.hashInput.value.trim();
    if (!text) return showToast('Enter text to hash', true);

    const selectedAlgos = Array.from(elements.hashAlgoCheckboxes)
        .filter(cb => cb.checked)
        .map(cb => cb.value);

    if (selectedAlgos.length === 0) return showToast('Select at least one algorithm', true);

    showLoading('Generating hashes...');
    try {
        const results = [];
        for (const algo of selectedAlgos) {
            const response = await fetch('/api/hash', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text, algorithm: algo })
            });
            const data = await response.json();
            if (response.ok) results.push(data);
        }

        elements.hashResults.style.display = 'block';
        elements.hashResultsContainer.innerHTML = results.map(r => `
            <div class="hash-result-item">
                <div class="hash-result-header">
                    <span class="hash-algo-name">${r.algorithm}</span>
                    <span class="algo-bits">${r.length} bits</span>
                </div>
                <div class="hash-result-value">${r.hash}</div>
            </div>
        `).join('');
        showToast('Hashes generated!');
    } catch (e) {
        showToast(e.message, true);
    } finally {
        hideLoading();
    }
}

// ============================================
// QR Code
// ============================================
async function generateQRCode(data, displayElement) {
    if (!data) return showToast('Enter data for QR code', true);
    if (data.length > 2000) return showToast('Data too large for QR (max 2000 chars)', true);

    showLoading('Generating QR...');
    try {
        const response = await fetch('/api/qr/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ data, size: 256 })
        });

        const result = await response.json();
        if (!response.ok) throw new Error(result.error);

        if (displayElement) {
            displayElement.src = result.qrCode;
            displayElement.parentElement.style.display = 'flex';
        }
        showToast('QR generated!');
        return result.qrCode;
    } catch (e) {
        showToast(e.message, true);
    } finally {
        hideLoading();
    }
}

async function showOutputQR() {
    const data = elements.outputText.value.trim();
    if (!data) return showToast('No output to generate QR', true);

    const qrCode = await generateQRCode(data, null);
    if (qrCode) {
        elements.modalQrImage.src = qrCode;
        elements.qrModal.classList.add('show');
    }
}

// ============================================
// Algorithm Comparison
// ============================================
async function compareAlgorithms() {
    const text = elements.compareInput.value.trim();
    if (!text) return showToast('Enter text to compare', true);

    showLoading('Comparing algorithms...');
    try {
        const response = await fetch('/api/compare', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error);

        elements.comparisonResults.style.display = 'block';
        elements.comparisonResults.innerHTML = `
            <table class="comparison-table">
                <thead>
                    <tr><th>Algorithm</th><th>Key Size</th><th>Output Length</th></tr>
                </thead>
                <tbody>
                    ${Object.values(data.results).map(r => `
                        <tr>
                            <td>${r.name}</td>
                            <td>${r.keySize} bits</td>
                            <td>${r.outputLength} chars</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
        showToast('Comparison complete!');
    } catch (e) {
        showToast(e.message, true);
    } finally {
        hideLoading();
    }
}

// ============================================
// Benchmark
// ============================================
async function runBenchmark() {
    const iterations = parseInt(elements.benchmarkIterations.value) || 100;

    showLoading('Running benchmark...');
    try {
        const response = await fetch('/api/benchmark', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ iterations })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error);

        const maxOps = Math.max(...Object.values(data.results).map(r => r.opsPerSec));

        elements.benchmarkResults.style.display = 'block';
        elements.benchmarkResults.innerHTML = `
            <p style="color: var(--text-muted); margin-bottom: 1rem;">Tested ${data.iterations} iterations</p>
            <table class="benchmark-table">
                <thead>
                    <tr><th>Algorithm</th><th>Avg Time</th><th>Ops/sec</th><th>Performance</th></tr>
                </thead>
                <tbody>
                    ${Object.entries(data.results).map(([algo, r]) => `
                        <tr>
                            <td>${algo.toUpperCase()}</td>
                            <td>${r.avgTime}ms</td>
                            <td>${r.opsPerSec.toLocaleString()}</td>
                            <td><div class="benchmark-bar" style="width: ${(r.opsPerSec / maxOps) * 100}%"></div></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
        showToast('Benchmark complete!');
    } catch (e) {
        showToast(e.message, true);
    } finally {
        hideLoading();
    }
}

// ============================================
// Key Export/Import
// ============================================
function exportKeys() {
    const keys = {
        aes: state.keys.aes,
        rsa: state.keys.rsa,
        chacha: state.keys.chacha,
        blowfish: state.keys.blowfish,
        ecc: state.keys.ecc,
        signature: state.signatureKeys
    };

    const blob = new Blob([JSON.stringify(keys, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ecdc-keys.json';
    a.click();
    URL.revokeObjectURL(url);
    showToast('Keys exported!');
}

function importKeys(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const keys = JSON.parse(e.target.result);
            if (keys.aes) state.keys.aes = keys.aes;
            if (keys.rsa) state.keys.rsa = keys.rsa;
            if (keys.chacha) state.keys.chacha = keys.chacha;
            if (keys.blowfish) state.keys.blowfish = keys.blowfish;
            if (keys.ecc) state.keys.ecc = keys.ecc;
            if (keys.signature) state.signatureKeys = keys.signature;
            updateKeysSection();
            showToast('Keys imported!');
        } catch {
            showToast('Invalid key file', true);
        }
    };
    reader.readAsText(file);
}

// ============================================
// History
// ============================================
function addToHistory(action, algorithm, input, output) {
    const entry = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        action,
        algorithm,
        input: input.substring(0, 100),
        output: output.substring(0, 100)
    };

    state.history.unshift(entry);
    if (state.history.length > 50) state.history.pop();
    localStorage.setItem('encryptionHistory', JSON.stringify(state.history));
    renderHistory();
}

function renderHistory() {
    if (state.history.length === 0) {
        elements.historyEmpty.style.display = 'block';
        elements.historyList.innerHTML = '';
        elements.historyList.appendChild(elements.historyEmpty);
        return;
    }

    elements.historyEmpty.style.display = 'none';
    elements.historyList.innerHTML = state.history.map(entry => `
        <div class="history-item">
            <div class="history-item-header">
                <span class="history-algo">${entry.algorithm.toUpperCase()} - ${entry.action}</span>
                <span class="history-time">${new Date(entry.timestamp).toLocaleString()}</span>
            </div>
            <div class="history-preview">${entry.output}...</div>
            <div class="history-actions">
                <button class="btn btn-secondary" onclick="copyHistoryOutput('${entry.output}')">📋 Copy</button>
            </div>
        </div>
    `).join('');
}

function copyHistoryOutput(text) {
    navigator.clipboard.writeText(text);
    showToast('Copied!');
}

function clearHistory() {
    state.history = [];
    localStorage.removeItem('encryptionHistory');
    renderHistory();
    showToast('History cleared!');
}

// ============================================
// Event Listeners
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    // Navigation
    elements.navItems.forEach(item => {
        item.addEventListener('click', () => switchTab(item.dataset.tab));
    });

    // Algorithm selection
    elements.algorithmButtons.forEach(btn => {
        btn.addEventListener('click', () => setActiveAlgorithm(btn.dataset.algorithm));
    });

    // Encrypt/Decrypt
    elements.encryptBtn.addEventListener('click', encrypt);
    elements.decryptBtn.addEventListener('click', decrypt);
    elements.clearInput.addEventListener('click', () => {
        elements.inputText.value = '';
        elements.outputText.value = '';
    });
    elements.copyOutput.addEventListener('click', () => {
        navigator.clipboard.writeText(elements.outputText.value);
        showToast('Copied!');
    });
    elements.qrOutput.addEventListener('click', showOutputQR);

    // Output format
    elements.formatBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            elements.formatBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state.outputFormat = btn.dataset.format;
        });
    });

    // PBKDF2
    elements.usePbkdf2.addEventListener('change', (e) => {
        elements.pbkdf2Inputs.style.display = e.target.checked ? 'block' : 'none';
    });
    elements.pbkdf2Password.addEventListener('input', updateKeyStrength);
    elements.deriveKeyBtn.addEventListener('click', deriveKey);

    // File handling
    elements.fileDropzone.addEventListener('click', () => elements.fileInput.click());
    elements.fileInput.addEventListener('change', (e) => handleFileSelect(e.target.files[0]));
    elements.fileDropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        elements.fileDropzone.classList.add('dragover');
    });
    elements.fileDropzone.addEventListener('dragleave', () => {
        elements.fileDropzone.classList.remove('dragover');
    });
    elements.fileDropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        elements.fileDropzone.classList.remove('dragover');
        handleFileSelect(e.dataTransfer.files[0]);
    });
    elements.generateFileKey.addEventListener('click', generateFileKey);
    elements.encryptFileBtn.addEventListener('click', encryptFile);
    elements.decryptFileBtn.addEventListener('click', decryptFile);
    elements.downloadFileBtn.addEventListener('click', downloadFile);

    // Signatures
    elements.sigAlgoBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            elements.sigAlgoBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state.signatureAlgorithm = btn.dataset.sigAlgo;
        });
    });
    elements.generateSigKeys.addEventListener('click', generateSignatureKeys);
    elements.signBtn.addEventListener('click', signMessage);
    elements.verifyBtn.addEventListener('click', verifySignature);

    // Hashing
    elements.hashAlgoCheckboxes.forEach(cb => {
        cb.addEventListener('change', () => {
            cb.closest('.hash-algo-checkbox').classList.toggle('checked', cb.checked);
        });
    });
    elements.generateHashBtn.addEventListener('click', generateHashes);

    // Tools
    elements.generateQrBtn.addEventListener('click', () => generateQRCode(elements.qrInput.value, elements.qrImage));
    elements.downloadQrBtn.addEventListener('click', () => {
        const a = document.createElement('a');
        a.href = elements.qrImage.src;
        a.download = 'qrcode.png';
        a.click();
    });
    elements.compareBtn.addEventListener('click', compareAlgorithms);
    elements.runBenchmarkBtn.addEventListener('click', runBenchmark);
    elements.exportKeysBtn.addEventListener('click', exportKeys);
    elements.importKeysBtn.addEventListener('click', () => elements.importKeysInput.click());
    elements.importKeysInput.addEventListener('change', (e) => importKeys(e.target.files[0]));

    // History
    elements.clearHistoryBtn.addEventListener('click', clearHistory);

    // Modal
    elements.closeQrModal.addEventListener('click', () => elements.qrModal.classList.remove('show'));
    elements.qrModal.addEventListener('click', (e) => {
        if (e.target === elements.qrModal) elements.qrModal.classList.remove('show');
    });

    // Initialize
    updateKeysSection();
    updateExplanation();
    renderHistory();

    // Initialize AOS animations
    if (typeof AOS !== 'undefined') {
        AOS.init({
            duration: 600,
            easing: 'ease-out-cubic',
            once: true,
            offset: 50
        });
    }

    // Add haptic feedback for mobile (if supported)
    const addHapticFeedback = (element) => {
        element.addEventListener('click', () => {
            if (navigator.vibrate) {
                navigator.vibrate(10);
            }
        });
    };

    // Apply haptic to all buttons
    document.querySelectorAll('.btn, .algorithm-btn, .nav-item').forEach(addHapticFeedback);
});

// Enhanced copy with animation feedback
function copyWithFeedback(button, text) {
    navigator.clipboard.writeText(text).then(() => {
        button.classList.add('copied');
        const originalContent = button.innerHTML;
        button.innerHTML = '✓';

        setTimeout(() => {
            button.classList.remove('copied');
            button.innerHTML = originalContent;
        }, 1500);

        showToast('Copied to clipboard!');
    }).catch(() => {
        showToast('Failed to copy', true);
    });
}

// Make functions globally accessible
window.generateKey = generateKey;
window.copyHistoryOutput = copyHistoryOutput;
window.copyWithFeedback = copyWithFeedback;
