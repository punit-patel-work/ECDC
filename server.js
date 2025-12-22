const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const Blowfish = require('egoroof-blowfish');
const multer = require('multer');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// ============================================
// AES-256-GCM Endpoints
// ============================================

app.get('/api/aes/generate-key', (req, res) => {
    try {
        const key = crypto.randomBytes(32).toString('hex');
        res.json({ key });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate AES key' });
    }
});

app.post('/api/aes/encrypt', (req, res) => {
    try {
        const { text, key } = req.body;
        if (!text || !key) {
            return res.status(400).json({ error: 'Text and key are required' });
        }

        const keyBuffer = Buffer.from(key, 'hex');
        if (keyBuffer.length !== 32) {
            return res.status(400).json({ error: 'Key must be 64 hex characters (256 bits)' });
        }

        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);

        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag().toString('hex');

        res.json({
            encrypted: `${iv.toString('hex')}:${authTag}:${encrypted}`
        });
    } catch (error) {
        res.status(500).json({ error: 'Encryption failed: ' + error.message });
    }
});

app.post('/api/aes/decrypt', (req, res) => {
    try {
        const { encryptedText, key } = req.body;
        if (!encryptedText || !key) {
            return res.status(400).json({ error: 'Encrypted text and key are required' });
        }

        const keyBuffer = Buffer.from(key, 'hex');
        const parts = encryptedText.split(':');
        if (parts.length !== 3) {
            return res.status(400).json({ error: 'Invalid encrypted format' });
        }

        const [ivHex, authTagHex, encrypted] = parts;
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');

        const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        res.json({ decrypted });
    } catch (error) {
        res.status(500).json({ error: 'Decryption failed: ' + error.message });
    }
});

// ============================================
// RSA-2048 Endpoints
// ============================================

app.get('/api/rsa/generate-keys', (req, res) => {
    try {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        res.json({ publicKey, privateKey });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate RSA keys' });
    }
});

app.post('/api/rsa/encrypt', (req, res) => {
    try {
        const { text, publicKey } = req.body;
        if (!text || !publicKey) {
            return res.status(400).json({ error: 'Text and public key are required' });
        }

        const encrypted = crypto.publicEncrypt(
            { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
            Buffer.from(text, 'utf8')
        );
        res.json({ encrypted: encrypted.toString('base64') });
    } catch (error) {
        res.status(500).json({ error: 'Encryption failed: ' + error.message });
    }
});

app.post('/api/rsa/decrypt', (req, res) => {
    try {
        const { encryptedText, privateKey } = req.body;
        if (!encryptedText || !privateKey) {
            return res.status(400).json({ error: 'Encrypted text and private key are required' });
        }

        const decrypted = crypto.privateDecrypt(
            { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
            Buffer.from(encryptedText, 'base64')
        );
        res.json({ decrypted: decrypted.toString('utf8') });
    } catch (error) {
        res.status(500).json({ error: 'Decryption failed: ' + error.message });
    }
});

// ============================================
// ChaCha20-Poly1305 Endpoints
// ============================================

app.get('/api/chacha/generate-key', (req, res) => {
    try {
        const key = nacl.randomBytes(32);
        res.json({ key: naclUtil.encodeBase64(key) });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate ChaCha key' });
    }
});

app.post('/api/chacha/encrypt', (req, res) => {
    try {
        const { text, key } = req.body;
        if (!text || !key) {
            return res.status(400).json({ error: 'Text and key are required' });
        }

        const keyBytes = naclUtil.decodeBase64(key);
        const nonce = nacl.randomBytes(24);
        const messageBytes = naclUtil.decodeUTF8(text);
        const encrypted = nacl.secretbox(messageBytes, nonce, keyBytes);

        res.json({
            encrypted: naclUtil.encodeBase64(nonce) + ':' + naclUtil.encodeBase64(encrypted)
        });
    } catch (error) {
        res.status(500).json({ error: 'Encryption failed: ' + error.message });
    }
});

app.post('/api/chacha/decrypt', (req, res) => {
    try {
        const { encryptedText, key } = req.body;
        if (!encryptedText || !key) {
            return res.status(400).json({ error: 'Encrypted text and key are required' });
        }

        const keyBytes = naclUtil.decodeBase64(key);
        const [nonceB64, encryptedB64] = encryptedText.split(':');
        const nonce = naclUtil.decodeBase64(nonceB64);
        const encrypted = naclUtil.decodeBase64(encryptedB64);

        const decrypted = nacl.secretbox.open(encrypted, nonce, keyBytes);
        if (!decrypted) {
            return res.status(400).json({ error: 'Decryption failed - invalid key or corrupted data' });
        }
        res.json({ decrypted: naclUtil.encodeUTF8(decrypted) });
    } catch (error) {
        res.status(500).json({ error: 'Decryption failed: ' + error.message });
    }
});

// ============================================
// Blowfish Endpoints
// ============================================

app.get('/api/blowfish/generate-key', (req, res) => {
    try {
        const key = crypto.randomBytes(16).toString('hex');
        res.json({ key });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate Blowfish key' });
    }
});

app.post('/api/blowfish/encrypt', (req, res) => {
    try {
        const { text, key } = req.body;
        if (!text || !key) {
            return res.status(400).json({ error: 'Text and key are required' });
        }

        const bf = new Blowfish(key, Blowfish.MODE.ECB, Blowfish.PADDING.PKCS5);
        const encoded = bf.encode(text);
        res.json({ encrypted: Buffer.from(encoded).toString('base64') });
    } catch (error) {
        res.status(500).json({ error: 'Encryption failed: ' + error.message });
    }
});

app.post('/api/blowfish/decrypt', (req, res) => {
    try {
        const { encryptedText, key } = req.body;
        if (!encryptedText || !key) {
            return res.status(400).json({ error: 'Encrypted text and key are required' });
        }

        const bf = new Blowfish(key, Blowfish.MODE.ECB, Blowfish.PADDING.PKCS5);
        const encryptedBytes = Uint8Array.from(Buffer.from(encryptedText, 'base64'));
        const decrypted = bf.decode(encryptedBytes, Blowfish.TYPE.STRING);
        res.json({ decrypted });
    } catch (error) {
        res.status(500).json({ error: 'Decryption failed: ' + error.message });
    }
});

// ============================================
// ECC (Curve25519) Endpoints
// ============================================

app.get('/api/ecc/generate-keys', (req, res) => {
    try {
        const keyPair = nacl.box.keyPair();
        res.json({
            publicKey: naclUtil.encodeBase64(keyPair.publicKey),
            privateKey: naclUtil.encodeBase64(keyPair.secretKey)
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate ECC keys' });
    }
});

app.post('/api/ecc/encrypt', (req, res) => {
    try {
        const { text, recipientPublicKey, senderPrivateKey } = req.body;
        if (!text || !recipientPublicKey || !senderPrivateKey) {
            return res.status(400).json({ error: 'Text, recipient public key, and sender private key are required' });
        }

        const recipientPubKeyBytes = naclUtil.decodeBase64(recipientPublicKey);
        const senderSecKeyBytes = naclUtil.decodeBase64(senderPrivateKey);
        const nonce = nacl.randomBytes(24);
        const messageBytes = naclUtil.decodeUTF8(text);
        const encrypted = nacl.box(messageBytes, nonce, recipientPubKeyBytes, senderSecKeyBytes);

        res.json({
            encrypted: naclUtil.encodeBase64(nonce) + ':' + naclUtil.encodeBase64(encrypted)
        });
    } catch (error) {
        res.status(500).json({ error: 'Encryption failed: ' + error.message });
    }
});

app.post('/api/ecc/decrypt', (req, res) => {
    try {
        const { encryptedText, senderPublicKey, recipientPrivateKey } = req.body;
        if (!encryptedText || !senderPublicKey || !recipientPrivateKey) {
            return res.status(400).json({ error: 'Encrypted text, sender public key, and recipient private key are required' });
        }

        const [nonceB64, encryptedB64] = encryptedText.split(':');
        const nonce = naclUtil.decodeBase64(nonceB64);
        const encrypted = naclUtil.decodeBase64(encryptedB64);
        const senderPubKeyBytes = naclUtil.decodeBase64(senderPublicKey);
        const recipientSecKeyBytes = naclUtil.decodeBase64(recipientPrivateKey);

        const decrypted = nacl.box.open(encrypted, nonce, senderPubKeyBytes, recipientSecKeyBytes);
        if (!decrypted) {
            return res.status(400).json({ error: 'Decryption failed - invalid keys or corrupted data' });
        }
        res.json({ decrypted: naclUtil.encodeUTF8(decrypted) });
    } catch (error) {
        res.status(500).json({ error: 'Decryption failed: ' + error.message });
    }
});

// ============================================
// PBKDF2 Key Derivation
// ============================================

app.post('/api/derive-key', (req, res) => {
    try {
        const { password, salt, algorithm, iterations = 100000 } = req.body;
        if (!password) {
            return res.status(400).json({ error: 'Password is required' });
        }

        const saltBuffer = salt ? Buffer.from(salt, 'utf8') : crypto.randomBytes(16);
        let keyLength = 32; // Default for AES-256

        if (algorithm === 'blowfish') keyLength = 16;

        const derivedKey = crypto.pbkdf2Sync(password, saltBuffer, iterations, keyLength, 'sha256');

        res.json({
            key: derivedKey.toString('hex'),
            salt: saltBuffer.toString('hex'),
            iterations,
            algorithm: algorithm || 'aes'
        });
    } catch (error) {
        res.status(500).json({ error: 'Key derivation failed: ' + error.message });
    }
});

// ============================================
// Digital Signatures (RSA & ECDSA)
// ============================================

app.get('/api/ecdsa/generate-keys', (req, res) => {
    try {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
            namedCurve: 'prime256v1',
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        res.json({ publicKey, privateKey });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate ECDSA keys' });
    }
});

app.post('/api/sign', (req, res) => {
    try {
        const { message, privateKey, algorithm = 'rsa' } = req.body;
        if (!message || !privateKey) {
            return res.status(400).json({ error: 'Message and private key are required' });
        }

        const sign = crypto.createSign('SHA256');
        sign.update(message);
        sign.end();

        const signature = sign.sign(privateKey, 'base64');
        res.json({ signature, algorithm });
    } catch (error) {
        res.status(500).json({ error: 'Signing failed: ' + error.message });
    }
});

app.post('/api/verify', (req, res) => {
    try {
        const { message, signature, publicKey } = req.body;
        if (!message || !signature || !publicKey) {
            return res.status(400).json({ error: 'Message, signature, and public key are required' });
        }

        const verify = crypto.createVerify('SHA256');
        verify.update(message);
        verify.end();

        const isValid = verify.verify(publicKey, signature, 'base64');
        res.json({ valid: isValid });
    } catch (error) {
        res.status(500).json({ error: 'Verification failed: ' + error.message });
    }
});

// ============================================
// Hash Generation
// ============================================

app.post('/api/hash', (req, res) => {
    try {
        const { text, algorithm = 'sha256' } = req.body;
        if (!text) {
            return res.status(400).json({ error: 'Text is required' });
        }

        const supportedAlgorithms = ['md5', 'sha1', 'sha256', 'sha512', 'sha3-256', 'sha3-512'];
        if (!supportedAlgorithms.includes(algorithm.toLowerCase())) {
            return res.status(400).json({ error: `Unsupported algorithm. Use: ${supportedAlgorithms.join(', ')}` });
        }

        const hash = crypto.createHash(algorithm.toLowerCase());
        hash.update(text);
        const digest = hash.digest('hex');

        res.json({
            hash: digest,
            algorithm: algorithm.toLowerCase(),
            length: digest.length * 4 // bits
        });
    } catch (error) {
        res.status(500).json({ error: 'Hashing failed: ' + error.message });
    }
});

// ============================================
// File Encryption/Decryption
// ============================================

app.post('/api/file/encrypt', upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const { key, algorithm = 'aes' } = req.body;
        if (!key) {
            return res.status(400).json({ error: 'Encryption key is required' });
        }

        const keyBuffer = Buffer.from(key, 'hex');
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);

        const encrypted = Buffer.concat([cipher.update(req.file.buffer), cipher.final()]);
        const authTag = cipher.getAuthTag();

        // Combine IV + authTag + encrypted data
        const result = Buffer.concat([iv, authTag, encrypted]);

        res.json({
            encrypted: result.toString('base64'),
            filename: req.file.originalname,
            size: req.file.size,
            encryptedSize: result.length
        });
    } catch (error) {
        res.status(500).json({ error: 'File encryption failed: ' + error.message });
    }
});

app.post('/api/file/decrypt', (req, res) => {
    try {
        const { encryptedData, key, filename } = req.body;
        if (!encryptedData || !key) {
            return res.status(400).json({ error: 'Encrypted data and key are required' });
        }

        const keyBuffer = Buffer.from(key, 'hex');
        const data = Buffer.from(encryptedData, 'base64');

        // Extract IV (12 bytes), authTag (16 bytes), and encrypted content
        const iv = data.slice(0, 12);
        const authTag = data.slice(12, 28);
        const encrypted = data.slice(28);

        const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
        decipher.setAuthTag(authTag);

        const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

        res.json({
            decrypted: decrypted.toString('base64'),
            filename: filename || 'decrypted_file',
            size: decrypted.length
        });
    } catch (error) {
        res.status(500).json({ error: 'File decryption failed: ' + error.message });
    }
});

// ============================================
// QR Code Generation
// ============================================

app.post('/api/qr/generate', async (req, res) => {
    try {
        const { data, size = 256 } = req.body;
        if (!data) {
            return res.status(400).json({ error: 'Data is required' });
        }

        // Limit data size to prevent oversized QR codes
        if (data.length > 2000) {
            return res.status(400).json({ error: 'Data too large for QR code (max 2000 characters)' });
        }

        const qrDataUrl = await QRCode.toDataURL(data, {
            width: size,
            margin: 2,
            color: { dark: '#6366f1', light: '#0a0a0f' }
        });

        res.json({ qrCode: qrDataUrl });
    } catch (error) {
        res.status(500).json({ error: 'QR generation failed: ' + error.message });
    }
});

// ============================================
// Performance Benchmark
// ============================================

app.post('/api/benchmark', (req, res) => {
    try {
        const { text = 'The quick brown fox jumps over the lazy dog', iterations = 100 } = req.body;
        const results = {};

        // AES-256-GCM
        const aesKey = crypto.randomBytes(32);
        const aesStart = performance.now();
        for (let i = 0; i < iterations; i++) {
            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
            cipher.update(text, 'utf8');
            cipher.final();
        }
        results.aes = {
            totalTime: (performance.now() - aesStart).toFixed(2),
            avgTime: ((performance.now() - aesStart) / iterations).toFixed(4),
            opsPerSec: Math.round(iterations / ((performance.now() - aesStart) / 1000))
        };

        // ChaCha20
        const chachaKey = nacl.randomBytes(32);
        const chachaStart = performance.now();
        for (let i = 0; i < iterations; i++) {
            const nonce = nacl.randomBytes(24);
            nacl.secretbox(naclUtil.decodeUTF8(text), nonce, chachaKey);
        }
        results.chacha = {
            totalTime: (performance.now() - chachaStart).toFixed(2),
            avgTime: ((performance.now() - chachaStart) / iterations).toFixed(4),
            opsPerSec: Math.round(iterations / ((performance.now() - chachaStart) / 1000))
        };

        // Blowfish
        const bfKey = crypto.randomBytes(16).toString('hex');
        const bf = new Blowfish(bfKey, Blowfish.MODE.ECB, Blowfish.PADDING.PKCS5);
        const bfStart = performance.now();
        for (let i = 0; i < iterations; i++) {
            bf.encode(text);
        }
        results.blowfish = {
            totalTime: (performance.now() - bfStart).toFixed(2),
            avgTime: ((performance.now() - bfStart) / iterations).toFixed(4),
            opsPerSec: Math.round(iterations / ((performance.now() - bfStart) / 1000))
        };

        // Hashing benchmarks
        const hashStart = performance.now();
        for (let i = 0; i < iterations; i++) {
            crypto.createHash('sha256').update(text).digest();
        }
        results.sha256 = {
            totalTime: (performance.now() - hashStart).toFixed(2),
            avgTime: ((performance.now() - hashStart) / iterations).toFixed(4),
            opsPerSec: Math.round(iterations / ((performance.now() - hashStart) / 1000))
        };

        res.json({
            results,
            iterations,
            textLength: text.length
        });
    } catch (error) {
        res.status(500).json({ error: 'Benchmark failed: ' + error.message });
    }
});

// ============================================
// Key Strength Analysis
// ============================================

app.post('/api/key-strength', (req, res) => {
    try {
        const { key, type = 'password' } = req.body;
        if (!key) {
            return res.status(400).json({ error: 'Key/password is required' });
        }

        let score = 0;
        const feedback = [];

        if (type === 'password') {
            // Length check
            if (key.length >= 8) score += 20;
            if (key.length >= 12) score += 15;
            if (key.length >= 16) score += 10;
            else feedback.push('Use at least 12 characters');

            // Character variety
            if (/[a-z]/.test(key)) score += 10;
            else feedback.push('Add lowercase letters');

            if (/[A-Z]/.test(key)) score += 10;
            else feedback.push('Add uppercase letters');

            if (/[0-9]/.test(key)) score += 10;
            else feedback.push('Add numbers');

            if (/[^a-zA-Z0-9]/.test(key)) score += 15;
            else feedback.push('Add special characters');

            // Entropy estimation
            const uniqueChars = new Set(key).size;
            if (uniqueChars >= key.length * 0.6) score += 10;
        } else {
            // Hex key analysis
            if (/^[a-fA-F0-9]+$/.test(key)) {
                const bits = key.length * 4;
                if (bits >= 128) score += 50;
                if (bits >= 256) score += 30;
                if (bits >= 512) score += 20;
                feedback.push(`Key length: ${bits} bits`);
            } else {
                feedback.push('Invalid hex key format');
            }
        }

        const strength = score >= 80 ? 'strong' : score >= 50 ? 'medium' : 'weak';

        res.json({ score: Math.min(score, 100), strength, feedback });
    } catch (error) {
        res.status(500).json({ error: 'Analysis failed: ' + error.message });
    }
});

// ============================================
// Algorithm Comparison
// ============================================

app.post('/api/compare', async (req, res) => {
    try {
        const { text } = req.body;
        if (!text) {
            return res.status(400).json({ error: 'Text is required' });
        }

        const results = {};

        // AES-256-GCM
        const aesKey = crypto.randomBytes(32);
        const aesIv = crypto.randomBytes(12);
        const aesCipher = crypto.createCipheriv('aes-256-gcm', aesKey, aesIv);
        let aesEncrypted = aesCipher.update(text, 'utf8', 'hex');
        aesEncrypted += aesCipher.final('hex');
        results.aes = {
            name: 'AES-256-GCM',
            encrypted: aesIv.toString('hex') + ':' + aesCipher.getAuthTag().toString('hex') + ':' + aesEncrypted,
            keySize: 256,
            outputLength: aesEncrypted.length
        };

        // ChaCha20
        const chachaKey = nacl.randomBytes(32);
        const chachaNonce = nacl.randomBytes(24);
        const chachaEncrypted = nacl.secretbox(naclUtil.decodeUTF8(text), chachaNonce, chachaKey);
        results.chacha = {
            name: 'ChaCha20-Poly1305',
            encrypted: naclUtil.encodeBase64(chachaNonce) + ':' + naclUtil.encodeBase64(chachaEncrypted),
            keySize: 256,
            outputLength: naclUtil.encodeBase64(chachaEncrypted).length
        };

        // Blowfish
        const bfKey = crypto.randomBytes(16).toString('hex');
        const bf = new Blowfish(bfKey, Blowfish.MODE.ECB, Blowfish.PADDING.PKCS5);
        const bfEncrypted = Buffer.from(bf.encode(text)).toString('base64');
        results.blowfish = {
            name: 'Blowfish',
            encrypted: bfEncrypted,
            keySize: 128,
            outputLength: bfEncrypted.length
        };

        res.json({ results, originalLength: text.length });
    } catch (error) {
        res.status(500).json({ error: 'Comparison failed: ' + error.message });
    }
});

// ============================================
// Start Server
// ============================================

app.listen(PORT, () => {
    console.log(`🔐 ECDC Server running on http://localhost:${PORT}`);
    console.log(`📁 File encryption enabled (max 50MB)`);
    console.log(`🔑 PBKDF2 key derivation available`);
    console.log(`✍️  Digital signatures (RSA/ECDSA) ready`);
});
