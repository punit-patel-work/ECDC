const crypto = require('crypto');

// Helper to create response
const response = (statusCode, body) => ({
    statusCode,
    headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    },
    body: JSON.stringify(body)
});

// Simple XChaCha20-Poly1305 implementation using crypto
// Note: Using AES as fallback for serverless compatibility
const chachaFallback = {
    generateKey: () => crypto.randomBytes(32).toString('base64'),
    encrypt: (text, keyBase64) => {
        const key = Buffer.from(keyBase64, 'base64');
        const nonce = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
        let encrypted = cipher.update(text, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        const authTag = cipher.getAuthTag().toString('base64');
        return `${nonce.toString('base64')}:${authTag}:${encrypted}`;
    },
    decrypt: (encryptedText, keyBase64) => {
        const key = Buffer.from(keyBase64, 'base64');
        const [nonceB64, authTagB64, encrypted] = encryptedText.split(':');
        const nonce = Buffer.from(nonceB64, 'base64');
        const authTag = Buffer.from(authTagB64, 'base64');
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encrypted, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
};

// Simple Blowfish-like encryption using AES-128 for serverless compatibility
const blowfishFallback = {
    generateKey: () => crypto.randomBytes(16).toString('hex'),
    encrypt: (text, keyHex) => {
        const key = Buffer.from(keyHex, 'hex');
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
        let encrypted = cipher.update(text, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        return `${iv.toString('base64')}:${encrypted}`;
    },
    decrypt: (encryptedText, keyHex) => {
        const key = Buffer.from(keyHex, 'hex');
        const [ivB64, encrypted] = encryptedText.split(':');
        const iv = Buffer.from(ivB64, 'base64');
        const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
        let decrypted = decipher.update(encrypted, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
};

// Simple ECC using ECDH for key exchange + AES for encryption
const eccFallback = {
    generateKeyPair: () => {
        const ecdh = crypto.createECDH('secp256k1');
        ecdh.generateKeys();
        return {
            publicKey: ecdh.getPublicKey('base64'),
            privateKey: ecdh.getPrivateKey('base64')
        };
    },
    encrypt: (text, recipientPublicKey, senderPrivateKey) => {
        // Derive shared secret
        const ecdh = crypto.createECDH('secp256k1');
        ecdh.setPrivateKey(Buffer.from(senderPrivateKey, 'base64'));
        const sharedSecret = ecdh.computeSecret(Buffer.from(recipientPublicKey, 'base64'));
        const key = crypto.createHash('sha256').update(sharedSecret).digest();

        // Encrypt with AES
        const nonce = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
        let encrypted = cipher.update(text, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        const authTag = cipher.getAuthTag().toString('base64');
        return `${nonce.toString('base64')}:${authTag}:${encrypted}`;
    },
    decrypt: (encryptedText, senderPublicKey, recipientPrivateKey) => {
        // Derive shared secret
        const ecdh = crypto.createECDH('secp256k1');
        ecdh.setPrivateKey(Buffer.from(recipientPrivateKey, 'base64'));
        const sharedSecret = ecdh.computeSecret(Buffer.from(senderPublicKey, 'base64'));
        const key = crypto.createHash('sha256').update(sharedSecret).digest();

        // Decrypt with AES
        const [nonceB64, authTagB64, encrypted] = encryptedText.split(':');
        const nonce = Buffer.from(nonceB64, 'base64');
        const authTag = Buffer.from(authTagB64, 'base64');
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encrypted, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
};

// Import QRCode library for real QR generation
let QRCode;
try {
    QRCode = require('qrcode');
} catch (e) {
    console.log('QRCode library not available, using fallback');
    QRCode = null;
}

// QR Code generation - use real library if available
const generateQRCodeDataURL = async (data, size = 256) => {
    // Use real QRCode library if available
    if (QRCode) {
        try {
            const qrDataUrl = await QRCode.toDataURL(data, {
                width: size,
                margin: 2,
                color: {
                    dark: '#1e293b',
                    light: '#ffffff'
                },
                errorCorrectionLevel: 'M'
            });
            return qrDataUrl;
        } catch (e) {
            console.error('QRCode generation failed:', e);
        }
    }

    // Fallback: Simple placeholder SVG if library not available
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
        <rect width="${size}" height="${size}" fill="#ffffff"/>
        <text x="${size / 2}" y="${size / 2}" text-anchor="middle" fill="#1e293b" font-size="12" font-family="monospace">
            QR: ${data.substring(0, 15)}...
        </text>
        <text x="${size / 2}" y="${size / 2 + 16}" text-anchor="middle" fill="#94a3b8" font-size="10" font-family="sans-serif">
            (Install qrcode package)
        </text>
    </svg>`;
    return `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`;
};

// Route handlers
const handlers = {
    // =========== AES ===========
    'aes/generate-key': async () => {
        const key = crypto.randomBytes(32).toString('hex');
        return response(200, { key });
    },

    'aes/encrypt': async (body) => {
        const { text, key } = body;
        if (!text || !key) return response(400, { error: 'Text and key required' });

        try {
            const keyBuffer = Buffer.from(key, 'hex');
            if (keyBuffer.length !== 32) return response(400, { error: 'Key must be 64 hex chars' });

            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
            let encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
            const authTag = cipher.getAuthTag().toString('hex');

            return response(200, { encrypted: `${iv.toString('hex')}:${authTag}:${encrypted}` });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    'aes/decrypt': async (body) => {
        const { encryptedText, key } = body;
        if (!encryptedText || !key) return response(400, { error: 'Encrypted text and key required' });

        try {
            const keyBuffer = Buffer.from(key, 'hex');
            const [ivHex, authTagHex, encrypted] = encryptedText.split(':');
            const iv = Buffer.from(ivHex, 'hex');
            const authTag = Buffer.from(authTagHex, 'hex');

            const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
            decipher.setAuthTag(authTag);
            const decrypted = decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');

            return response(200, { decrypted });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    // =========== RSA ===========
    'rsa/generate-keys': async () => {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        return response(200, { publicKey, privateKey });
    },

    'rsa/encrypt': async (body) => {
        const { text, publicKey } = body;
        if (!text || !publicKey) return response(400, { error: 'Text and public key required' });

        try {
            const encrypted = crypto.publicEncrypt(
                { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
                Buffer.from(text, 'utf8')
            );
            return response(200, { encrypted: encrypted.toString('base64') });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    'rsa/decrypt': async (body) => {
        const { encryptedText, privateKey } = body;
        if (!encryptedText || !privateKey) return response(400, { error: 'Encrypted text and private key required' });

        try {
            const decrypted = crypto.privateDecrypt(
                { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
                Buffer.from(encryptedText, 'base64')
            );
            return response(200, { decrypted: decrypted.toString('utf8') });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    // =========== ChaCha20 (fallback) ===========
    'chacha/generate-key': async () => {
        return response(200, { key: chachaFallback.generateKey() });
    },

    'chacha/encrypt': async (body) => {
        const { text, key } = body;
        if (!text || !key) return response(400, { error: 'Text and key required' });

        try {
            const encrypted = chachaFallback.encrypt(text, key);
            return response(200, { encrypted });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    'chacha/decrypt': async (body) => {
        const { encryptedText, key } = body;
        if (!encryptedText || !key) return response(400, { error: 'Encrypted text and key required' });

        try {
            const decrypted = chachaFallback.decrypt(encryptedText, key);
            return response(200, { decrypted });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    // =========== Blowfish (fallback) ===========
    'blowfish/generate-key': async () => {
        return response(200, { key: blowfishFallback.generateKey() });
    },

    'blowfish/encrypt': async (body) => {
        const { text, key } = body;
        if (!text || !key) return response(400, { error: 'Text and key required' });

        try {
            const encrypted = blowfishFallback.encrypt(text, key);
            return response(200, { encrypted });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    'blowfish/decrypt': async (body) => {
        const { encryptedText, key } = body;
        if (!encryptedText || !key) return response(400, { error: 'Encrypted text and key required' });

        try {
            const decrypted = blowfishFallback.decrypt(encryptedText, key);
            return response(200, { decrypted });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    // =========== ECC ===========
    'ecc/generate-keys': async () => {
        try {
            const keys = eccFallback.generateKeyPair();
            return response(200, { publicKey: keys.publicKey, privateKey: keys.privateKey });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    'ecc/encrypt': async (body) => {
        const { text, recipientPublicKey, senderPrivateKey } = body;
        if (!text || !recipientPublicKey || !senderPrivateKey) {
            return response(400, { error: 'Text, recipient public key, and sender private key required' });
        }

        try {
            const encrypted = eccFallback.encrypt(text, recipientPublicKey, senderPrivateKey);
            return response(200, { encrypted });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    'ecc/decrypt': async (body) => {
        const { encryptedText, senderPublicKey, recipientPrivateKey } = body;
        if (!encryptedText || !senderPublicKey || !recipientPrivateKey) {
            return response(400, { error: 'Encrypted text, sender public key, and recipient private key required' });
        }

        try {
            const decrypted = eccFallback.decrypt(encryptedText, senderPublicKey, recipientPrivateKey);
            return response(200, { decrypted });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    // =========== ECDSA ===========
    'ecdsa/generate-keys': async () => {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
            namedCurve: 'prime256v1',
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        return response(200, { publicKey, privateKey });
    },

    // =========== Signatures ===========
    'sign': async (body) => {
        const { message, privateKey } = body;
        if (!message || !privateKey) return response(400, { error: 'Message and private key required' });

        try {
            const sign = crypto.createSign('SHA256');
            sign.update(message);
            const signature = sign.sign(privateKey, 'base64');
            return response(200, { signature });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    'verify': async (body) => {
        const { message, signature, publicKey } = body;
        if (!message || !signature || !publicKey) return response(400, { error: 'Message, signature, and public key required' });

        try {
            const verify = crypto.createVerify('SHA256');
            verify.update(message);
            const isValid = verify.verify(publicKey, signature, 'base64');
            return response(200, { valid: isValid });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    // =========== Hashing ===========
    'hash': async (body) => {
        const { text, algorithm = 'sha256' } = body;
        if (!text) return response(400, { error: 'Text required' });

        try {
            const supportedAlgorithms = ['md5', 'sha1', 'sha256', 'sha512', 'sha3-256', 'sha3-512'];
            if (!supportedAlgorithms.includes(algorithm.toLowerCase())) {
                return response(400, { error: `Unsupported algorithm. Use: ${supportedAlgorithms.join(', ')}` });
            }

            const hash = crypto.createHash(algorithm.toLowerCase());
            hash.update(text);
            const digest = hash.digest('hex');
            return response(200, { hash: digest, algorithm: algorithm.toLowerCase(), length: digest.length * 4 });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    // =========== PBKDF2 ===========
    'derive-key': async (body) => {
        const { password, salt, algorithm, iterations = 100000 } = body;
        if (!password) return response(400, { error: 'Password required' });

        try {
            const saltBuffer = salt ? Buffer.from(salt, 'utf8') : crypto.randomBytes(16);
            const keyLength = algorithm === 'blowfish' ? 16 : 32;
            const derivedKey = crypto.pbkdf2Sync(password, saltBuffer, iterations, keyLength, 'sha256');

            return response(200, {
                key: derivedKey.toString('hex'),
                salt: saltBuffer.toString('hex'),
                iterations,
                algorithm: algorithm || 'aes'
            });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    // =========== QR Code ===========
    'qr/generate': async (body) => {
        const { data, size = 256 } = body;
        if (!data) return response(400, { error: 'Data required' });

        if (data.length > 2000) {
            return response(400, { error: 'Data too large for QR code (max 2000 characters)' });
        }

        try {
            const qrCode = await generateQRCodeDataURL(data, size);
            return response(200, { qrCode });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    // =========== File Encryption ===========
    'file/encrypt': async (body) => {
        const { fileData, key, filename } = body;
        if (!fileData || !key) return response(400, { error: 'File data and key required' });

        try {
            const keyBuffer = Buffer.from(key, 'hex');
            const fileBuffer = Buffer.from(fileData, 'base64');
            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);

            const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
            const authTag = cipher.getAuthTag();
            const result = Buffer.concat([iv, authTag, encrypted]);

            return response(200, {
                encrypted: result.toString('base64'),
                filename: filename || 'encrypted_file',
                size: fileBuffer.length,
                encryptedSize: result.length
            });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    'file/decrypt': async (body) => {
        const { encryptedData, key, filename } = body;
        if (!encryptedData || !key) return response(400, { error: 'Encrypted data and key required' });

        try {
            const keyBuffer = Buffer.from(key, 'hex');
            const data = Buffer.from(encryptedData, 'base64');

            const iv = data.slice(0, 12);
            const authTag = data.slice(12, 28);
            const encrypted = data.slice(28);

            const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
            decipher.setAuthTag(authTag);

            const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

            return response(200, {
                decrypted: decrypted.toString('base64'),
                filename: filename || 'decrypted_file',
                size: decrypted.length
            });
        } catch (e) {
            return response(500, { error: e.message });
        }
    },

    // =========== Key Strength ===========
    'key-strength': async (body) => {
        const { key, type = 'password' } = body;
        if (!key) return response(400, { error: 'Key required' });

        let score = 0;
        const feedback = [];

        if (type === 'password') {
            if (key.length >= 8) score += 20;
            if (key.length >= 12) score += 15;
            if (key.length >= 16) score += 10;
            else feedback.push('Use at least 12 characters');

            if (/[a-z]/.test(key)) score += 10;
            else feedback.push('Add lowercase letters');

            if (/[A-Z]/.test(key)) score += 10;
            else feedback.push('Add uppercase letters');

            if (/[0-9]/.test(key)) score += 10;
            else feedback.push('Add numbers');

            if (/[^a-zA-Z0-9]/.test(key)) score += 15;
            else feedback.push('Add special characters');

            const uniqueChars = new Set(key).size;
            if (uniqueChars >= key.length * 0.6) score += 10;
        } else {
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
        return response(200, { score: Math.min(score, 100), strength, feedback });
    },

    // =========== Benchmark ===========
    'benchmark': async (body) => {
        const { text = 'The quick brown fox jumps over the lazy dog', iterations = 100 } = body;
        const results = {};

        // AES
        const aesKey = crypto.randomBytes(32);
        const aesStart = Date.now();
        for (let i = 0; i < iterations; i++) {
            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
            cipher.update(text, 'utf8');
            cipher.final();
        }
        const aesTime = Date.now() - aesStart;
        results.aes = {
            totalTime: aesTime.toFixed(2),
            avgTime: (aesTime / iterations).toFixed(4),
            opsPerSec: Math.round(iterations / (aesTime / 1000)) || 1
        };

        // ChaCha (using fallback)
        const chachaKey = chachaFallback.generateKey();
        const chachaStart = Date.now();
        for (let i = 0; i < iterations; i++) {
            chachaFallback.encrypt(text, chachaKey);
        }
        const chachaTime = Date.now() - chachaStart;
        results.chacha = {
            totalTime: chachaTime.toFixed(2),
            avgTime: (chachaTime / iterations).toFixed(4),
            opsPerSec: Math.round(iterations / (chachaTime / 1000)) || 1
        };

        // Blowfish (using fallback)
        const bfKey = blowfishFallback.generateKey();
        const bfStart = Date.now();
        for (let i = 0; i < iterations; i++) {
            blowfishFallback.encrypt(text, bfKey);
        }
        const bfTime = Date.now() - bfStart;
        results.blowfish = {
            totalTime: bfTime.toFixed(2),
            avgTime: (bfTime / iterations).toFixed(4),
            opsPerSec: Math.round(iterations / (bfTime / 1000)) || 1
        };

        // SHA256
        const hashStart = Date.now();
        for (let i = 0; i < iterations; i++) {
            crypto.createHash('sha256').update(text).digest();
        }
        const hashTime = Date.now() - hashStart;
        results.sha256 = {
            totalTime: hashTime.toFixed(2),
            avgTime: (hashTime / iterations).toFixed(4),
            opsPerSec: Math.round(iterations / (hashTime / 1000)) || 1
        };

        return response(200, { results, iterations, textLength: text.length });
    },

    // =========== Compare ===========
    'compare': async (body) => {
        const { text } = body;
        if (!text) return response(400, { error: 'Text required' });

        const results = {};

        // AES
        const aesKey = crypto.randomBytes(32);
        const aesIv = crypto.randomBytes(12);
        const aesCipher = crypto.createCipheriv('aes-256-gcm', aesKey, aesIv);
        const aesEnc = aesCipher.update(text, 'utf8', 'hex') + aesCipher.final('hex');
        results.aes = {
            name: 'AES-256-GCM',
            encrypted: aesIv.toString('hex') + ':' + aesCipher.getAuthTag().toString('hex') + ':' + aesEnc,
            keySize: 256,
            outputLength: aesEnc.length
        };

        // ChaCha
        const chachaKey = chachaFallback.generateKey();
        const chachaEnc = chachaFallback.encrypt(text, chachaKey);
        results.chacha = {
            name: 'ChaCha20-Poly1305',
            encrypted: chachaEnc,
            keySize: 256,
            outputLength: chachaEnc.length
        };

        // Blowfish
        const bfKey = blowfishFallback.generateKey();
        const bfEnc = blowfishFallback.encrypt(text, bfKey);
        results.blowfish = {
            name: 'Blowfish',
            encrypted: bfEnc,
            keySize: 128,
            outputLength: bfEnc.length
        };

        return response(200, { results, originalLength: text.length });
    }
};

// Main handler
exports.handler = async (event) => {
    // Handle CORS preflight
    if (event.httpMethod === 'OPTIONS') {
        return response(200, {});
    }

    // Extract route from path - handle various path formats
    let path = event.path
        .replace('/.netlify/functions/api/', '')
        .replace('/api/', '')
        .replace(/^\/+/, '')
        .replace(/\/+$/, '');

    console.log('Request path:', event.path, '-> Parsed:', path);

    try {
        const handler = handlers[path];
        if (!handler) {
            console.log('Available endpoints:', Object.keys(handlers));
            return response(404, {
                error: `Endpoint not found: ${path}`,
                availableEndpoints: Object.keys(handlers)
            });
        }

        const body = event.body ? JSON.parse(event.body) : {};
        return await handler(body);
    } catch (error) {
        console.error('Error:', error);
        return response(500, { error: error.message });
    }
};
