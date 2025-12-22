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

// Route handlers
const handlers = {
    // AES
    'aes/generate-key': async () => {
        const key = crypto.randomBytes(32).toString('hex');
        return response(200, { key });
    },

    'aes/encrypt': async (body) => {
        const { text, key } = body;
        if (!text || !key) return response(400, { error: 'Text and key required' });

        const keyBuffer = Buffer.from(key, 'hex');
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
        const authTag = cipher.getAuthTag().toString('hex');

        return response(200, { encrypted: `${iv.toString('hex')}:${authTag}:${encrypted}` });
    },

    'aes/decrypt': async (body) => {
        const { encryptedText, key } = body;
        if (!encryptedText || !key) return response(400, { error: 'Encrypted text and key required' });

        const keyBuffer = Buffer.from(key, 'hex');
        const [ivHex, authTagHex, encrypted] = encryptedText.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');

        const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
        decipher.setAuthTag(authTag);
        const decrypted = decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');

        return response(200, { decrypted });
    },

    // RSA
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

        const encrypted = crypto.publicEncrypt(
            { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
            Buffer.from(text, 'utf8')
        );
        return response(200, { encrypted: encrypted.toString('base64') });
    },

    'rsa/decrypt': async (body) => {
        const { encryptedText, privateKey } = body;
        if (!encryptedText || !privateKey) return response(400, { error: 'Encrypted text and private key required' });

        const decrypted = crypto.privateDecrypt(
            { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
            Buffer.from(encryptedText, 'base64')
        );
        return response(200, { decrypted: decrypted.toString('utf8') });
    },

    // ECDSA
    'ecdsa/generate-keys': async () => {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
            namedCurve: 'prime256v1',
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        return response(200, { publicKey, privateKey });
    },

    // Signatures
    'sign': async (body) => {
        const { message, privateKey } = body;
        if (!message || !privateKey) return response(400, { error: 'Message and private key required' });

        const sign = crypto.createSign('SHA256');
        sign.update(message);
        const signature = sign.sign(privateKey, 'base64');
        return response(200, { signature });
    },

    'verify': async (body) => {
        const { message, signature, publicKey } = body;
        if (!message || !signature || !publicKey) return response(400, { error: 'Message, signature, and public key required' });

        const verify = crypto.createVerify('SHA256');
        verify.update(message);
        const isValid = verify.verify(publicKey, signature, 'base64');
        return response(200, { valid: isValid });
    },

    // Hashing
    'hash': async (body) => {
        const { text, algorithm = 'sha256' } = body;
        if (!text) return response(400, { error: 'Text required' });

        const hash = crypto.createHash(algorithm.toLowerCase());
        hash.update(text);
        const digest = hash.digest('hex');
        return response(200, { hash: digest, algorithm, length: digest.length * 4 });
    },

    // PBKDF2
    'derive-key': async (body) => {
        const { password, salt, algorithm, iterations = 100000 } = body;
        if (!password) return response(400, { error: 'Password required' });

        const saltBuffer = salt ? Buffer.from(salt, 'utf8') : crypto.randomBytes(16);
        const keyLength = algorithm === 'blowfish' ? 16 : 32;
        const derivedKey = crypto.pbkdf2Sync(password, saltBuffer, iterations, keyLength, 'sha256');

        return response(200, { key: derivedKey.toString('hex'), salt: saltBuffer.toString('hex'), iterations });
    },

    // Key Strength
    'key-strength': async (body) => {
        const { key, type = 'password' } = body;
        if (!key) return response(400, { error: 'Key required' });

        let score = 0;
        if (key.length >= 8) score += 20;
        if (key.length >= 12) score += 15;
        if (key.length >= 16) score += 10;
        if (/[a-z]/.test(key)) score += 10;
        if (/[A-Z]/.test(key)) score += 10;
        if (/[0-9]/.test(key)) score += 10;
        if (/[^a-zA-Z0-9]/.test(key)) score += 15;

        const strength = score >= 80 ? 'strong' : score >= 50 ? 'medium' : 'weak';
        return response(200, { score: Math.min(score, 100), strength });
    },

    // Benchmark
    'benchmark': async (body) => {
        const { text = 'The quick brown fox', iterations = 100 } = body;
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
        results.aes = { totalTime: aesTime, avgTime: (aesTime / iterations).toFixed(4), opsPerSec: Math.round(iterations / (aesTime / 1000)) };

        // SHA256
        const hashStart = Date.now();
        for (let i = 0; i < iterations; i++) {
            crypto.createHash('sha256').update(text).digest();
        }
        const hashTime = Date.now() - hashStart;
        results.sha256 = { totalTime: hashTime, avgTime: (hashTime / iterations).toFixed(4), opsPerSec: Math.round(iterations / (hashTime / 1000)) };

        return response(200, { results, iterations });
    },

    // Compare
    'compare': async (body) => {
        const { text } = body;
        if (!text) return response(400, { error: 'Text required' });

        const results = {};

        // AES
        const aesKey = crypto.randomBytes(32);
        const aesIv = crypto.randomBytes(12);
        const aesCipher = crypto.createCipheriv('aes-256-gcm', aesKey, aesIv);
        const aesEnc = aesCipher.update(text, 'utf8', 'hex') + aesCipher.final('hex');
        results.aes = { name: 'AES-256-GCM', keySize: 256, outputLength: aesEnc.length };

        return response(200, { results, originalLength: text.length });
    }
};

// Main handler
exports.handler = async (event) => {
    // Handle CORS preflight
    if (event.httpMethod === 'OPTIONS') {
        return response(200, {});
    }

    // Extract route from path
    const path = event.path.replace('/.netlify/functions/api/', '').replace('/api/', '');

    try {
        const handler = handlers[path];
        if (!handler) {
            return response(404, { error: 'Endpoint not found' });
        }

        const body = event.body ? JSON.parse(event.body) : {};
        return await handler(body);
    } catch (error) {
        return response(500, { error: error.message });
    }
};
