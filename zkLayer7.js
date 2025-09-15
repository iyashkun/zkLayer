const crypto = require('crypto');

// Helper function to generate a 32-byte key from a password using PBKDF2
function deriveKey(password, salt = crypto.randomBytes(16)) {
    return {
        key: crypto.pbkdf2Sync(password, salt, 1000, 32, 'sha256'),
        salt: salt
    };
}

// 7-Layer Encryption
function layer7Encrypt(secret, password) {
    const startTime = performance.now();
    let currentData = secret;
    const layersData = [];
    const ivs = [];
    const salts = [];
    const lengths = [];

    // Layer 1: Encrypt secret with password
    let { key, salt } = deriveKey(password);
    let iv = crypto.randomBytes(16);
    let cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(currentData, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    layersData.push(encrypted);
    ivs.push(iv.toString('base64'));
    salts.push(salt.toString('base64'));
    lengths.push(encrypted.length);

    // Layers 2 to 7: Use 50% of previous output as password, encrypt other 50%
    for (let layer = 2; layer <= 7; layer++) {
        const prevEncrypted = layersData[layersData.length - 1];
        const halfLength = Math.floor(prevEncrypted.length / 2);
        const nextPass = prevEncrypted.slice(0, halfLength);
        const nextData = prevEncrypted.slice(halfLength);

        const { key: nextKey, salt: nextSalt } = deriveKey(nextPass);
        const nextIv = crypto.randomBytes(16);
        const nextCipher = crypto.createCipheriv('aes-256-cbc', nextKey, nextIv);
        let nextEncrypted = nextCipher.update(nextData, 'utf8', 'base64');
        nextEncrypted += nextCipher.final('base64');

        layersData.push(nextEncrypted);
        ivs.push(nextIv.toString('base64'));
        salts.push(nextSalt.toString('base64'));
        lengths.push(nextEncrypted.length);
    }

    const endTime = performance.now();
    console.log(`Encryption time: ${(endTime - startTime).toFixed(2)}ms`);

    // Return the final encrypted data and components for decryption
    return {
        ciphertext: layersData[layersData.length - 1],
        ivs: ivs,
        salts: salts,
        lengths: lengths
    };
}

// 7-Layer Decryption
function layer7Decrypt(encryptedData, password) {
    const startTime = performance.now();
    const { ciphertext, ivs, salts, lengths } = encryptedData;
    let currentData = ciphertext;

    // Reverse the layers from 7 to 1
    for (let layer = 6; layer >= 0; layer--) {
        const halfLength = Math.floor(lengths[layer] / 2);
        const prevPass = currentData.slice(0, halfLength);
        const prevData = currentData.slice(halfLength);

        const { key } = deriveKey(prevPass, Buffer.from(salts[layer], 'base64'));
        const iv = Buffer.from(ivs[layer], 'base64');
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(prevData, 'base64', 'utf8');
        decrypted += decipher.final('utf8');

        currentData = decrypted;
    }

    // Final decryption for Layer 1
    const { key } = deriveKey(password, Buffer.from(salts[0], 'base64'));
    const iv = Buffer.from(ivs[0], 'base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let finalDecrypted = decipher.update(currentData, 'base64', 'utf8');
    finalDecrypted += decipher.final('utf8');

    const endTime = performance.now();
    console.log(`Decryption time: ${(endTime - startTime).toFixed(2)}ms`);

    return finalDecrypted;
}

// Example usage
const secret = "This is my super secret message!";
const password = "mySecurePassword123";
const encrypted = layer7Encrypt(secret, password);
console.log("Encrypted:", encrypted);
const decrypted = layer7Decrypt(encrypted, password);
console.log("Decrypted:", decrypted);
