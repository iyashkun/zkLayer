const crypto = require('crypto');

// Helper function to generate a 32-byte key from a password using PBKDF2
function deriveKey(password, salt = crypto.randomBytes(16)) {
    return {
        key: crypto.pbkdf2Sync(password, salt, 1000, 32, 'sha256'),
        salt: salt
    };
}

// Layer3 Encryption
function layer3Encrypt(secret, password) {
    const startTime = performance.now();
    
    // Layer 1: Encrypt secret with password
    const { key: key1, salt: salt1 } = deriveKey(password);
    const iv1 = crypto.randomBytes(16);
    const cipher1 = crypto.createCipheriv('aes-256-cbc', key1, iv1);
    let encrypted1 = cipher1.update(secret, 'utf8', 'base64');
    encrypted1 += cipher1.final('base64');
    
    // Layer 2: Use 50% of encrypted1 as password, encrypt other 50%
    const halfLength = Math.floor(encrypted1.length / 2);
    const layer2Pass = encrypted1.slice(0, halfLength);
    const layer2Data = encrypted1.slice(halfLength);
    const { key: key2, salt: salt2 } = deriveKey(layer2Pass);
    const iv2 = crypto.randomBytes(16);
    const cipher2 = crypto.createCipheriv('aes-256-cbc', key2, iv2);
    let encrypted2 = cipher2.update(layer2Data, 'utf8', 'base64');
    encrypted2 += cipher2.final('base64');
    
    // Layer 3: Use 50% of encrypted2 as password, encrypt other 50%
    const halfLength2 = Math.floor(encrypted2.length / 2);
    const layer3Pass = encrypted2.slice(0, halfLength2);
    const layer3Data = encrypted2.slice(halfLength2);
    const { key: key3, salt: salt3 } = deriveKey(layer3Pass);
    const iv3 = crypto.randomBytes(16);
    const cipher3 = crypto.createCipheriv('aes-256-cbc', key3, iv3);
    let encrypted3 = cipher3.update(layer3Data, 'utf8', 'base64');
    encrypted3 += cipher3.final('base64');
    
    const endTime = performance.now();
    console.log(`Encryption time: ${(endTime - startTime).toFixed(2)}ms`);
    
    // Return the final encrypted data and necessary components for decryption
    return {
        ciphertext: encrypted3,
        iv1: iv1.toString('base64'),
        iv2: iv2.toString('base64'),
        iv3: iv3.toString('base64'),
        salt1: salt1.toString('base64'),
        salt2: salt2.toString('base64'),
        salt3: salt3.toString('base64'),
        layer1Length: encrypted1.length,
        layer2Length: encrypted2.length
    };
}

// Layer3 Decryption
function layer3Decrypt(encryptedData, password) {
    const startTime = performance.now();
    
    const { ciphertext, iv1, iv2, iv3, salt1, salt2, salt3, layer1Length, layer2Length } = encryptedData;
    
    // Layer 3: Derive key and decrypt
    const { key: key1 } = deriveKey(password, Buffer.from(salt1, 'base64'));
    const iv1Buf = Buffer.from(iv1, 'base64');
    const cipher1 = crypto.createCipheriv('aes-256-cbc', key1, iv1Buf);
    let layer1Full = cipher1.update(encryptedData.ciphertext, 'base64', 'utf8');
    layer1Full += cipher1.final('utf8');
    
    // Reconstruct Layer 2 data
    const halfLength2 = Math.floor(layer2Length / 2);
    const layer3Pass = layer1Full.slice(0, halfLength2);
    const layer3Data = layer1Full.slice(halfLength2);
    const { key: key2 } = deriveKey(layer3Pass, Buffer.from(salt2, 'base64'));
    const iv2Buf = Buffer.from(iv2, 'base64');
    const decipher2 = crypto.createDecipheriv('aes-256-cbc', key2, iv2Buf);
    let layer2Data = decipher2.update(layer3Data, 'base64', 'utf8');
    layer2Data += decipher2.final('utf8');
    
    // Reconstruct Layer 1 data
    const halfLength1 = Math.floor(layer1Length / 2);
    const layer2Pass = layer2Data.slice(0, halfLength1);
    const layer2Encrypted = layer2Data.slice(halfLength1);
    const { key: key3 } = deriveKey(layer2Pass, Buffer.from(salt3, 'base64'));
    const iv3Buf = Buffer.from(iv3, 'base64');
    const decipher3 = crypto.createDecipheriv('aes-256-cbc', key3, iv3Buf);
    let decryptedSecret = decipher3.update(layer2Encrypted, 'base64', 'utf8');
    decryptedSecret += decipher3.final('utf8');
    
    const endTime = performance.now();
    console.log(`Decryption time: ${(endTime - startTime).toFixed(2)}ms`);
    
    return decryptedSecret;
}

// Example usage
const secret = "This is my super secret message!";
const password = "mySecurePassword123";
const encrypted = layer3Encrypt(secret, password);
console.log("Encrypted:", encrypted);
const decrypted = layer3Decrypt(encrypted, password);
console.log("Decrypted:", decrypted);
