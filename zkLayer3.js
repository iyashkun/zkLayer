import crypto from 'crypto'; // Use require since Node.js is being used

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
    
    // Layer 2: Use first half of encrypted1 as password, encrypt second half
    const halfLength = Math.floor(encrypted1.length / 2);
    const layer2Pass = encrypted1.slice(0, halfLength);
    const layer2Data = encrypted1.slice(halfLength);
    const { key: key2, salt: salt2 } = deriveKey(layer2Pass);
    const iv2 = crypto.randomBytes(16);
    const cipher2 = crypto.createCipheriv('aes-256-cbc', key2, iv2);
    let encrypted2 = cipher2.update(layer2Data, 'utf8', 'base64');
    encrypted2 += cipher2.final('base64');
    
    // Layer 3: Use first half of encrypted2 as password, encrypt second half
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
        layer2Length: encrypted2.length,
        layer2Pass: layer2Pass, // Store the password used for Layer 2
        layer3Pass: layer3Pass // Store the password used for Layer 3
    };
}

// Layer3 Decryption
function layer3Decrypt(encryptedData, password) {
    const startTime = performance.now();
    
    const { ciphertext, iv1, iv2, iv3, salt1, salt2, salt3, layer1Length, layer2Length, layer2Pass, layer3Pass } = encryptedData;
    
    // Layer 3: Decrypt to get the second half of layer2Data
    const { key: key3 } = deriveKey(layer3Pass, Buffer.from(salt3, 'base64'));
    const iv3Buf = Buffer.from(iv3, 'base64');
    const decipher3 = crypto.createDecipheriv('aes-256-cbc', key3, iv3Buf);
    let layer3Decrypted = decipher3.update(ciphertext, 'base64', 'utf8');
    layer3Decrypted += decipher3.final('utf8');
    
    // Reconstruct Layer 2 data (layer3Pass + decrypted layer3)
    const layer2Data = layer3Pass + layer3Decrypted;
    
    // Layer 2: Decrypt to get the second half of layer1Data
    const { key: key2 } = deriveKey(layer2Pass, Buffer.from(salt2, 'base64'));
    const iv2Buf = Buffer.from(iv2, 'base64');
    const decipher2 = crypto.createDecipheriv('aes-256-cbc', key2, iv2Buf);
    let layer2Decrypted = decipher2.update(layer2Data, 'base64', 'utf8');
    layer2Decrypted += decipher2.final('utf8');
    
    // Layer 1: Decrypt to get the original secret
    const layer1Data = layer2Pass + layer2Decrypted;
    const { key: key1 } = deriveKey(password, Buffer.from(salt1, 'base64'));
    const iv1Buf = Buffer.from(iv1, 'base64');
    const decipher1 = crypto.createDecipheriv('aes-256-cbc', key1, iv1Buf);
    let decryptedSecret = decipher1.update(layer1Data, 'base64', 'utf8');
    decryptedSecret += decipher1.final('utf8');
    
    const endTime = performance.now();
    console.log(`Decryption time: ${(endTime - startTime).toFixed(2)}ms`);
    
    return decryptedSecret;
}

// Example usage
const secret = "This is my super secret message...!";
const password = "mySecurePassword123";
const encrypted = layer3Encrypt(secret, password);
console.log("Encrypted:", encrypted);
const decrypted = layer3Decrypt(encrypted, password);
console.log("Decrypted:", decrypted);
