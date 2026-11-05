import test from 'node:test';
import assert from 'node:assert/strict';

function identifyHash(str) {
    const val = str.trim();
    if (!val) return { type: "Empty", valid: false };

    if (/^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$/.test(val)) {
        return { type: "Bcrypt", valid: true };
    }
    if (/^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/.test(val)) {
        return { type: "Argon2", valid: true };
    }
    if (/^\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$/.test(val)) {
        return { type: "SHA-512 Crypt", valid: true };
    }

    if (!/^[a-fA-F0-9]+$/.test(val)) {
        return { type: "Invalid Non-Hex", valid: false };
    }

    switch (val.length) {
        case 8: return { type: "CRC32", valid: true };
        case 32: return { type: "MD5", valid: true };
        case 40: return { type: "SHA-1", valid: true };
        case 64: return { type: "SHA-256", valid: true };
        case 128: return { type: "SHA-512", valid: true };
        default: return { type: "Unknown", valid: false };
    }
}

test('Hash Analyzer - Hex hash recognition', () => {
    // MD5 (32 hex)
    assert.deepEqual(identifyHash('098f6bcd4621d373cade4e832627b4f6'), { type: 'MD5', valid: true });
    // SHA-1 (40 hex)
    assert.deepEqual(identifyHash('a94a8fe5ccb19ba61c4c0873d391e987982fbbd3'), { type: 'SHA-1', valid: true });
    // SHA-256 (64 hex)
    assert.deepEqual(identifyHash('5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'), { type: 'SHA-256', valid: true });
    // CRC32 (8 hex)
    assert.deepEqual(identifyHash('cbf43926'), { type: 'CRC32', valid: true });
});

test('Hash Analyzer - Rejection of invalid non-hex characters', () => {
    // 32 chars but contains non-hex 'Z'
    assert.equal(identifyHash('098f6bcd4621d373cade4e832627b4fZ').valid, false);
});

test('Hash Analyzer - Password hash formats (Bcrypt & Argon2)', () => {
    const bcrypt = '$2a$12$e8McS9YyU.5sV0c7d5tD8e4Q.y5aL0rD4w7E1e0B6q3F7a1b9C2d3';
    assert.equal(identifyHash(bcrypt).type, 'Bcrypt');

    const argon2 = '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgTVBcCK5aBc9/Po3xMTePChJaBb3';
    assert.equal(identifyHash(argon2).type, 'Argon2');
});

