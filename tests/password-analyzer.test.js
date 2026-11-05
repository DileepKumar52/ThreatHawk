import test from 'node:test';
import assert from 'node:assert/strict';

function getCharacterSetPool(password) {
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    if (/[^A-Za-z0-9]/.test(password)) pool += 33;
    return pool;
}

function calculateEntropy(password) {
    const pool = getCharacterSetPool(password);
    if (!password || pool === 0) return 0;
    return Math.round(password.length * Math.log2(pool) * 10) / 10;
}

const COMMON_PASSWORDS = new Set(["123456", "password", "qwerty", "admin123"]);

function detectPatterns(password) {
    const lower = password.toLowerCase();
    return {
        commonPassword: COMMON_PASSWORDS.has(lower),
        numberSequence: /(?:0123|1234|2345|3456|4567|5678|6789|7890)/.test(lower),
        keyboardSequence: /(?:qwerty|asdf|zxcv|qazwsx)/.test(lower),
        repeatedCharacters: /(.)\1{2,}/.test(password),
        onlyNumbers: /^\d+$/.test(password)
    };
}

function calculateStrengthScore(password) {
    if (!password) return 0;
    const patterns = detectPatterns(password);
    if (patterns.commonPassword) return 5;

    let score = 0;
    if (password.length >= 8) score += 15;
    if (password.length >= 12) score += 15;
    if (password.length >= 16) score += 15;
    if (password.length >= 20) score += 10;

    let types = 0;
    if (/[a-z]/.test(password)) types++;
    if (/[A-Z]/.test(password)) types++;
    if (/[0-9]/.test(password)) types++;
    if (/[^A-Za-z0-9]/.test(password)) types++;
    score += types * 5;

    const uniqueRatio = new Set(password).size / password.length;
    score += Math.round(uniqueRatio * 20);

    if (patterns.numberSequence) score -= 15;
    if (patterns.keyboardSequence) score -= 15;
    if (patterns.repeatedCharacters) score -= 15;
    if (patterns.onlyNumbers) score -= 20;

    return Math.max(0, Math.min(100, score));
}

test('Password Intelligence - Entropy calculation', () => {
    assert.equal(calculateEntropy(''), 0);
    // 8 lowercase letters: pool 26 -> 8 * log2(26) = 8 * 4.7004 = 37.6
    assert.equal(calculateEntropy('abcdefgh'), 37.6);
    // 16 chars with full pool (26 + 26 + 10 + 33 = 95): 16 * log2(95) = 16 * 6.5698 = 105.1
    assert.equal(calculateEntropy('aB3!aB3!aB3!aB3!'), 105.1);
});

test('Password Intelligence - Common password detection', () => {
    assert.equal(detectPatterns('password').commonPassword, true);
    assert.equal(detectPatterns('123456').commonPassword, true);
    assert.equal(detectPatterns('Xk9#mP2$qL5*vN8!').commonPassword, false);
});

test('Password Intelligence - Pattern detection', () => {
    assert.equal(detectPatterns('pass1234word').numberSequence, true);
    assert.equal(detectPatterns('myqwertykey').keyboardSequence, true);
    assert.equal(detectPatterns('aaaabbbb').repeatedCharacters, true);
    assert.equal(detectPatterns('987654321').onlyNumbers, true);
});

test('Password Intelligence - Strength score boundaries', () => {
    assert.equal(calculateStrengthScore(''), 0);
    assert.equal(calculateStrengthScore('password'), 5);
    // Complex 20+ character random password scores 90-100
    const highEntropy = 'Jk8#mQ2$vL9*wZ4!xP7@';
    assert.ok(calculateStrengthScore(highEntropy) >= 90);
});

