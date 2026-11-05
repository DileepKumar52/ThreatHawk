import test from 'node:test';
import assert from 'node:assert/strict';

function isIPAddress(host) {
    if (/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(host)) return true;
    if (host.includes(":") && /^[a-fA-F0-9:\[\]]+$/.test(host)) return true;
    if (/^\d{8,11}$/.test(host)) return true;
    return false;
}

function detectHomograph(host) {
    if (host.toLowerCase().startsWith("xn--")) return true;
    return /[^\u0000-\u007F]/.test(host);
}

const SUSPICIOUS_TLDS = new Set([".zip", ".mov", ".top", ".tk", ".buzz", ".country"]);

function checkSuspiciousTLD(host) {
    const parts = host.toLowerCase().split(".");
    if (parts.length < 2) return false;
    return SUSPICIOUS_TLDS.has(`.${parts[parts.length - 1]}`);
}

function hasEmbeddedCredentials(url) {
    try {
        const u = new URL(url);
        return Boolean(u.username || u.password || url.includes("@"));
    } catch {
        return false;
    }
}

test('URL Analyzer - IP address detection', () => {
    assert.equal(isIPAddress('192.168.1.1'), true);
    assert.equal(isIPAddress('45.227.255.206'), true);
    assert.equal(isIPAddress('2130706433'), true); // Decimal IP for 127.0.0.1
    assert.equal(isIPAddress('threathawk.net'), false);
    assert.equal(isIPAddress('google.com'), false);
});

test('URL Analyzer - Homograph & Punycode detection', () => {
    assert.equal(detectHomograph('xn--gogle-qta.com'), true);
    assert.equal(detectHomograph('googlе.com'), true); // Cyrillic 'е' (U+0435)
    assert.equal(detectHomograph('google.com'), false);
});

test('URL Analyzer - Suspicious TLD detection', () => {
    assert.equal(checkSuspiciousTLD('update-secure.zip'), true);
    assert.equal(checkSuspiciousTLD('login-account.top'), true);
    assert.equal(checkSuspiciousTLD('legitimate-site.org'), false);
});

test('URL Analyzer - Embedded credentials detection', () => {
    assert.equal(hasEmbeddedCredentials('https://admin:pass@example.com'), true);
    assert.equal(hasEmbeddedCredentials('https://paypal.com@malicious-host.com'), true);
    assert.equal(hasEmbeddedCredentials('https://threathawk.net/tools/'), false);
});

