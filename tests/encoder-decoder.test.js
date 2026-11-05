import test from 'node:test';
import assert from 'node:assert/strict';

const UTF8 = {
    encodeBase64(str, urlSafe = false) {
        const bytes = new TextEncoder().encode(str);
        let bin = "";
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        let b64 = btoa(bin);
        if (urlSafe) {
            b64 = b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        }
        return b64;
    },

    decodeBase64(b64) {
        let clean = b64.trim().replace(/-/g, "+").replace(/_/g, "/");
        while (clean.length % 4 !== 0) clean += "=";
        const bin = atob(clean);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return new TextDecoder().decode(bytes);
    },

    encodeHex(str) {
        const bytes = new TextEncoder().encode(str);
        return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join(" ");
    },

    decodeHex(hex) {
        const clean = hex.replace(/[\s0x\\,]/g, "");
        if (clean.length % 2 !== 0) throw new Error("Invalid hex string");
        const bytes = new Uint8Array(clean.length / 2);
        for (let i = 0; i < clean.length; i += 2) {
            bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
        }
        return new TextDecoder().decode(bytes);
    },

    rot13(str) {
        return str.replace(/[a-zA-Z]/g, c => {
            const code = c.charCodeAt(0);
            const base = code >= 97 ? 97 : 65;
            return String.fromCharCode(((code - base + 13) % 26) + base);
        });
    }
};

test('Encoder & Decoder - UTF-8 safe Base64 roundtrip', () => {
    const text = 'Hello ThreatHawk! 🔐 🛡️ Accent: café & résumé';
    const encoded = UTF8.encodeBase64(text);
    const decoded = UTF8.decodeBase64(encoded);
    assert.equal(decoded, text);
});

test('Encoder & Decoder - Base64URL safety', () => {
    // String that produces '+' and '/' in standard base64
    const text = 'subjects?_d=1&_u=2';
    const b64 = UTF8.encodeBase64(text, false);
    const b64url = UTF8.encodeBase64(text, true);
    assert.equal(b64url.includes('+'), false);
    assert.equal(b64url.includes('/'), false);
    assert.equal(b64url.includes('='), false);
    assert.equal(UTF8.decodeBase64(b64url), text);
});

test('Encoder & Decoder - Hex roundtrip', () => {
    const text = 'ThreatHawk';
    const hex = UTF8.encodeHex(text);
    assert.equal(hex, '54 68 72 65 61 74 48 61 77 6b');
    assert.equal(UTF8.decodeHex(hex), text);
});

test('Encoder & Decoder - ROT13 bidirectional shift', () => {
    const text = 'Attack at dawn!';
    const shifted = UTF8.rot13(text);
    assert.equal(shifted, 'Nggnpx ng qnja!');
    assert.equal(UTF8.rot13(shifted), text);
});

