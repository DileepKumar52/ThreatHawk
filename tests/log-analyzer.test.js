import test from 'node:test';
import assert from 'node:assert/strict';

const RULES = [
    { name: "SQL Injection", severity: "critical", regex: /(\bUNION\b.{1,40}\bSELECT\b|'\s*OR\s*'?\d+'?\s*=\s*'?\d+|--|\bINFORMATION_SCHEMA\b)/i },
    { name: "XSS", severity: "critical", regex: /(<script[\s>]|javascript:|onerror\s*=|onload\s*=)/i },
    { name: "Path Traversal", severity: "critical", regex: /(\.\.\/|\.\.\\|\/etc\/passwd)/i },
    { name: "Failed Auth", severity: "warning", regex: /(failed\s+password|authentication\s+failure|failed\s+login)/i }
];

function isPrivateIP(ip) {
    return /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.0\.0\.1)/.test(ip);
}

function matchRule(line) {
    for (const r of RULES) {
        if (r.regex.test(line)) return r.name;
    }
    return null;
}

test('Log Analyzer - SQL Injection pattern detection', () => {
    const line = 'GET /items.php?cat=1 UNION SELECT 1,username,password FROM admin-- 200';
    assert.equal(matchRule(line), 'SQL Injection');
});

test('Log Analyzer - XSS detection', () => {
    const line = 'POST /comment.php - text=<script>alert(1)</script>';
    assert.equal(matchRule(line), 'XSS');
});

test('Log Analyzer - Path Traversal detection', () => {
    const line = 'GET /download.php?file=../../../../etc/passwd HTTP/1.1';
    assert.equal(matchRule(line), 'Path Traversal');
});

test('Log Analyzer - Authentication failure detection', () => {
    const line = 'Failed password for invalid user admin from 185.143.223.11 port 42812 ssh2';
    assert.equal(matchRule(line), 'Failed Auth');
});

test('Log Analyzer - RFC1918 Private vs Public IP routing', () => {
    assert.equal(isPrivateIP('192.168.1.100'), true);
    assert.equal(isPrivateIP('10.0.4.15'), true);
    assert.equal(isPrivateIP('172.16.0.1'), true);
    assert.equal(isPrivateIP('127.0.0.1'), true);
    assert.equal(isPrivateIP('45.227.255.206'), false);
    assert.equal(isPrivateIP('8.8.8.8'), false);
});

