import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

test('favicon.svg is a valid scalable SVG vector with modern ThreatHawk branding', () => {
    const svgPath = path.join(rootDir, 'favicon.svg');
    assert.ok(fs.existsSync(svgPath), 'favicon.svg exists');
    const content = fs.readFileSync(svgPath, 'utf8');

    assert.ok(content.includes('<svg'), 'contains svg root');
    assert.ok(content.includes('viewBox="0 0 512 512"'), 'has 512x512 viewBox');
    assert.ok(content.includes('threatHawkEmblem'), 'contains threatHawkEmblem graphic group');
    assert.ok(!content.includes('ns0:'), 'free of broken namespace prefixes');
});

test('favicon.ico is a valid multi-resolution icon file', () => {
    const icoPath = path.join(rootDir, 'favicon.ico');
    assert.ok(fs.existsSync(icoPath), 'favicon.ico exists');
    const buf = fs.readFileSync(icoPath);

    assert.ok(buf.length > 100, 'ICO file has content');
    assert.equal(buf.readUInt16LE(0), 0, 'Reserved must be 0');
    assert.equal(buf.readUInt16LE(2), 1, 'Type must be 1 (ICO)');
    const count = buf.readUInt16LE(4);
    assert.ok(count >= 3, `Expected at least 3 resolutions (16, 32, 48), got ${count}`);

    // Verify first entry points to valid PNG data
    const firstOffset = buf.readUInt32LE(18); // offset of first image in header
    const firstMagic = buf.subarray(firstOffset, firstOffset + 8);
    assert.deepEqual(firstMagic, PNG_MAGIC, 'First ICO frame is valid PNG data');
});

test('Raster PNG icons are valid PNGs with correct dimensions', () => {
    const expected = [
        { file: 'favicon-96x96.png', w: 96, h: 96 },
        { file: 'apple-touch-icon.png', w: 180, h: 180 },
        { file: 'web-app-manifest-192x192.png', w: 192, h: 192 },
        { file: 'web-app-manifest-512x512.png', w: 512, h: 512 }
    ];

    for (const item of expected) {
        const filePath = path.join(rootDir, item.file);
        assert.ok(fs.existsSync(filePath), `${item.file} exists`);
        const buf = fs.readFileSync(filePath);

        assert.deepEqual(buf.subarray(0, 8), PNG_MAGIC, `${item.file} has PNG magic signature`);
        const width = buf.readUInt32BE(16);
        const height = buf.readUInt32BE(20);
        assert.equal(width, item.w, `${item.file} width expected ${item.w}, got ${width}`);
        assert.equal(height, item.h, `${item.file} height expected ${item.h}, got ${height}`);
    }
});

test('site.webmanifest is valid JSON and links all PWA manifest icons', () => {
    const manifestPath = path.join(rootDir, 'site.webmanifest');
    assert.ok(fs.existsSync(manifestPath), 'site.webmanifest exists');
    const content = fs.readFileSync(manifestPath, 'utf8');
    const manifest = JSON.parse(content);

    assert.equal(manifest.name, 'ThreatHawk');
    assert.ok(Array.isArray(manifest.icons), 'icons is an array');
    assert.ok(manifest.icons.length >= 2, 'has 192x192 and 512x512 icons');

    for (const icon of manifest.icons) {
        const rel = icon.src.replace(/^\//, '');
        assert.ok(fs.existsSync(path.join(rootDir, rel)), `Icon ${icon.src} exists on disk`);
    }
});

