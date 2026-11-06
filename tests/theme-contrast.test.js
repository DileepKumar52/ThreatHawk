import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

function hexToRgb(hex) {
    hex = hex.replace('#', '');
    if (hex.length === 3) {
        hex = hex.split('').map(c => c + c).join('');
    }
    const num = parseInt(hex, 16);
    return {
        r: (num >> 16) & 255,
        g: (num >> 8) & 255,
        b: num & 255
    };
}

function getLuminance({ r, g, b }) {
    const a = [r, g, b].map(v => {
        v /= 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    });
    return a[0] * 0.2126 + a[1] * 0.7152 + a[2] * 0.0722;
}

function getContrast(hex1, hex2) {
    const l1 = getLuminance(hexToRgb(hex1));
    const l2 = getLuminance(hexToRgb(hex2));
    const lighter = Math.max(l1, l2);
    const darker = Math.min(l1, l2);
    return (lighter + 0.05) / (darker + 0.05);
}

test('Light theme hairline contrast is improved and distinctly visible', () => {
    const cssPath = path.join(rootDir, 'css', 'design-system.css');
    const cssContent = fs.readFileSync(cssPath, 'utf8');

    // Extract light theme hairline from :root
    const lightHairlineMatch = cssContent.match(/--color-hairline:\s*(#[0-9a-fA-F]+);/);
    assert.ok(lightHairlineMatch, 'Light hairline defined');
    const lightHairline = lightHairlineMatch[1].toLowerCase();

    const lightSoftMatch = cssContent.match(/--color-hairline-soft:\s*(#[0-9a-fA-F]+);/);
    assert.ok(lightSoftMatch, 'Light hairline-soft defined');
    const lightHairlineSoft = lightSoftMatch[1].toLowerCase();

    // Check contrast against white (#ffffff)
    const contrastAgainstWhite = getContrast(lightHairline, '#ffffff');
    assert.ok(
        contrastAgainstWhite >= 1.4,
        `Expected hairline contrast against white >= 1.4:1, got ${contrastAgainstWhite.toFixed(2)}:1`
    );

    // Soft divider should also have noticeable contrast against white
    const softContrastAgainstWhite = getContrast(lightHairlineSoft, '#ffffff');
    assert.ok(
        softContrastAgainstWhite >= 1.2,
        `Expected hairline-soft contrast against white >= 1.2:1, got ${softContrastAgainstWhite.toFixed(2)}:1`
    );

    // Contrast should remain subtle (not harsh / dark: hairline should be lighter than #999999)
    const hairlineRgb = hexToRgb(lightHairline);
    assert.ok(hairlineRgb.r >= 200, 'Hairline should remain a light neutral tone (>= 200 RGB)');
});

test('Dark theme tokens remain completely unchanged', () => {
    const cssPath = path.join(rootDir, 'css', 'design-system.css');
    const cssContent = fs.readFileSync(cssPath, 'utf8');

    // Find dark theme block
    const darkBlockMatch = cssContent.match(/\[data-theme="dark"\][\s\S]*?\{([\s\S]*?)\}/);
    assert.ok(darkBlockMatch, 'Dark theme block exists');
    const darkBlock = darkBlockMatch[1];

    assert.match(darkBlock, /--color-hairline:\s*#222222;/, 'Dark hairline must be #222222');
    assert.match(darkBlock, /--color-hairline-soft:\s*#171717;/, 'Dark hairline-soft must be #171717');
    assert.match(darkBlock, /--color-canvas:\s*#000000;/, 'Dark canvas must be #000000');
    assert.match(darkBlock, /--color-canvas-elevated:\s*#0a0a0a;/, 'Dark canvas-elevated must be #0a0a0a');
});

