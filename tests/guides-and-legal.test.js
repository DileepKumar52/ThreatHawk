import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.ico': 'image/x-icon',
    '.txt': 'text/plain; charset=utf-8',
    '.webmanifest': 'application/manifest+json'
};

let server;
let baseUrl;

before(async () => {
    await new Promise((resolve) => {
        server = http.createServer((req, res) => {
            const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
            const pathname = decodeURIComponent(urlObj.pathname);

            let relativePath = pathname.replace(/^\/+/, '');
            if (!relativePath) relativePath = 'index.html';

            let filePath = path.join(rootDir, relativePath);

            if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
                if (!pathname.endsWith('/')) {
                    const redirectTarget = pathname + '/' + (urlObj.search || '');
                    res.writeHead(301, {
                        'Location': redirectTarget,
                        'Content-Type': 'text/plain'
                    });
                    return res.end(`Redirecting to ${redirectTarget}`);
                }
                filePath = path.join(filePath, 'index.html');
            } else if (!fs.existsSync(filePath)) {
                if (fs.existsSync(filePath + '.html')) {
                    filePath = filePath + '.html';
                }
            }

            if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
                const ext = path.extname(filePath).toLowerCase();
                const contentType = MIME_TYPES[ext] || 'application/octet-stream';
                res.writeHead(200, { 'Content-Type': contentType });
                fs.createReadStream(filePath).pipe(res);
            } else {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('Not found');
            }
        });

        server.listen(0, '127.0.0.1', () => {
            baseUrl = `http://127.0.0.1:${server.address().port}`;
            resolve();
        });
    });
});

after(() => {
    if (server) server.close();
});

function request(url, options = {}) {
    return new Promise((resolve, reject) => {
        http.get(url, options, (res) => {
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
                resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    body: data
                });
            });
        }).on('error', reject);
    });
}

const targetPages = [
    '/guides/',
    '/guides/how-to-check-if-a-url-is-safe/',
    '/guides/how-to-read-security-logs/',
    '/guides/md5-vs-sha1-vs-sha256-vs-sha512/',
    '/guides/what-are-indicators-of-compromise/',
    '/guides/what-is-base64-encoding/',
    '/guides/what-is-phishing/',
    '/guides/what-makes-a-password-strong/',
    '/about/',
    '/contact/',
    '/privacy-policy/',
    '/terms/',
    '/disclaimer/'
];

test('Directory routes without trailing slash return 301 redirect', async () => {
    for (const page of targetPages) {
        const withoutSlash = page.replace(/\/$/, '');
        const res = await request(`${baseUrl}${withoutSlash}`);
        assert.equal(res.statusCode, 301, `Expected 301 for ${withoutSlash}`);
        assert.equal(res.headers.location, page, `Expected Location ${page} for ${withoutSlash}`);
    }
});

test('Target guides and legal pages return 200 OK HTML', async () => {
    for (const page of targetPages) {
        const res = await request(`${baseUrl}${page}`);
        assert.equal(res.statusCode, 200, `Expected 200 for ${page}`);
        assert.ok(res.headers['content-type'].includes('text/html'), `Expected text/html for ${page}`);
        assert.ok(res.body.includes('<title>'), `Expected <title> tag in ${page}`);
    }
});

test('All CSS, JS and Favicon assets linked by pages resolve with 200 OK', async () => {
    const checkedAssets = new Set();
    for (const page of targetPages) {
        const res = await request(`${baseUrl}${page}`);
        const html = res.body;

        const cssMatches = [...html.matchAll(/<link[^>]+rel="stylesheet"[^>]+href="([^"]+)"/gi)];
        const jsMatches = [...html.matchAll(/<script[^>]+src="([^"]+)"/gi)];
        const iconMatches = [...html.matchAll(/<link[^>]+rel="(?:icon|shortcut icon|apple-touch-icon)"[^>]+href="([^"]+)"/gi)];

        const assets = [
            ...cssMatches.map(m => m[1]),
            ...jsMatches.map(m => m[1]),
            ...iconMatches.map(m => m[1])
        ];

        for (const asset of assets) {
            if (asset.startsWith('http://') || asset.startsWith('https://')) {
                continue;
            }

            const assetUrl = new URL(asset, `${baseUrl}${page}`).href;
            if (checkedAssets.has(assetUrl)) continue;
            checkedAssets.add(assetUrl);

            const assetRes = await request(assetUrl);
            assert.equal(assetRes.statusCode, 200, `Failed to load asset ${assetUrl} from page ${page}`);
        }
    }
});

