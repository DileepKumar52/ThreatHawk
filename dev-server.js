/**
 * ThreatHawk Local Development Server
 * Lightweight, zero-dependency development server supporting:
 * - Multi-page static routing (clean URLs, directories, index.html resolution)
 * - Serverless API execution (/api/safe-browsing) compatible with production Vercel runtime
 * - Automatic .env and .env.local configuration loading
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 1. Load local environment variables (.env.local, .env) if present
for (const envFile of ['.env.local', '.env']) {
    const envPath = path.join(__dirname, envFile);
    if (fs.existsSync(envPath)) {
        try {
            process.loadEnvFile(envPath);
            console.log(`Loaded environment from ${envFile}`);
            break;
        } catch (e) {
            console.warn(`Could not load ${envFile}:`, e.message);
        }
    }
}

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.ico': 'image/x-icon',
    '.txt': 'text/plain; charset=utf-8',
    '.xml': 'application/xml; charset=utf-8',
    '.webmanifest': 'application/manifest+json',
    '.woff2': 'font/woff2',
    '.woff': 'font/woff',
    '.ttf': 'font/ttf'
};

// 2. Import serverless function handler
let safeBrowsingHandler = null;
try {
    const apiModule = await import('./api/safe-browsing.js');
    safeBrowsingHandler = apiModule.default;
} catch (err) {
    console.warn('Could not pre-import api/safe-browsing.js:', err.message);
}

// 3. HTTP Server
const server = http.createServer(async (req, res) => {
    const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = decodeURIComponent(urlObj.pathname);

    // API Routing: /api/safe-browsing
    if (pathname === '/api/safe-browsing' || pathname === '/api/safe-browsing/') {
        if (!safeBrowsingHandler) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'API handler not loaded.' }));
        }

        // Collect body
        let bodyRaw = '';
        req.on('data', chunk => {
            bodyRaw += chunk;
        });

        req.on('end', async () => {
            try {
                if (bodyRaw) {
                    try {
                        req.body = JSON.parse(bodyRaw);
                    } catch {
                        req.body = {};
                    }
                } else {
                    req.body = {};
                }

                // Adapter to match Vercel Serverless Function signature
                const vercelRes = {
                    statusCode: 200,
                    setHeader(name, val) {
                        res.setHeader(name, val);
                        return this;
                    },
                    status(code) {
                        this.statusCode = code;
                        return this;
                    },
                    json(data) {
                        res.writeHead(this.statusCode, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify(data));
                        return this;
                    },
                    end(data = '') {
                        res.writeHead(this.statusCode);
                        res.end(data);
                        return this;
                    }
                };

                await safeBrowsingHandler(req, vercelRes);
            } catch (err) {
                console.error('API Error in /api/safe-browsing:', err);
                if (!res.headersSent) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Internal server error in API.' }));
                }
            }
        });
        return;
    }

    // Static File Serving
    let relativePath = pathname.replace(/^\/+/, '');
    if (!relativePath) relativePath = 'index.html';

    let filePath = path.join(__dirname, relativePath);

    // If path is a directory, ensure trailing slash for correct relative asset resolution
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
        // Try appending .html (clean URLs support)
        if (fs.existsSync(filePath + '.html')) {
            filePath = filePath + '.html';
        }
    }

    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        const ext = path.extname(filePath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';

        res.writeHead(200, {
            'Content-Type': contentType,
            'X-Content-Type-Options': 'nosniff'
        });
        fs.createReadStream(filePath).pipe(res);
    } else {
        // 404 Not Found
        res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The path <code>${pathname}</code> was not found.</p><a href="/">Return to ThreatHawk Home</a></body></html>`);
    }
});

server.listen(PORT, '127.0.0.1', () => {
    console.log(`\n🦅 ThreatHawk Dev Server running at:`);
    console.log(`   ➜ Local:   http://localhost:${PORT}/`);
    console.log(`   ➜ API:     http://localhost:${PORT}/api/safe-browsing`);
    console.log(`   ➜ Network: http://127.0.0.1:${PORT}/\n`);
    console.log(`Press Ctrl+C to stop.\n`);
});

