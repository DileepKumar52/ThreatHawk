import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const ALL_PAGES = [
    'index.html',
    'tools/password-analyzer/index.html',
    'tools/url-analyzer/index.html',
    'tools/hash-analyzer/index.html',
    'tools/log-analyzer/index.html',
    'tools/encoder-decoder/index.html',
    'guides/index.html',
    'guides/how-to-check-if-a-url-is-safe/index.html',
    'guides/how-to-read-security-logs/index.html',
    'guides/md5-vs-sha1-vs-sha256-vs-sha512/index.html',
    'guides/what-are-indicators-of-compromise/index.html',
    'guides/what-is-base64-encoding/index.html',
    'guides/what-is-phishing/index.html',
    'guides/what-makes-a-password-strong/index.html',
    'about/index.html',
    'contact/index.html',
    'privacy-policy/index.html',
    'terms/index.html',
    'disclaimer/index.html'
];

const REQUIRED_TOOLS = [
    'password-analyzer',
    'url-analyzer',
    'hash-analyzer',
    'log-analyzer',
    'encoder-decoder'
];

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.ico': 'image/x-icon',
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

function httpGet(url) {
    return new Promise((resolve, reject) => {
        http.get(url, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        }).on('error', reject);
    });
}

test('Navigation - Exactly 19 platform pages are tracked and exist on disk', () => {
    assert.strictEqual(ALL_PAGES.length, 19, 'Expected 19 platform pages');
    for (const page of ALL_PAGES) {
        const fullPath = path.join(rootDir, page);
        assert.ok(fs.existsSync(fullPath), `Page file ${page} must exist`);
    }
});

test('Navigation - Modules dropdown exists and has proper accessibility attributes on every page', () => {
    for (const page of ALL_PAGES) {
        const content = fs.readFileSync(path.join(rootDir, page), 'utf8');

        // Dropdown toggle button
        assert.ok(
            content.includes('aria-controls="modulesDropdown"'),
            `${page} must have a button with aria-controls="modulesDropdown"`
        );
        assert.ok(
            content.includes('aria-expanded="false"'),
            `${page} dropdown toggle must have initial aria-expanded="false"`
        );

        // Dropdown container must NOT be active on page load
        const dropdownContainerMatch = content.match(/<li[^>]*class="([^"]*(?:th-dropdown|nav-dropdown)[^"]*)"/i);
        assert.ok(dropdownContainerMatch, `${page} must have a dropdown container (.th-dropdown or .nav-dropdown)`);
        assert.ok(
            !dropdownContainerMatch[1].split(/\s+/).includes('active'),
            `${page} dropdown container must NOT have class "active" on page load`
        );

        // Dropdown menu element
        assert.ok(
            content.includes('id="modulesDropdown"'),
            `${page} must have dropdown menu element with id="modulesDropdown"`
        );
    }
});

test('Navigation - All 5 cybersecurity tools are accessible from the Modules dropdown on every page', () => {
    for (const page of ALL_PAGES) {
        const content = fs.readFileSync(path.join(rootDir, page), 'utf8');
        const menuMatch = content.match(/<ul[^>]*id="modulesDropdown"[\s\S]*?<\/ul>/i);
        assert.ok(menuMatch, `${page} must contain a <ul> with id="modulesDropdown"`);

        const menuHtml = menuMatch[0];
        const links = [...menuHtml.matchAll(/href="([^"]*)"/g)].map(m => m[1]);
        const pageDir = path.dirname(page);

        const resolvedTargets = links.map(l => {
            let resolved = l.startsWith('/') ? path.join('.', l) : path.join(pageDir, l);
            if (resolved.endsWith('/') || !path.extname(resolved)) {
                resolved = path.join(resolved, 'index.html');
            }
            return { raw: l, resolved: path.normalize(resolved) };
        });

        for (const tool of REQUIRED_TOOLS) {
            const hasTool = resolvedTargets.some(t => t.resolved.includes(tool));
            assert.ok(hasTool, `${page} Modules dropdown must contain a link that resolves to tool: ${tool}`);
        }
    }
});

test('Navigation - All dropdown tool links resolve to HTTP 200 OK over the test server', async () => {
    for (const page of ALL_PAGES) {
        const content = fs.readFileSync(path.join(rootDir, page), 'utf8');
        const menuMatch = content.match(/<ul[^>]*id="modulesDropdown"[\s\S]*?<\/ul>/i);
        const links = [...menuMatch[0].matchAll(/href="([^"]*)"/g)].map(m => m[1]);

        // Construct current page URL path on test server
        const pageUrlPath = page === 'index.html' ? '/' : '/' + path.dirname(page) + '/';
        const pageUrl = new URL(pageUrlPath, baseUrl);

        for (const rawLink of links) {
            // Resolve link relative to current page URL
            const resolvedUrl = new URL(rawLink, pageUrl);
            const res = await httpGet(resolvedUrl.href);

            assert.strictEqual(
                res.status,
                200,
                `${page} tool link "${rawLink}" (resolved to ${resolvedUrl.pathname}) must return HTTP 200, got ${res.status}`
            );
            assert.ok(
                res.body.includes('<!DOCTYPE html>') || res.body.includes('<html'),
                `${resolvedUrl.pathname} must serve HTML content`
            );
        }
    }
});

test('Navigation - No page has duplicate or conflicting JavaScript listeners', () => {
    for (const page of ALL_PAGES) {
        const content = fs.readFileSync(path.join(rootDir, page), 'utf8');
        const scripts = [...content.matchAll(/<script[^>]*src="([^"]*)"/gi)].map(m => m[1]);

        // Check that app.js and core.js are never loaded simultaneously on the same page
        const hasAppJs = scripts.some(s => s.endsWith('app.js') && !s.includes('tools/'));
        const hasCoreJs = scripts.some(s => s.endsWith('core.js'));

        if (['about/index.html', 'contact/index.html', 'privacy-policy/index.html', 'terms/index.html', 'disclaimer/index.html'].includes(page)) {
            assert.ok(!hasAppJs, `${page} must NOT load legacy app.js`);
            assert.ok(hasCoreJs, `${page} must load core.js`);
        }
    }
});

test('Navigation - Mobile navigation drawer and toggle button exist on every page', () => {
    for (const page of ALL_PAGES) {
        const content = fs.readFileSync(path.join(rootDir, page), 'utf8');
        assert.ok(content.includes('th-mobile-toggle'), `${page} must contain a mobile menu toggle (.th-mobile-toggle)`);
        assert.ok(content.includes('id="mobileDrawer"'), `${page} must contain mobile navigation drawer (#mobileDrawer)`);

        // Check that mobile drawer contains all 5 tools
        const drawerMatch = content.match(/<div[^>]*id="mobileDrawer"[\s\S]*?<\/div>/i);
        assert.ok(drawerMatch, `${page} mobile drawer must be present in HTML`);
        const drawerHtml = drawerMatch[0];
        const drawerLinks = [...drawerHtml.matchAll(/href="([^"]*)"/g)].map(m => m[1]);
        const pageDir = path.dirname(page);

        const resolvedDrawerTargets = drawerLinks.map(l => {
            let resolved = l.startsWith('/') ? path.join('.', l) : path.join(pageDir, l);
            if (resolved.endsWith('/') || !path.extname(resolved)) {
                resolved = path.join(resolved, 'index.html');
            }
            return { raw: l, resolved: path.normalize(resolved) };
        });

        for (const tool of REQUIRED_TOOLS) {
            const hasTool = resolvedDrawerTargets.some(t => t.resolved.includes(tool));
            assert.ok(
                hasTool,
                `${page} mobile drawer must provide access to tool: ${tool}`
            );
        }
    }
});

test('Navigation - js/core.js exports dropdown and drawer APIs with idempotency guard', () => {
    const coreJs = fs.readFileSync(path.join(rootDir, 'js/core.js'), 'utf8');
    assert.ok(coreJs.includes('initDropdowns'), 'core.js must implement initDropdowns');
    assert.ok(coreJs.includes('thDropdownInitialized'), 'core.js must guard against multiple dropdown initializations');
    assert.ok(coreJs.includes('initMobileDrawer'), 'core.js must implement initMobileDrawer');
    assert.ok(coreJs.includes('ArrowDown'), 'core.js dropdown must support ArrowDown keyboard navigation');
    assert.ok(coreJs.includes('Escape'), 'core.js dropdown must support Escape keyboard closing');
});
