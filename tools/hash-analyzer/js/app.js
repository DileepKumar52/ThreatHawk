/**
 * ThreatHawk Hash Analyzer & Native Digest Generator
 * Comprehensive cryptographic hash format identification, duplicate detection, batch analysis, and Web Crypto generation.
 */

"use strict";

(function () {
    const hashInput = document.getElementById("hashInput");
    const hashFiles = document.getElementById("hashFiles");
    const dropZone = document.getElementById("dropZone");
    const analyzeBtn = document.getElementById("analyzeBtn");
    const clearBtn = document.getElementById("clearBtn");

    const totalHashesEl = document.getElementById("totalHashes");
    const validHashesEl = document.getElementById("validHashes");
    const invalidHashesEl = document.getElementById("invalidHashes");
    const duplicateHashesEl = document.getElementById("duplicateHashes");
    const hashResultsBody = document.getElementById("hashResultsBody");

    const exportTxtBtn = document.getElementById("exportTxtBtn");
    const exportJsonBtn = document.getElementById("exportJsonBtn");
    const exportCsvBtn = document.getElementById("exportCsvBtn");

    // Generator elements
    const plainTextInput = document.getElementById("plainTextInput");
    const genSha256 = document.getElementById("genSha256");
    const genSha512 = document.getElementById("genSha512");
    const genSha384 = document.getElementById("genSha384");
    const genSha1 = document.getElementById("genSha1");

    let currentResults = [];

    // --------------------------------------------------------------------------
    // 1. ADVANCED HASH IDENTIFICATION
    // --------------------------------------------------------------------------
    function identifyHash(str) {
        const val = str.trim();
        if (!val) return { type: "Empty", valid: false, length: 0 };

        // Bcrypt ($2a$, $2b$, $2y$)
        if (/^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$/.test(val)) {
            return { type: "Bcrypt (Blowfish)", valid: true, length: val.length, category: "bcrypt" };
        }

        // Argon2 ($argon2id$, $argon2i$, $argon2d$)
        if (/^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/.test(val)) {
            return { type: "Argon2 Password Hash", valid: true, length: val.length, category: "bcrypt" };
        }

        // Unix Crypt variants
        if (/^\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$/.test(val)) {
            return { type: "SHA-512 Crypt (Unix)", valid: true, length: val.length, category: "sha512" };
        }
        if (/^\$5\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}$/.test(val)) {
            return { type: "SHA-256 Crypt (Unix)", valid: true, length: val.length, category: "sha256" };
        }
        if (/^\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$/.test(val)) {
            return { type: "MD5 Crypt (Unix)", valid: true, length: val.length, category: "md5" };
        }

        // Standard Hex Hashes (Must be valid hex)
        if (!/^[a-fA-F0-9]+$/.test(val)) {
            return { type: "Invalid Non-Hex Characters", valid: false, length: val.length, category: "unknown" };
        }

        switch (val.length) {
            case 8:
                return { type: "CRC32", valid: true, length: 8, category: "md5" };
            case 32:
                return { type: "MD5 / NTLM", valid: true, length: 32, category: "md5" };
            case 40:
                return { type: "SHA-1 / RIPEMD-160", valid: true, length: 40, category: "sha1" };
            case 56:
                return { type: "SHA-224 / SHA3-224", valid: true, length: 56, category: "sha256" };
            case 64:
                return { type: "SHA-256 / SHA3-256 / BLAKE2s", valid: true, length: 64, category: "sha256" };
            case 96:
                return { type: "SHA-384 / SHA3-384", valid: true, length: 96, category: "sha512" };
            case 128:
                return { type: "SHA-512 / SHA3-512 / BLAKE2b", valid: true, length: 128, category: "sha512" };
            default:
                return { type: `Unknown (${val.length} hex digits)`, valid: false, length: val.length, category: "unknown" };
        }
    }

    // --------------------------------------------------------------------------
    // 2. BATCH & TEXT ANALYSIS
    // --------------------------------------------------------------------------
    function extractHashes(text) {
        return text
            .split(/[\r\n,;\s]+/)
            .map(s => s.trim().replace(/^["']|["']$/g, ""))
            .filter(Boolean);
    }

    function processHashes(hashList) {
        const seen = new Map();
        const results = [];
        let validCount = 0;
        let invalidCount = 0;
        let duplicateCount = 0;

        hashList.forEach((raw, idx) => {
            const lower = raw.toLowerCase();
            const isDup = seen.has(lower);
            if (isDup) {
                duplicateCount++;
                seen.set(lower, seen.get(lower) + 1);
            } else {
                seen.set(lower, 1);
            }

            const info = identifyHash(raw);
            if (info.valid) validCount++;
            else invalidCount++;

            results.push({
                id: idx + 1,
                hash: raw,
                type: info.type,
                valid: info.valid,
                category: info.category,
                isDuplicate: isDup
            });
        });

        currentResults = results;

        // Update counts
        if (totalHashesEl) totalHashesEl.textContent = results.length;
        if (validHashesEl) validHashesEl.textContent = validCount;
        if (invalidHashesEl) invalidHashesEl.textContent = invalidCount;
        if (duplicateHashesEl) duplicateHashesEl.textContent = duplicateCount;

        // Render Table
        renderTable(results);
    }

    function renderTable(results) {
        if (!hashResultsBody) return;
        if (results.length === 0) {
            hashResultsBody.innerHTML = `
                <tr>
                    <td colspan="5" style="text-align: center; padding: 32px; color: var(--color-mute);">
                        No hashes parsed yet. Paste hashes above or drop a file to analyze.
                    </td>
                </tr>
            `;
            return;
        }

        hashResultsBody.innerHTML = results.map(r => `
            <tr>
                <td style="font-family: var(--font-mono); color: var(--color-mute);">${r.id}</td>
                <td>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span class="hash-cell-code" title="${r.hash}">${r.hash}</span>
                        ${r.isDuplicate ? '<span style="font-size:10px; padding:2px 6px; background:#fef3c7; color:#b45309; border-radius:4px; font-weight:600;">DUP</span>' : ''}
                    </div>
                </td>
                <td>
                    <span class="hash-type-badge ${r.category}">
                        ${r.type}
                    </span>
                </td>
                <td>
                    <span style="font-size: 12px; font-weight: 500; color: ${r.valid ? 'var(--color-success-alt)' : 'var(--color-error)'};">
                        ${r.valid ? '✓ Valid' : '✕ Invalid'}
                    </span>
                </td>
                <td>
                    <button type="button" class="btn-app-ghost" style="height:26px; padding:0 8px; font-size:11px;" onclick="window.ThreatHawk.copyToClipboard('${r.hash}', 'Hash copied')">
                        <i class="fa-regular fa-copy" aria-hidden="true"></i> Copy
                    </button>
                </td>
            </tr>
        `).join("");
    }

    // --------------------------------------------------------------------------
    // 3. FILE DROP & READ
    // --------------------------------------------------------------------------
    async function handleFile(file) {
        if (!file) return;
        try {
            const text = await file.text();
            const extracted = extractHashes(text);
            if (extracted.length === 0) {
                if (window.ThreatHawk) window.ThreatHawk.toast("No hashes found in file", "fa-triangle-exclamation");
                return;
            }
            processHashes(extracted);
            if (window.ThreatHawk) window.ThreatHawk.toast(`Parsed ${extracted.length} hashes from ${file.name}`, "fa-file-circle-check");
        } catch (e) {
            console.error("File read error:", e);
            if (window.ThreatHawk) window.ThreatHawk.toast("Could not read file", "fa-xmark");
        }
    }

    // --------------------------------------------------------------------------
    // 4. BROWSER NATIVE HASH GENERATOR (Web Crypto API)
    // --------------------------------------------------------------------------
    async function computeDigest(algo, message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest(algo, msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
    }

    async function updateGeneratedHashes() {
        const text = plainTextInput.value;
        if (!text) {
            if (genSha256) genSha256.textContent = "—";
            if (genSha512) genSha512.textContent = "—";
            if (genSha384) genSha384.textContent = "—";
            if (genSha1) genSha1.textContent = "—";
            return;
        }

        try {
            const [s256, s512, s384, s1] = await Promise.all([
                computeDigest("SHA-256", text),
                computeDigest("SHA-512", text),
                computeDigest("SHA-384", text),
                computeDigest("SHA-1", text)
            ]);

            if (genSha256) genSha256.textContent = s256;
            if (genSha512) genSha512.textContent = s512;
            if (genSha384) genSha384.textContent = s384;
            if (genSha1) genSha1.textContent = s1;
        } catch (e) {
            console.error("Digest computation error:", e);
        }
    }

    // --------------------------------------------------------------------------
    // 5. EXPORT HELPERS
    // --------------------------------------------------------------------------
    function downloadFile(content, fileName, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // --------------------------------------------------------------------------
    // 6. INITIALIZATION & EVENTS
    // --------------------------------------------------------------------------
    document.addEventListener("DOMContentLoaded", () => {
        // Tab switching
        const tabIdentifier = document.getElementById("tabIdentifier");
        const tabGenerator = document.getElementById("tabGenerator");
        const panelIdentifier = document.getElementById("panelIdentifier");
        const panelGenerator = document.getElementById("panelGenerator");

        if (tabIdentifier && tabGenerator) {
            tabIdentifier.addEventListener("click", () => {
                tabIdentifier.classList.add("active");
                tabGenerator.classList.remove("active");
                panelIdentifier.style.display = "block";
                panelGenerator.style.display = "none";
            });

            tabGenerator.addEventListener("click", () => {
                tabGenerator.classList.add("active");
                tabIdentifier.classList.remove("active");
                panelIdentifier.style.display = "none";
                panelGenerator.style.display = "block";
                plainTextInput.focus();
            });
        }

        // Live generator typing
        if (plainTextInput) {
            plainTextInput.addEventListener("input", updateGeneratedHashes);
        }

        // Manual Analyze button
        if (analyzeBtn && hashInput) {
            analyzeBtn.addEventListener("click", () => {
                const text = hashInput.value.trim();
                if (!text) {
                    if (window.ThreatHawk) window.ThreatHawk.toast("Paste hashes to analyze", "fa-triangle-exclamation");
                    hashInput.focus();
                    return;
                }
                const hashes = extractHashes(text);
                processHashes(hashes);
                if (window.ThreatHawk) window.ThreatHawk.toast(`Identified ${hashes.length} hashes`, "fa-check");
            });
        }

        // Clear button
        if (clearBtn) {
            clearBtn.addEventListener("click", () => {
                if (hashInput) hashInput.value = "";
                if (hashFiles) hashFiles.value = "";
                currentResults = [];
                processHashes([]);
                if (window.ThreatHawk) window.ThreatHawk.toast("Workspace reset", "fa-rotate-left");
            });
        }

        // File drop zone
        if (dropZone && hashFiles) {
            dropZone.addEventListener("dragover", e => {
                e.preventDefault();
                dropZone.classList.add("dragover");
            });
            dropZone.addEventListener("dragleave", () => {
                dropZone.classList.remove("dragover");
            });
            dropZone.addEventListener("drop", e => {
                e.preventDefault();
                dropZone.classList.remove("dragover");
                if (e.dataTransfer.files.length > 0) {
                    handleFile(e.dataTransfer.files[0]);
                }
            });
            hashFiles.addEventListener("change", () => {
                if (hashFiles.files.length > 0) {
                    handleFile(hashFiles.files[0]);
                }
            });
        }

        // Export Actions
        if (exportTxtBtn) {
            exportTxtBtn.addEventListener("click", () => {
                if (currentResults.length === 0) return;
                const txt = currentResults.map(r => `${r.hash} | ${r.type} | Valid: ${r.valid}`).join("\n");
                downloadFile(txt, "threathawk-hashes.txt", "text/plain");
            });
        }

        if (exportJsonBtn) {
            exportJsonBtn.addEventListener("click", () => {
                if (currentResults.length === 0) return;
                const json = JSON.stringify(currentResults, null, 2);
                downloadFile(json, "threathawk-hashes.json", "application/json");
            });
        }

        if (exportCsvBtn) {
            exportCsvBtn.addEventListener("click", () => {
                if (currentResults.length === 0) return;
                const header = "ID,Hash,Type,Valid,IsDuplicate\n";
                const rows = currentResults.map(r => `"${r.id}","${r.hash}","${r.type}",${r.valid},${r.isDuplicate}`).join("\n");
                downloadFile(header + rows, "threathawk-hashes.csv", "text/csv");
            });
        }

        renderTable([]);
    });
})();
