/**
 * ThreatHawk URL Analyzer & Heuristic Reputation Engine
 * Inspects URLs for phishing indicators, homograph spoofing, IP hosts, suspicious TLDs, and queries Google Safe Browsing.
 */

"use strict";

(function () {
    const urlInput = document.getElementById("urlInput");
    const analyzeBtn = document.getElementById("analyzeBtn");
    const clearBtn = document.getElementById("clearBtn");

    const protocol = document.getElementById("protocol");
    const hostname = document.getElementById("hostname");
    const domain = document.getElementById("domain");
    const tld = document.getElementById("tld");
    const subdomain = document.getElementById("subdomain");
    const port = document.getElementById("port");
    const path = document.getElementById("path");
    const query = document.getElementById("query");
    const fragment = document.getElementById("fragment");
    const length = document.getElementById("length");

    const riskScore = document.getElementById("riskScore");
    const riskLabel = document.getElementById("riskLabel");
    const riskDial = document.getElementById("riskDial");
    const findingsList = document.getElementById("findingsList");
    const findingCount = document.getElementById("findingCount");

    const SUSPICIOUS_TLDS = new Set([
        ".zip", ".mov", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".country", ".buzz", ".work", ".click", ".link", ".rest", ".fit"
    ]);

    const URL_SHORTENERS = new Set([
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
        "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc"
    ]);

    const TRUSTED_BRANDS = [
        "google", "microsoft", "apple", "amazon", "paypal", "netflix",
        "facebook", "instagram", "whatsapp", "linkedin", "github", "dropbox",
        "adobe", "coinbase", "binance", "chase", "wellsfargo", "bankofamerica"
    ];

    const EXECUTABLE_EXTENSIONS = [
        ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".msi", ".jar",
        ".apk", ".dmg", ".iso", ".dll"
    ];

    function isIPAddress(host) {
        // Dotted IPv4
        if (/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(host)) return true;
        // IPv6
        if (host.includes(":") && /^[a-fA-F0-9:\[\]]+$/.test(host)) return true;
        // Decimal/Hex obfuscated IP (pure integer)
        if (/^\d{8,11}$/.test(host)) return true;
        return false;
    }

    function detectHomograph(host) {
        if (host.toLowerCase().startsWith("xn--")) return true;
        // Non-ASCII characters in host
        return /[^\u0000-\u007F]/.test(host);
    }

    function detectBrandImpersonation(host) {
        const cleanHost = host.toLowerCase().replace(/^www\./, "");
        const labels = cleanHost.split(".");
        const domainLabel = labels.length >= 2 ? labels[labels.length - 2] : labels[0];

        // Replace common leetspeak
        const normalized = domainLabel
            .replace(/0/g, "o")
            .replace(/1/g, "l")
            .replace(/3/g, "e")
            .replace(/5/g, "s")
            .replace(/7/g, "t")
            .replace(/@/g, "a");

        for (const brand of TRUSTED_BRANDS) {
            if (domainLabel === brand) continue; // Genuine exact domain
            if (normalized.includes(brand) || cleanHost.includes(`${brand}-`) || cleanHost.includes(`-${brand}`)) {
                return { brand, suspicious: domainLabel };
            }
        }
        return null;
    }

    function evaluateHeuristics(urlObj, rawInput) {
        const findings = [];
        let score = 0;

        const host = urlObj.hostname;
        const lowerHost = host.toLowerCase();

        // 1. Insecure HTTP Protocol
        if (urlObj.protocol === "http:") {
            score += 15;
            findings.push({
                severity: "medium",
                title: "Unencrypted Connection (HTTP)",
                description: "Traffic is transmitted in cleartext without TLS encryption, susceptible to interception and tampering."
            });
        }

        // 2. Direct IP Address Host
        if (isIPAddress(host)) {
            score += 35;
            findings.push({
                severity: "high",
                title: "Direct IP Address Hostname",
                description: "The URL connects directly to a numerical IP rather than a registered domain name, common in malicious C2 infrastructure and phishing campaigns."
            });
        }

        // 3. IDN / Punycode Homograph Spoofing
        if (detectHomograph(host)) {
            score += 45;
            findings.push({
                severity: "critical",
                title: "Punycode / IDN Homograph Detected",
                description: "Hostname contains Punycode ('xn--') or Unicode lookalike characters designed to spoof legitimate brand identities."
            });
        }

        // 4. Embedded Credentials
        if (urlObj.username || urlObj.password || rawInput.includes("@")) {
            score += 40;
            findings.push({
                severity: "critical",
                title: "Embedded Credentials in URL (@)",
                description: "The URL contains an '@' character or embedded credentials, frequently used to obscure the actual destination domain in phishing links."
            });
        }

        // 5. Brand Impersonation (Typosquatting)
        const brandMatch = detectBrandImpersonation(host);
        if (brandMatch) {
            score += 35;
            findings.push({
                severity: "high",
                title: `Potential Brand Impersonation (${brandMatch.brand})`,
                description: `Domain contains lookalike pattern mimicking '${brandMatch.brand}', indicating possible typosquatting or phishing intent.`
            });
        }

        // 6. Suspicious TLD
        const parts = lowerHost.split(".");
        const tldStr = parts.length > 1 ? `.${parts[parts.length - 1]}` : "";
        if (SUSPICIOUS_TLDS.has(tldStr)) {
            score += 20;
            findings.push({
                severity: "medium",
                title: `High-Risk Top-Level Domain (${tldStr})`,
                description: `The top-level domain '${tldStr}' has a disproportionate prevalence of spam, malicious redirection, and disposable domains.`
            });
        }

        // 7. URL Shortener
        if (URL_SHORTENERS.has(lowerHost)) {
            score += 15;
            findings.push({
                severity: "info",
                title: "URL Shortener Service",
                description: "URL destination is masked behind a redirection service, hiding the true endpoint from immediate inspection."
            });
        }

        // 8. Deep Subdomain Nesting
        if (parts.length > 4) {
            score += 20;
            findings.push({
                severity: "medium",
                title: "Excessive Subdomain Depth",
                description: `URL contains ${parts.length - 2} subdomain levels, often used to bypass reputation filters or simulate legitimate multi-tenant subdomains.`
            });
        }

        // 9. Dangerous Executable Download Path
        const lowerPath = urlObj.pathname.toLowerCase();
        for (const ext of EXECUTABLE_EXTENSIONS) {
            if (lowerPath.endsWith(ext)) {
                score += 35;
                findings.push({
                    severity: "high",
                    title: `Direct Executable Payload (${ext})`,
                    description: `URL path terminates with an executable payload extension (${ext}), presenting direct binary execution hazard.`
                });
                break;
            }
        }

        // 10. Obfuscated / Double Encoding
        if (/%25|%2e%2e/i.test(urlObj.pathname) || /%25/i.test(urlObj.search)) {
            score += 30;
            findings.push({
                severity: "high",
                title: "Path Traversal / Double Percent Encoding",
                description: "URL contains double-encoded characters (%25) or encoded directory traversal indicators (%2e%2e) designed to evade WAF filters."
            });
        }

        return {
            score: Math.min(100, score),
            findings: findings
        };
    }

    async function checkSafeBrowsing(url) {
        try {
            const res = await fetch("/api/safe-browsing", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url })
            });
            if (!res.ok) return { available: false };
            return await res.json();
        } catch (e) {
            return { available: false };
        }
    }

    function resetUI() {
        protocol.textContent = "—";
        hostname.textContent = "—";
        domain.textContent = "—";
        tld.textContent = "—";
        subdomain.textContent = "—";
        port.textContent = "—";
        path.textContent = "—";
        query.textContent = "—";
        fragment.textContent = "—";
        length.textContent = "—";

        riskScore.textContent = "0";
        riskLabel.textContent = "Not Analyzed";
        if (riskDial) {
            riskDial.style.strokeDashoffset = 377;
            riskDial.style.stroke = "var(--color-mute)";
        }
        findingCount.textContent = "0 findings";
        findingsList.innerHTML = `
            <div style="padding: 24px; text-align: center; color: var(--color-mute);">
                <i class="fa-solid fa-shield-halved" style="font-size: 24px; margin-bottom: 8px; opacity: 0.5;" aria-hidden="true"></i>
                <p>Enter a URL and click Analyze to inspect security indicators.</p>
            </div>
        `;
    }

    async function analyzeURL() {
        let input = urlInput.value.trim();
        if (!input) {
            if (window.ThreatHawk) window.ThreatHawk.toast("Please enter a URL first", "fa-triangle-exclamation");
            urlInput.focus();
            return;
        }

        if (!/^https?:\/\//i.test(input) && !/^ftp:\/\//i.test(input)) {
            input = "https://" + input;
        }

        try {
            const parsed = new URL(input);

            // Populate Parsed Components
            protocol.textContent = parsed.protocol.replace(":", "").toUpperCase();
            hostname.textContent = parsed.hostname;
            const parts = parsed.hostname.split(".");

            if (parts.length >= 2) {
                domain.textContent = parts[parts.length - 2];
                tld.textContent = "." + parts[parts.length - 1];
                subdomain.textContent = parts.length > 2 ? parts.slice(0, -2).join(".") : "None";
            } else {
                domain.textContent = parsed.hostname;
                tld.textContent = "Unknown";
                subdomain.textContent = "None";
            }

            port.textContent = parsed.port || (parsed.protocol === "https:" ? "443 (Default)" : "80 (Default)");
            path.textContent = parsed.pathname || "/";
            query.textContent = parsed.search ? new URLSearchParams(parsed.search).size.toString() : "0";
            fragment.textContent = parsed.hash ? parsed.hash.substring(1) : "None";
            length.textContent = `${input.length} chars`;

            // Run Heuristic Analysis
            const heuristics = evaluateHeuristics(parsed, input);
            let finalScore = heuristics.score;
            const finalFindings = [...heuristics.findings];

            analyzeBtn.disabled = true;
            analyzeBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> Checking…`;

            // Query Safe Browsing
            const rep = await checkSafeBrowsing(input);
            if (rep && rep.checked && rep.safe === false) {
                finalScore = 100;
                finalFindings.unshift({
                    severity: "critical",
                    title: "Google Safe Browsing Threat Match",
                    description: `Flagged as malicious threat: ${rep.threats?.map(t => t.threatType).join(", ") || "Known Malicious Site"}.`
                });
            }

            // Update Risk Dial
            riskScore.textContent = finalScore;
            let label = "Low Risk";
            let color = "var(--color-success-alt)";

            if (finalScore >= 75) { label = "Critical Risk"; color = "var(--color-error)"; }
            else if (finalScore >= 50) { label = "High Risk"; color = "#dc2626"; }
            else if (finalScore >= 25) { label = "Medium Risk"; color = "var(--color-warning)"; }

            riskLabel.textContent = label;
            riskLabel.style.color = color;

            if (riskDial) {
                const circumference = 377;
                const offset = circumference - (finalScore / 100) * circumference;
                riskDial.style.strokeDashoffset = offset;
                riskDial.style.stroke = color;
            }

            // Render Findings
            findingCount.textContent = `${finalFindings.length} finding${finalFindings.length === 1 ? "" : "s"}`;
            if (finalFindings.length === 0) {
                findingsList.innerHTML = `
                    <div style="padding: 16px; display: flex; align-items: center; gap: 10px; color: var(--color-success-alt);">
                        <i class="fa-solid fa-circle-check" aria-hidden="true"></i>
                        <span>No suspicious heuristic patterns or known threat signatures detected.</span>
                    </div>
                `;
            } else {
                findingsList.innerHTML = finalFindings.map(f => `
                    <div class="finding-item">
                        <span class="finding-badge ${f.severity}">${f.severity}</span>
                        <div class="finding-content">
                            <h4>${f.title}</h4>
                            <p>${f.description}</p>
                        </div>
                    </div>
                `).join("");
            }

            if (window.ThreatHawk) window.ThreatHawk.toast("URL analysis complete", "fa-shield-halved");
        } catch (err) {
            console.error("Invalid URL format:", err);
            if (window.ThreatHawk) window.ThreatHawk.toast("Please enter a valid URL", "fa-xmark");
            resetUI();
            urlInput.focus();
        } finally {
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = `<i class="fa-solid fa-magnifying-glass-chart" aria-hidden="true"></i> Analyze URL`;
        }
    }

    document.addEventListener("DOMContentLoaded", () => {
        if (!urlInput) return;
        analyzeBtn.addEventListener("click", analyzeURL);
        clearBtn.addEventListener("click", () => {
            urlInput.value = "";
            resetUI();
            urlInput.focus();
            if (window.ThreatHawk) window.ThreatHawk.toast("Cleared", "fa-rotate-left");
        });

        urlInput.addEventListener("keydown", e => {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                analyzeURL();
            }
        });

        resetUI();
    });
})();
