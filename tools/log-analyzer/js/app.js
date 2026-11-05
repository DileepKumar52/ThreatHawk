/**
 * ThreatHawk Security Log Analyzer
 * Multi-format parser, automated IOC extraction, attack pattern detection (SQLi, XSS, Path Traversal, Brute-Force), and incident reporting.
 */

"use strict";

(function () {
    const logFile = document.getElementById("logFile");
    const dropZone = document.getElementById("dropZone");
    const uploadBtn = document.getElementById("uploadBtn");
    const clearBtn = document.getElementById("clearBtn");
    const searchInput = document.getElementById("searchInput");
    const severityFilter = document.getElementById("severityFilter");
    const sampleBtn = document.getElementById("sampleBtn");

    const totalEvents = document.getElementById("totalEvents");
    const failedLogins = document.getElementById("failedLogins");
    const suspiciousIPs = document.getElementById("suspiciousIPs");
    const criticalAlerts = document.getElementById("criticalAlerts");

    const threatScore = document.getElementById("threatScore");
    const threatLevel = document.getElementById("threatLevel");
    const threatDial = document.getElementById("threatDial");

    const alertPanel = document.getElementById("alertPanel");
    const iocList = document.getElementById("iocList");
    const iocCount = document.getElementById("iocCount");
    const eventTable = document.getElementById("eventTable");
    const exportReportBtn = document.getElementById("exportReportBtn");

    let parsedEvents = [];
    let detectedIOCs = [];
    let currentIncidentSummary = "";

    // --------------------------------------------------------------------------
    // 1. SIGNATURE REGEXES & ATTACK RULES
    // --------------------------------------------------------------------------
    const RULES = [
        {
            name: "SQL Injection (SQLi)",
            severity: "critical",
            regex: /(\bUNION\b.{1,40}\bSELECT\b|'\s*OR\s*'?\d+'?\s*=\s*'?\d+|--|\bINFORMATION_SCHEMA\b|\bSLEEP\s*\(|\bDROP\s+TABLE\b)/i
        },
        {
            name: "Cross-Site Scripting (XSS)",
            severity: "critical",
            regex: /(<script[\s>]|javascript:|onerror\s*=|onload\s*=|alert\s*\(|<img\s+src=.*onerror)/i
        },
        {
            name: "Directory Traversal / LFI",
            severity: "critical",
            regex: /(\.\.\/|\.\.\\|\/etc\/passwd|c:\\windows\\system32|\/proc\/self\/environ|win\.ini)/i
        },
        {
            name: "Remote Command Execution / Web Shell",
            severity: "critical",
            regex: /(;\s*(cat|ls|whoami|id|wget|curl)\b|cmd\.exe|powershell(\.exe)?\s+(-enc|-w|-nop)|eval\s*\(base64_decode)/i
        },
        {
            name: "Reconnaissance Security Scanner",
            severity: "warning",
            regex: /\b(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|acunetix|nessus)\b/i
        },
        {
            name: "Failed Authentication",
            severity: "warning",
            regex: /(failed\s+password|authentication\s+failure|failed\s+login|invalid\s+user|access\s+denied|status:\s*401|status:\s*403)/i
        }
    ];

    function isPrivateIP(ip) {
        if (/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.0\.0\.1)/.test(ip)) return true;
        return false;
    }

    function extractIP(line) {
        const match = line.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/);
        return match ? match[0] : null;
    }

    function extractTimestamp(line) {
        const timeMatch = line.match(/\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(\.\d+)?Z?\b/) ||
                           line.match(/\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/) ||
                           line.match(/\b\d{2}:\d{2}:\d{2}\b/);
        return timeMatch ? timeMatch[0] : "—";
    }

    function collectIOCs(text) {
        const iocMap = new Map();

        const add = (type, val) => {
            const key = `${type}:${val}`;
            if (iocMap.has(key)) {
                iocMap.get(key).count++;
            } else {
                iocMap.set(key, { type, value: val, count: 1 });
            }
        };

        // Extract IPs
        const ips = text.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) || [];
        ips.forEach(ip => {
            if (!isPrivateIP(ip)) add("Public IP", ip);
            else add("Private IP", ip);
        });

        // Extract URLs
        const urls = text.match(/https?:\/\/[^\s"'<>]+/gi) || [];
        urls.forEach(u => add("URL", u));

        // Extract CVEs
        const cves = text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || [];
        cves.forEach(c => add("CVE", c.toUpperCase()));

        // Extract Hashes
        const sha256s = text.match(/\b[a-fA-F0-9]{64}\b/g) || [];
        sha256s.forEach(h => add("SHA-256", h));

        const md5s = text.match(/\b[a-fA-F0-9]{32}\b/g) || [];
        md5s.forEach(h => add("MD5", h));

        return Array.from(iocMap.values());
    }

    // --------------------------------------------------------------------------
    // 2. PARSING ENGINE
    // --------------------------------------------------------------------------
    function analyzeLogLines(lines) {
        parsedEvents = [];
        const ipAuthFailures = new Map();
        const alerts = [];
        let failedLoginCount = 0;
        let criticalAttackCount = 0;

        lines.forEach((line, index) => {
            const trimmed = line.trim();
            if (!trimmed) return;

            const ip = extractIP(trimmed);
            const time = extractTimestamp(trimmed);

            let matchedRule = null;
            for (const rule of RULES) {
                if (rule.regex.test(trimmed)) {
                    matchedRule = rule;
                    break;
                }
            }

            const severity = matchedRule ? matchedRule.severity : "info";
            const ruleName = matchedRule ? matchedRule.name : "Normal Activity";

            if (ruleName === "Failed Authentication") {
                failedLoginCount++;
                if (ip) {
                    ipAuthFailures.set(ip, (ipAuthFailures.get(ip) || 0) + 1);
                }
            } else if (severity === "critical") {
                criticalAttackCount++;
                alerts.push(`[${time}] ${ruleName} detected from ${ip || "client"}`);
            }

            parsedEvents.push({
                id: index + 1,
                time,
                ip: ip || "—",
                severity,
                rule: ruleName,
                raw: trimmed
            });
        });

        // Detect Brute-force attacks (5+ failed logins from same IP)
        let suspiciousIpCount = 0;
        ipAuthFailures.forEach((count, ip) => {
            if (count >= 5) {
                suspiciousIpCount++;
                alerts.unshift(`Brute-Force Warning: IP ${ip} has ${count} failed authentication attempts.`);
            }
        });

        // Calculate Overall Threat Score (0 - 100)
        let score = 0;
        if (criticalAttackCount > 0) score += Math.min(60, criticalAttackCount * 20);
        if (suspiciousIpCount > 0) score += Math.min(30, suspiciousIpCount * 10);
        if (failedLoginCount > 10) score += 15;
        if (lines.length > 0 && failedLoginCount / lines.length > 0.4) score += 15;
        score = Math.min(100, Math.max(score, criticalAttackCount > 0 ? 75 : (failedLoginCount > 0 ? 30 : 5)));

        // Extract all IOCs
        detectedIOCs = collectIOCs(lines.join("\n"));

        // Render UI
        updateDashboard(lines.length, failedLoginCount, suspiciousIpCount, criticalAttackCount, score, alerts);
        renderTable(parsedEvents);
        renderIOCs(detectedIOCs);
    }

    function updateDashboard(total, failed, suspIPs, criticals, score, alerts) {
        if (totalEvents) totalEvents.textContent = total;
        if (failedLogins) failedLogins.textContent = failed;
        if (suspiciousIPs) suspiciousIPs.textContent = suspIPs;
        if (criticalAlerts) criticalAlerts.textContent = criticals;

        if (threatScore) threatScore.textContent = score;
        let lvl = "Low Risk";
        let color = "var(--color-success-alt)";

        if (score >= 75) { lvl = "Critical Risk"; color = "var(--color-error)"; }
        else if (score >= 50) { lvl = "High Risk"; color = "#dc2626"; }
        else if (score >= 25) { lvl = "Medium Risk"; color = "var(--color-warning)"; }

        if (threatLevel) {
            threatLevel.textContent = lvl;
            threatLevel.style.color = color;
        }

        if (threatDial) {
            const circumference = 377;
            const offset = circumference - (score / 100) * circumference;
            threatDial.style.strokeDashoffset = offset;
            threatDial.style.stroke = color;
        }

        // Render Alerts
        if (alertPanel) {
            if (alerts.length === 0) {
                alertPanel.innerHTML = `
                    <div style="padding: 12px; text-align: center; color: var(--color-mute); font-size: 13px;">
                        <i class="fa-solid fa-circle-check" style="color:var(--color-success-alt); margin-right:4px;" aria-hidden="true"></i>
                        No critical alerts detected in the analyzed log stream.
                    </div>
                `;
            } else {
                alertPanel.innerHTML = alerts.slice(0, 8).map(a => `
                    <div class="alert-item ${a.includes('Warning') ? 'warning' : 'critical'}">
                        <i class="fa-solid fa-triangle-exclamation" style="margin-top:2px;" aria-hidden="true"></i>
                        <span>${a}</span>
                    </div>
                `).join("");
            }
        }
    }

    function renderTable(events) {
        if (!eventTable) return;
        if (events.length === 0) {
            eventTable.innerHTML = `<tr><td colspan="5" style="text-align: center; padding: 32px; color: var(--color-mute);">No log events loaded.</td></tr>`;
            return;
        }

        const filterSeverity = severityFilter ? severityFilter.value : "All";
        const query = searchInput ? searchInput.value.toLowerCase().trim() : "";

        const filtered = events.filter(e => {
            const matchesSev = filterSeverity === "All" || e.severity.toLowerCase() === filterSeverity.toLowerCase();
            const matchesQuery = !query || e.raw.toLowerCase().includes(query) || e.ip.toLowerCase().includes(query) || e.rule.toLowerCase().includes(query);
            return matchesSev && matchesQuery;
        });

        eventTable.innerHTML = filtered.slice(0, 150).map(e => `
            <tr>
                <td style="color: var(--color-mute);">${e.time}</td>
                <td><span class="severity-pill ${e.severity}">${e.severity}</span></td>
                <td><span style="font-weight: 500; color: var(--color-ink);">${e.rule}</span></td>
                <td><span style="color: ${isPrivateIP(e.ip) ? 'var(--color-mute)' : 'var(--color-ink)'};">${e.ip}</span></td>
                <td style="max-width: 380px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${e.raw}">${e.raw}</td>
            </tr>
        `).join("");
    }

    function renderIOCs(iocs) {
        if (!iocList) return;
        if (iocCount) iocCount.textContent = `${iocs.length} indicator${iocs.length === 1 ? '' : 's'}`;

        if (iocs.length === 0) {
            iocList.innerHTML = `<p style="color: var(--color-mute); font-size: 13px; padding: 12px;">No indicators of compromise detected.</p>`;
            return;
        }

        iocList.innerHTML = iocs.slice(0, 16).map(ioc => `
            <div class="ioc-item">
                <span class="ioc-type-pill">${ioc.type}</span>
                <span class="ioc-value" title="${ioc.value}">${ioc.value}</span>
                <button type="button" class="btn-app-ghost" style="height:24px; padding:0 6px; font-size:10px;" onclick="window.ThreatHawk.copyToClipboard('${ioc.value}', 'IOC copied')">
                    <i class="fa-regular fa-copy" aria-hidden="true"></i>
                </button>
            </div>
        `).join("");
    }

    // --------------------------------------------------------------------------
    // 3. EXPORTS & SAMPLES
    // --------------------------------------------------------------------------
    const SAMPLE_LOGS = `2026-11-05 10:14:02 185.143.223.11 - Failed password for invalid user admin from 185.143.223.11 port 42812 ssh2
2026-11-05 10:14:04 185.143.223.11 - Failed password for invalid user root from 185.143.223.11 port 42814 ssh2
2026-11-05 10:14:06 185.143.223.11 - Failed password for invalid user test from 185.143.223.11 port 42816 ssh2
2026-11-05 10:14:08 185.143.223.11 - Failed password for invalid user ubuntu from 185.143.223.11 port 42818 ssh2
2026-11-05 10:14:10 185.143.223.11 - Failed password for invalid user oracle from 185.143.223.11 port 42820 ssh2
2026-11-05 10:15:30 192.168.1.45 - GET /index.php?id=1' UNION SELECT 1,username,password FROM users-- 200
2026-11-05 10:16:12 45.227.255.206 - GET /view.php?page=../../../../etc/passwd HTTP/1.1 200
2026-11-05 10:17:45 103.88.12.45 - POST /search.php?q=<script>alert('xss')</script> HTTP/1.1 200
2026-11-05 10:18:22 10.0.0.5 - User-Agent: sqlmap/1.6#stable (https://sqlmap.org) probing endpoint
2026-11-05 10:20:01 192.168.1.100 - Accepted publickey for dileep from 192.168.1.100 port 51234 ssh2`;

    function loadSample() {
        analyzeLogLines(SAMPLE_LOGS.split("\n"));
        if (window.ThreatHawk) window.ThreatHawk.toast("Loaded sample security log stream", "fa-file-lines");
    }

    // --------------------------------------------------------------------------
    // 4. INITIALIZATION
    // --------------------------------------------------------------------------
    document.addEventListener("DOMContentLoaded", () => {
        if (!logFile) return;

        // Upload button trigger
        if (uploadBtn) {
            uploadBtn.addEventListener("click", () => {
                if (!logFile.files.length) {
                    if (window.ThreatHawk) window.ThreatHawk.toast("Select a log file first", "fa-triangle-exclamation");
                    logFile.click();
                    return;
                }
                const file = logFile.files[0];
                file.text().then(content => {
                    analyzeLogLines(content.split(/\r?\n/));
                    if (window.ThreatHawk) window.ThreatHawk.toast(`Analyzed ${file.name}`, "fa-shield-halved");
                }).catch(err => {
                    console.error("File reading error:", err);
                    if (window.ThreatHawk) window.ThreatHawk.toast("Could not read log file", "fa-xmark");
                });
            });
        }

        // File change
        logFile.addEventListener("change", () => {
            if (logFile.files.length > 0) {
                const f = logFile.files[0];
                const label = document.getElementById("logFileLabel");
                if (label) label.textContent = `${f.name} (${(f.size / 1024).toFixed(1)} KB)`;
                uploadBtn.click();
            }
        });

        // Sample button
        if (sampleBtn) {
            sampleBtn.addEventListener("click", loadSample);
        }

        // Search & Filter
        if (searchInput) searchInput.addEventListener("input", () => renderTable(parsedEvents));
        if (severityFilter) severityFilter.addEventListener("change", () => renderTable(parsedEvents));

        // Clear button
        if (clearBtn) {
            clearBtn.addEventListener("click", () => {
                parsedEvents = [];
                detectedIOCs = [];
                analyzeLogLines([]);
                if (window.ThreatHawk) window.ThreatHawk.toast("Log workspace cleared", "fa-rotate-left");
            });
        }

        // Export Report
        if (exportReportBtn) {
            exportReportBtn.addEventListener("click", () => {
                if (parsedEvents.length === 0) return;
                const header = "ID,Timestamp,Severity,RuleName,IP,RawEvent\n";
                const rows = parsedEvents.map(e => `"${e.id}","${e.time}","${e.severity}","${e.rule}","${e.ip}","${e.raw.replace(/"/g, '""')}"`).join("\n");
                const blob = new Blob([header + rows], { type: "text/csv" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = "threathawk-incident-report.csv";
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            });
        }

        // Drag & drop
        if (dropZone) {
            dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.classList.add("is-dragging"); });
            dropZone.addEventListener("dragleave", () => dropZone.classList.remove("is-dragging"));
            dropZone.addEventListener("drop", e => {
                e.preventDefault();
                dropZone.classList.remove("is-dragging");
                if (e.dataTransfer.files.length > 0) {
                    logFile.files = e.dataTransfer.files;
                    const changeEvent = new Event("change");
                    logFile.dispatchEvent(changeEvent);
                }
            });
        }

        // Initialize empty state
        analyzeLogLines([]);
    });
})();
