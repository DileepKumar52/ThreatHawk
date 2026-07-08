const logFile = document.getElementById("logFile");
const uploadBtn = document.getElementById("uploadBtn");
const loadingMessage = document.getElementById("loadingMessage");

const totalEvents = document.getElementById("totalEvents");
const criticalAlerts = document.getElementById("criticalAlerts");
const suspiciousIPs = document.getElementById("suspiciousIPs");
const failedLogins = document.getElementById("failedLogins");

const eventTable = document.getElementById("eventTable");
const alertPanel = document.getElementById("alertPanel");

const searchInput = document.getElementById("searchInput");
const severityFilter = document.getElementById("severityFilter");
let eventChart;

const threatScore = document.getElementById("threatScore");
const iocList = document.getElementById("iocList");

const incidentSummary = document.getElementById("incidentSummary");
const exportReportBtn = document.getElementById("exportReportBtn");

let latestReport = "";

const recommendations = document.getElementById("recommendations");

const knownMaliciousIPs = [
    "45.227.255.206",
    "185.143.223.11",
    "103.88.12.45"
];

let detectedIOCs = [];

severityFilter.addEventListener("change", filterTable);
searchInput.addEventListener("input", filterTable);

logFile.addEventListener("change", function () {
    const file = logFile.files[0];
    const fileName = document.getElementById("fileName");

    fileName.textContent = file ? file.name : "No file selected";
});

function filterTable() {
    const searchText = searchInput.value.toLowerCase();
    const selectedSeverity = severityFilter.value;

    const rows = document.querySelectorAll("#eventTable tr");

    rows.forEach(row => {
        const rowText = row.textContent.toLowerCase();
        const severity =
            row.cells[1].textContent.trim();

        const matchesSearch =
            rowText.includes(searchText);

        const matchesSeverity =
            selectedSeverity === "All" ||
            severity === selectedSeverity;

        if (matchesSearch && matchesSeverity) {
            row.style.display = "";
        } else {
            row.style.display = "none";
        }
    });
}

uploadBtn.addEventListener("click", function () 
    {
        const file = logFile.files[0];

        if (!file) {
            alert("Please select a log file first.");
            return;
        }

        uploadBtn.disabled = true;
        uploadBtn.textContent = "Analyzing...";
        loadingMessage.textContent = "Processing log file, please wait...";

        const reader = new FileReader();

        reader.onload = function (event) {
            const content = event.target.result;

            const logLines = content
            .split("\n")
            .map(line => line.trim())
            .filter(line => line.length > 0);

            setTimeout(() => {
                try {
                    analyzeLogs(logLines);
                    loadingMessage.textContent = "Analysis complete.";

                    setTimeout(() => {
                    loadingMessage.textContent = "";
                    }, 2500);
                } catch (error) {
                    console.error(error);
                    loadingMessage.textContent = "Something went wrong while analyzing the log.";
                } finally {
                    uploadBtn.disabled = false;
                    uploadBtn.textContent = "Analyze Log";
                }
            }, 100);
        };

        reader.readAsText(file);
    }
);

function extractIP(line) {
    const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
    const match = line.match(ipPattern);
    return match ? match[0] : "-";
}

function extractTime(line) {
    const timePattern = /\b\d{2}:\d{2}:\d{2}\b/;
    const match = line.match(timePattern);
    return match ? match[0] : "-";
}

function extractURLs(line) {
    return line.match(/https?:\/\/[^\s"'<>]+/gi) || [];
}

function extractEmails(line) {
    return line.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) || [];
}

function extractDomains(line) {
    return line.match(/\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g) || [];
}

function extractMD5(line) {
    return line.match(/\b[a-fA-F0-9]{32}\b/g) || [];
}

function extractSHA1(line) {
    return line.match(/\b[a-fA-F0-9]{40}\b/g) || [];
}

function extractSHA256(line) {
    return line.match(/\b[a-fA-F0-9]{64}\b/g) || [];
}

function extractCVEs(line) {
    return line.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || [];
}

function addIOC(type, value) {
    const existingIOC = detectedIOCs.find(
        ioc => ioc.type === type && ioc.value === value
    );

    if (existingIOC) {
        existingIOC.count++;
    } else {
        detectedIOCs.push({
            type: type,
            value: value,
            count: 1
        });
    }
}

function isFailedLogin(line) {
    const lowerLine = line.toLowerCase();

    return (
        lowerLine.includes("failed login") ||
        lowerLine.includes("authentication failure") ||
        lowerLine.includes("invalid password") ||
        lowerLine.includes("failed password")
    );
}

function analyzeLogs(logLines) {
    let failedCount = 0;
    let criticalCount = 0;
    let infoCount = 0;
    let warningCount = 0;

    const failedLoginCounts = {};
    const alerts = [];

    let score = 0;

    detectedIOCs = [];

    eventTable.innerHTML = "";

    logLines.forEach(line => {
        const ip = extractIP(line);
        const time = extractTime(line);

        extractURLs(line).forEach(url => {
            addIOC("URL", url);
        });

        extractEmails(line).forEach(email => {
            addIOC("Email", email);
        });

        extractDomains(line).forEach(domain => {
            addIOC("Domain", domain);
        });

        extractMD5(line).forEach(hash => {
            addIOC("MD5", hash);
        });

        extractSHA1(line).forEach(hash => {
            addIOC("SHA1", hash);
        });

        extractSHA256(line).forEach(hash => {
            addIOC("SHA256", hash);
        });

        extractCVEs(line).forEach(cve => {
            addIOC("CVE", cve.toUpperCase());
        });

        if (knownMaliciousIPs.includes(ip)) {
            addIOC("IP", ip);
        }

        let severity = "Info";


        if (isFailedLogin(line)) {
            failedCount++;
            severity = "Warning";
            if (ip !== "-") {
                failedLoginCounts[ip] = (failedLoginCounts[ip] || 0) + 1;
            }
        }
        if (severity === "Warning") {
            warningCount++;
        } 
        else {
            infoCount++;
        }       

        const row = document.createElement("tr");

        let rowClass = "";

        if (severity === "Warning") {
        rowClass = "warning-row";
        }

        row.className = rowClass;

        row.innerHTML = `
            <td>${time}</td>
            <td class="${severity === "Warning" ? "warning-text" : "info-text"}">${severity}</td>
            <td>${line}</td>
            <td class="${knownMaliciousIPs.includes(ip) ? "malicious-ip" : ""}">${ip}</td>
        `;

        eventTable.appendChild(row);
    });

    Object.keys(failedLoginCounts).forEach(ip => {
        if (failedLoginCounts[ip] >= 10) {
            alerts.push(`⚠ Suspicious failed logins from ${ip} (${failedLoginCounts[ip]} attempts)`);
        }
    });

    const suspiciousCount = Object.values(failedLoginCounts).filter(count => count >= 10).length;

    Object.keys(failedLoginCounts).forEach(ip => {
        if (failedLoginCounts[ip] >= 20) {
            criticalCount++;

            alerts.push(
                `🚨 Brute force attack detected from ${ip} (${failedLoginCounts[ip]} failed attempts)`
            );
        }
    });

    totalEvents.textContent = logLines.length;
    failedLogins.textContent = failedCount;
    suspiciousIPs.textContent = suspiciousCount;
    criticalAlerts.textContent = criticalCount;

    updateChart(infoCount, warningCount);

    if (alerts.length === 0) {
        alertPanel.innerHTML = "No alerts yet.";
    } else {
        alertPanel.innerHTML = alerts
            .map(alert => `<div class="alert-item">${alert}</div>`)
            .join("");
    }
    
    score = 0;

    const failedLoginRatio = logLines.length > 0 ? failedCount / logLines.length : 0;
    const iocCount = detectedIOCs.length;

    if (failedCount >= 50) score += 15;
    if (failedCount >= 200) score += 15;
    if (failedCount >= 1000) score += 20;

    if (failedLoginRatio >= 0.25) score += 15;
    if (failedLoginRatio >= 0.50) score += 15;

    if (suspiciousCount >= 2) score += 10;
    if (suspiciousCount >= 5) score += 15;

    if (criticalCount >= 1) score += 15;
    if (criticalCount >= 3) score += 15;

    if (iocCount >= 1) score += 10;
    if (iocCount >= 5) score += 10;

    score = Math.min(score, 100);

    let threatLevel = "Low";

    if (score >= 80) {
        threatLevel = "Critical";
    }
    else if (score >= 50) {
        threatLevel = "High";
    }
    else if (score >= 20) {
        threatLevel = "Medium";
    }

    threatScore.innerHTML = `
        ${score}
        <div class="threat-level">${threatLevel}</div>
    `;

    if (detectedIOCs.length === 0) {
        iocList.innerHTML = "No IOCs detected.";
    } 
    else {
        iocList.innerHTML = detectedIOCs
        .sort((a, b) => b.count - a.count)
            .map(ioc => `
                <div class="ioc-item">
                    <span>🚨 ${ioc.type}: ${ioc.value}</span>
                    <span class="ioc-badge">${ioc.count} Hits</span>
                </div>
            `)
        .join("");
    }

    latestReport = `
    ThreatHawk Incident Report
    --------------------------

    Threat Score: ${score}
    Threat Level: ${threatLevel}

    Total Events: ${logLines.length}
    Failed Logins: ${failedCount}
    Suspicious IPs: ${suspiciousCount}
    Critical Alerts: ${criticalCount}

    Detected IOCs:
    ${detectedIOCs.length === 0 ? "None" : detectedIOCs.map(ioc => `${ioc.type}: ${ioc.value}`).join(", ")}

    Summary:
    ${criticalCount > 0 ? "Possible brute-force activity detected." : "No critical brute-force activity detected."}
    ${detectedIOCs.length > 0 ? "Indicators of compromise were found in the logs." : "No IOCs were found."}
    `;

    let threatClass = "threat-low";

    if (threatLevel === "Critical") {
        threatClass = "threat-critical";
    }
    else if (threatLevel === "High") {
        threatClass = "threat-high";
    }
    else if (threatLevel === "Medium") {
        threatClass = "threat-medium";
    }

    const topIOC = detectedIOCs.length > 0
    ? detectedIOCs.sort((a, b) => b.count - a.count)[0]
    : null;

    let summaryText = "";

    if (score >= 80) {
        summaryText = `
            <p><strong>Threat Level:</strong> <span class="threat-critical">Critical</span></p>
            <p>
                ThreatHawk detected a high-risk security incident involving 
                <strong>${failedCount}</strong> failed login attempts across 
                <strong>${logLines.length}</strong> log events.
            </p>
            <p>
                <strong>${Object.keys(failedLoginCounts).length}</strong> suspicious source IP(s) were observed.
                ${topIOC ? `The most active IOC was <strong>${topIOC.value}</strong> with <strong>${topIOC.count}</strong> hits.` : ""}
            </p>
            <p>
                This activity strongly suggests a brute-force or credential attack pattern.
                Immediate investigation and blocking of suspicious IPs is recommended.
            </p>
        `;
    } else if (score >= 50) {
        summaryText = `
            <p><strong>Threat Level:</strong> <span class="threat-high">High</span></p>
            <p>
                ThreatHawk detected suspicious authentication activity with 
                <strong>${failedCount}</strong> failed login attempts.
            </p>
            <p>
                Several indicators require review, but the activity does not yet show the same intensity as a critical incident.
            </p>
        `;
    } else if (score >= 25) {
        summaryText = `
            <p><strong>Threat Level:</strong> <span class="threat-medium">Medium</span></p>
            <p>
                ThreatHawk found moderate suspicious activity in the uploaded logs.
                Some failed login patterns or indicators should be reviewed.
            </p>
        `;
    } else {
        summaryText = `
            <p><strong>Threat Level:</strong> <span class="threat-low">Low</span></p>
            <p>
                No major attack pattern was detected. The log contains limited suspicious activity.
            </p>
        `;
    }

    incidentSummary.innerHTML = `
        ${summaryText}

        <p><strong>Threat Score:</strong> ${score}</p>
        <p><strong>Total Events:</strong> ${logLines.length}</p>
        <p><strong>Failed Logins:</strong> ${failedCount}</p>
        <p><strong>Suspicious IPs:</strong> ${suspiciousCount}</p>
        <p><strong>Critical Alerts:</strong> ${criticalCount}</p>
    `;

    let recommendationText = "";

    if (threatLevel === "Critical") {
        recommendationText =
            "Immediately block malicious IPs and investigate compromised accounts.";
    }
    else if (threatLevel === "High") {
        recommendationText =
            "Review authentication logs and monitor affected systems.";
    }
    else if (threatLevel === "Medium") {
        recommendationText =
            "Increase monitoring and verify suspicious activities.";
    }
    else {
        recommendationText =
            "No immediate action required.";
    }

    recommendations.innerHTML = `
        <h3>Recommended Actions</h3>
        <ul class="recommendation-list">
            <li>✔ ${recommendationText}</li>
            <li>✔ Enable Multi-Factor Authentication (MFA).</li>
            <li>✔ Review successful logins after repeated failures.</li>
            <li>✔ Continue monitoring suspicious source IPs.</li>
        </ul>
    `;

}

function updateChart(infoCount, warningCount) {
    const ctx = document.getElementById("eventChart");

    if (eventChart) {
        eventChart.destroy();
    }

    eventChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels: ["Info", "Warning"],
            datasets: [{
                data: [infoCount, warningCount],
                backgroundColor: [
                    "#00d4ff",
                    "#ffb347"
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    labels: {
                        color: "#ffffff"
                    }
                }
            }
        }
    });
}

exportReportBtn.addEventListener("click", function () {
    if (!latestReport) {
        alert("Please analyze a log file first.");
        return;
    }

    const blob = new Blob([latestReport], {
        type: "text/plain"
    });

    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "threathawk-incident-report.txt";
    link.click();

    URL.revokeObjectURL(link.href);
});