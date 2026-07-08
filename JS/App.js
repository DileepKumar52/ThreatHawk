const logFile = document.getElementById("logFile");
const uploadBtn = document.getElementById("uploadBtn");

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

uploadBtn.addEventListener("click", function () {
    const file = logFile.files[0];

    if (!file) {
        alert("Please select a log file first.");
        return;
    }

    const reader = new FileReader();

    reader.onload = function (event) {
        const content = event.target.result;

        const logLines = content
            .split("\n")
            .map(line => line.trim())
            .filter(line => line.length > 0);

        analyzeLogs(logLines);
    };

    reader.readAsText(file);
});

function extractIP(line) {
    const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
    const match = line.match(ipPattern);
    return match ? match[0] : "-";
}

function extractTime(line) {
    const timePattern = /\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}/;
    const match = line.match(timePattern);
    return match ? match[0] : "-";
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

    const ipCounts = {};
    const failedLoginCounts = {};
    const alerts = [];
    const detectedIOCs = new Set();
    let score = 0;

    eventTable.innerHTML = "";

    logLines.forEach(line => {
        const ip = extractIP(line);
        const time = extractTime(line);

        if (knownMaliciousIPs.includes(ip)) {
            detectedIOCs.add(ip);
            score += 10;
        }

        let severity = "Info";

        if (ip !== "-") {
            ipCounts[ip] = (ipCounts[ip] || 0) + 1;
        }

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
    score += criticalCount * 20;
    score += suspiciousCount * 10;

    if (score > 100) {
        score = 100;
    }

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

    if (detectedIOCs.size === 0) {
        iocList.innerHTML = "No IOCs detected.";
    } 
    else {
        iocList.innerHTML = Array.from(detectedIOCs)
            .map(ip => `<div class="ioc-item">🚨 Known malicious IP detected: ${ip}</div>`)
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
    ${detectedIOCs.size === 0 ? "None" : Array.from(detectedIOCs).join(", ")}

    Summary:
    ${criticalCount > 0 ? "Possible brute-force activity detected." : "No critical brute-force activity detected."}
    ${detectedIOCs.size > 0 ? "Known malicious IP addresses were found in the logs." : "No known malicious IPs were found."}
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

    incidentSummary.innerHTML = `
    <p>
    <strong>Threat Level:</strong>
    <span class="${threatClass}">
    ${threatLevel}
    </span>
    </p>

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

    recommendations.innerHTML =
        `<p><strong>Recommendation:</strong>
         ${recommendationText}</p>`;

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