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
    const alerts = [];

    eventTable.innerHTML = "";

    logLines.forEach(line => {
        const ip = extractIP(line);
        const time = extractTime(line);

        let severity = "Info";

        if (ip !== "-") {
            ipCounts[ip] = (ipCounts[ip] || 0) + 1;
        }

        if (isFailedLogin(line)) {
            failedCount++;
            severity = "Warning";
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
            <td>${ip}</td>
        `;

        eventTable.appendChild(row);
    });

    Object.keys(ipCounts).forEach(ip => {
        if (ipCounts[ip] >= 5) {
            alerts.push(`⚠ Suspicious activity from ${ip} (${ipCounts[ip]} events)`);
        }
    });

    const suspiciousCount = Object.values(ipCounts).filter(count => count >= 5).length;

    if (failedCount >= 5) {
        criticalCount++;
        alerts.push(`🚨 Possible brute force activity detected: ${failedCount} failed logins`);
    }

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