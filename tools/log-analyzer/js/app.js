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

const fileName = document.getElementById("fileName");
const clearBtn = document.getElementById("clearBtn");

const dropZone = document.getElementById("dropZone");
const selectedFilePanel =
    document.getElementById("selectedFilePanel");

const processingPanel =
    document.getElementById("processingPanel");

const processingStage =
    document.getElementById("processingStage");

const processingPercent =
    document.getElementById("processingPercent");

const processingFill =
    document.getElementById("processingFill");

const threatSphere =
    document.getElementById("threatSphere");

const threatLevelElement =
    document.getElementById("threatLevel");

const attackTimeline =
    document.getElementById("attackTimeline");

const iocCountBadge =
    document.getElementById("iocCount");

const eventCountBadge =
    document.getElementById("eventCountBadge");

const themeToggle =
    document.getElementById("themeToggle");

const toast =
    document.getElementById("toast");

const toastMessage =
    document.getElementById("toastMessage");

let toastTimer = null;

const knownMaliciousIPs = [
    "45.227.255.206",
    "185.143.223.11",
    "103.88.12.45"
];

let detectedIOCs = [];

function showToast(
    message,
    iconClass = "fa-check"
) {
    if (!toast || !toastMessage) {
        return;
    }

    toastMessage.textContent = message;

    const icon = toast.querySelector("i");

    if (icon) {
        icon.className =
            `fa-solid ${iconClass}`;
    }

    toast.classList.add("show");

    clearTimeout(toastTimer);

    toastTimer = setTimeout(() => {
        toast.classList.remove("show");
    }, 2300);
}

function updateThemeButton(lightModeEnabled) {
    if (!themeToggle) {
        return;
    }

    const icon =
        themeToggle.querySelector("i");

    const text =
        themeToggle.querySelector("span");

    if (icon) {
        icon.className =
            lightModeEnabled
                ? "fa-regular fa-moon"
                : "fa-regular fa-sun";
    }

    if (text) {
        text.textContent =
            lightModeEnabled
                ? "Dark Mode"
                : "Light Mode";
    }

    themeToggle.setAttribute(
        "aria-label",
        lightModeEnabled
            ? "Switch to dark mode"
            : "Switch to light mode"
    );
}

function applySavedTheme() {
    const savedTheme =
        localStorage.getItem(
            "threathawk-log-theme"
        );

    const lightModeEnabled =
        savedTheme === "light";

    document.body.classList.toggle(
        "light-mode",
        lightModeEnabled
    );

    updateThemeButton(lightModeEnabled);
}

function toggleTheme() {
    const lightModeEnabled =
        !document.body.classList.contains(
            "light-mode"
        );

    document.body.classList.toggle(
        "light-mode",
        lightModeEnabled
    );

    localStorage.setItem(
        "threathawk-log-theme",
        lightModeEnabled
            ? "light"
            : "dark"
    );

    updateThemeButton(lightModeEnabled);
}

function setProcessingProgress(
    percent,
    stage,
    message = ""
) {
    const safePercent =
        Math.max(
            0,
            Math.min(percent, 100)
        );

    processingPercent.textContent =
        `${safePercent}%`;

    processingFill.style.width =
        `${safePercent}%`;

    processingStage.textContent =
        stage;

    loadingMessage.textContent =
        message;
}

function animateNumber(
    element,
    targetValue,
    duration = 500
) {
    const startValue =
        Number.parseInt(
            element.textContent,
            10
        ) || 0;

    const difference =
        targetValue - startValue;

    const startTime =
        performance.now();

    function update(currentTime) {
        const progress =
            Math.min(
                (currentTime - startTime) /
                duration,
                1
            );

        const eased =
            1 - Math.pow(1 - progress, 3);

        element.textContent =
            Math.round(
                startValue +
                difference * eased
            );

        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            element.textContent =
                targetValue;

            element.classList.add(
                "updated"
            );
        }
    }

    requestAnimationFrame(update);
}

function updateThreatSphere(
    score,
    threatLevel
) {
    threatSphere.classList.remove(
        "threat-low-state",
        "threat-medium-state",
        "threat-high-state",
        "threat-critical-state"
    );

    const stateClass =
        threatLevel === "Critical"
            ? "threat-critical-state"
            : threatLevel === "High"
                ? "threat-high-state"
                : threatLevel === "Medium"
                    ? "threat-medium-state"
                    : "threat-low-state";

    threatSphere.classList.add(
        stateClass
    );

    threatLevelElement.textContent =
        `${threatLevel} Risk`;

    animateNumber(
        threatScore,
        score,
        650
    );
}

function updateSelectedFile(file) {
    if (!file) {
        fileName.textContent =
            "No file selected";

        selectedFilePanel.classList.add(
            "empty-file"
        );

        return;
    }

    fileName.textContent =
        `${file.name} · ${formatFileSize(file.size)}`;

    selectedFilePanel.classList.remove(
        "empty-file"
    );
}

function formatFileSize(bytes) {
    if (!bytes) {
        return "0 B";
    }

    const units = [
        "B",
        "KB",
        "MB",
        "GB"
    ];

    const index =
        Math.min(
            Math.floor(
                Math.log(bytes) /
                Math.log(1024)
            ),
            units.length - 1
        );

    const value =
        bytes / Math.pow(1024, index);

    return `${value.toFixed(
        index === 0 ? 0 : 1
    )} ${units[index]}`;
}

severityFilter.addEventListener("change", filterTable);
searchInput.addEventListener("input", filterTable);

logFile.addEventListener(
    "change",
    () => {
        updateSelectedFile(
            logFile.files[0]
        );
    }
);

dropZone.addEventListener(
    "click",
    () => {
        logFile.click();
    }
);

dropZone.addEventListener(
    "keydown",
    event => {
        if (
            event.key === "Enter" ||
            event.key === " "
        ) {
            event.preventDefault();
            logFile.click();
        }
    }
);

[
    "dragenter",
    "dragover"
].forEach(eventName => {
    dropZone.addEventListener(
        eventName,
        event => {
            event.preventDefault();

            dropZone.classList.add(
                "is-dragging"
            );
        }
    );
});

[
    "dragleave",
    "drop"
].forEach(eventName => {
    dropZone.addEventListener(
        eventName,
        event => {
            event.preventDefault();

            dropZone.classList.remove(
                "is-dragging"
            );
        }
    );
});

dropZone.addEventListener(
    "drop",
    event => {
        const files =
            event.dataTransfer.files;

        if (!files.length) {
            return;
        }

        const file = files[0];

        const extension =
            file.name
                .split(".")
                .pop()
                .toLowerCase();

        if (
            !["txt", "log", "csv"]
                .includes(extension)
        ) {
            showToast(
                "Only TXT, LOG and CSV files are supported",
                "fa-triangle-exclamation"
            );

            return;
        }

        const transfer =
            new DataTransfer();

        transfer.items.add(file);

        logFile.files =
            transfer.files;

        updateSelectedFile(file);
    }
);

function filterTable() {
    const searchText =
        searchInput.value
            .toLowerCase();

    const selectedSeverity =
        severityFilter.value;

    const rows =
        document.querySelectorAll(
            "#eventTable tr"
        );

    rows.forEach(row => {
        if (
            row.classList.contains(
                "empty-row"
            ) ||
            row.cells.length < 2
        ) {
            return;
        }

        const rowText =
            row.textContent
                .toLowerCase();

        const severity =
            row.cells[1]
                .textContent
                .trim();

        const matchesSearch =
            rowText.includes(
                searchText
            );

        const matchesSeverity =
            selectedSeverity === "All" ||
            severity ===
                selectedSeverity;

        row.style.display =
            matchesSearch &&
            matchesSeverity
                ? ""
                : "none";
    });
}

uploadBtn.addEventListener(
    "click",
    () => {
        const file =
            logFile.files[0];

        if (!file) {
            showToast(
                "Please select a log file first",
                "fa-circle-exclamation"
            );

            return;
        }

        uploadBtn.disabled = true;

        uploadBtn.innerHTML = `
            <i class="fa-solid fa-spinner fa-spin"></i>
            Analyzing...
        `;

        dropZone.classList.add(
            "is-processing"
        );

        setProcessingProgress(
            10,
            "Reading log file",
            "Loading file contents..."
        );

        const reader =
            new FileReader();

        reader.onload =
            function (event) {
                const content =
                    event.target.result;

                setProcessingProgress(
                    30,
                    "Parsing events",
                    "Normalizing log entries..."
                );

                const logLines =
                    content
                        .split(/\r?\n/)
                        .map(line =>
                            line.trim()
                        )
                        .filter(Boolean);

                setTimeout(() => {
                    setProcessingProgress(
                        55,
                        "Extracting indicators",
                        "Searching for IPs, URLs, hashes and CVEs..."
                    );
                }, 180);

                setTimeout(() => {
                    setProcessingProgress(
                        75,
                        "Detecting attack patterns",
                        "Checking authentication failures and brute-force activity..."
                    );
                }, 360);

                setTimeout(() => {
                    try {
                        analyzeLogs(
                            logLines
                        );

                        setProcessingProgress(
                            100,
                            "Analysis complete",
                            "Threat analysis completed successfully."
                        );

                        showToast(
                            "Log analysis completed",
                            "fa-shield-halved"
                        );
                    } catch (error) {
                        console.error(error);

                        setProcessingProgress(
                            0,
                            "Analysis failed",
                            "Something went wrong while analyzing the log."
                        );

                        showToast(
                            "Log analysis failed",
                            "fa-xmark"
                        );
                    } finally {
                        uploadBtn.disabled =
                            false;

                        uploadBtn.innerHTML = `
                            <i class="fa-solid fa-magnifying-glass-chart"></i>
                            Analyze Log
                        `;

                        dropZone.classList.remove(
                            "is-processing"
                        );
                    }
                }, 600);
            };

        reader.onerror =
            function () {
                setProcessingProgress(
                    0,
                    "File read failed",
                    "The selected file could not be read."
                );

                uploadBtn.disabled = false;

                uploadBtn.innerHTML = `
                    <i class="fa-solid fa-magnifying-glass-chart"></i>
                    Analyze Log
                `;

                dropZone.classList.remove(
                    "is-processing"
                );

                showToast(
                    "The selected file could not be read",
                    "fa-xmark"
                );
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
    const timelineEvents = [];

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
        
        if (severity === "Warning") {
            timelineEvents.push({
                time,
                title: "Failed authentication",
                description: line
            });
        }

        if (
            ip !== "-" &&
            knownMaliciousIPs.includes(ip)
        ) {
            timelineEvents.push({
                time,
                title: "Known malicious IP detected",
                description:
                    `${ip} matched the local malicious-IP list.`
            });
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

    animateNumber(
        totalEvents,
        logLines.length
    );

    animateNumber(
        failedLogins,
        failedCount
    );

    animateNumber(
        suspiciousIPs,
        suspiciousCount
    );

    animateNumber(
        criticalAlerts,
        criticalCount
    );

    eventCountBadge.textContent =
        `${logLines.length} ${
            logLines.length === 1
                ? "event"
                : "events"
        }`;

    updateChart(infoCount, warningCount);

    if (alerts.length === 0) {
        alertPanel.innerHTML = `
            <div class="empty-state">

                <div class="empty-state-icon">
                    <i class="fa-solid fa-shield-check"></i>
                </div>

                <strong>
                    No critical alerts detected
                </strong>

                <p>
                    The analyzed log did not produce
                    any high-priority alerts.
                </p>

            </div>
        `;
    } else {
        alertPanel.innerHTML =
            alerts
                .map(alert => `
                    <div class="alert-item">
                        <span>${alert}</span>
                    </div>
                `)
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

    updateThreatSphere(
        score,
        threatLevel
    );

    iocCountBadge.textContent =
    `${detectedIOCs.length} ${
        detectedIOCs.length === 1
            ? "indicator"
            : "indicators"
    }`;

    if (detectedIOCs.length === 0) {
        iocList.innerHTML = `
            <div class="empty-state">

                <div class="empty-state-icon">
                    <i class="fa-solid fa-crosshairs"></i>
                </div>

                <strong>
                    No IOCs detected
                </strong>

                <p>
                    No URLs, domains, hashes,
                    CVEs or malicious IP matches
                    were extracted.
                </p>

            </div>
        `;
    } else {
        iocList.innerHTML =
            detectedIOCs
                .sort(
                    (first, second) =>
                        second.count -
                        first.count
                )
                .map(ioc => `
                    <div class="ioc-item">

                        <div>
                            <strong>
                                ${ioc.type}: ${ioc.value}
                            </strong>

                            <p>
                                Extracted indicator of compromise
                            </p>
                        </div>

                        <span class="ioc-badge">
                            ${ioc.count} ${
                                ioc.count === 1
                                    ? "Hit"
                                    : "Hits"
                            }
                        </span>

                    </div>
                `)
                .join("");
    }

    if (timelineEvents.length === 0) {
        attackTimeline.innerHTML = `
            <div class="timeline-empty-state">

                <div class="empty-state-icon">
                    <i class="fa-solid fa-clock-rotate-left"></i>
                </div>

                <strong>
                    No notable timeline events
                </strong>

                <p>
                    No authentication failures or known
                    malicious-IP events were identified.
                </p>

            </div>
        `;
    } else {
        attackTimeline.innerHTML =
            timelineEvents
                .slice(0, 50)
                .map(event => `
                    <article class="timeline-item">

                        <div class="timeline-item-header">

                            <strong>
                                ${event.title}
                            </strong>

                            <time>
                                ${event.time}
                            </time>

                        </div>

                        <p>
                            ${event.description}
                        </p>

                    </article>
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
            <li>${recommendationText}</li>
            <li>Enable Multi-Factor Authentication (MFA).</li>
            <li>Review successful logins after repeated failures.</li>
            <li>Continue monitoring suspicious source IPs.</li>
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
                    "#64748b",
                    "#ff8c1a"
                ],
                borderColor: [
                    "#94a3b8",
                    "#ffab47"
                ],
                borderWidth: 1
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
        showToast(
            "Analyze a log file before exporting",
            "fa-circle-exclamation"
        );

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
    
    showToast(
        "Incident report exported",
        "fa-file-export"
    );
});

clearBtn.addEventListener(
    "click",
    () => {
        logFile.value = "";

        updateSelectedFile(null);

        totalEvents.textContent = "0";
        criticalAlerts.textContent = "0";
        suspiciousIPs.textContent = "0";
        failedLogins.textContent = "0";

        updateThreatSphere(
            0,
            "Low"
        );

        eventCountBadge.textContent =
            "0 events";

        iocCountBadge.textContent =
            "0 indicators";

        eventTable.innerHTML = `
            <tr class="empty-row">

                <td colspan="4">

                    <div class="table-empty-state">

                        <div class="empty-state-icon">
                            <i class="fa-solid fa-table-list"></i>
                        </div>

                        <strong>
                            No events available
                        </strong>

                        <p>
                            Upload and analyze a log file
                            to populate this table.
                        </p>

                    </div>

                </td>

            </tr>
        `;

        alertPanel.innerHTML = `
            <div class="empty-state">

                <div class="empty-state-icon">
                    <i class="fa-solid fa-bell"></i>
                </div>

                <strong>
                    No alerts detected
                </strong>

                <p>
                    Upload and analyze a log file
                    to view security alerts.
                </p>

            </div>
        `;

        attackTimeline.innerHTML = `
            <div class="timeline-empty-state">

                <div class="empty-state-icon">
                    <i class="fa-solid fa-clock-rotate-left"></i>
                </div>

                <strong>
                    No timeline generated
                </strong>

                <p>
                    Notable events will appear here
                    after analysis.
                </p>

            </div>
        `;

        iocList.innerHTML = `
            <div class="empty-state">

                <div class="empty-state-icon">
                    <i class="fa-solid fa-crosshairs"></i>
                </div>

                <strong>
                    No IOCs detected
                </strong>

                <p>
                    Extracted indicators will appear
                    here after analysis.
                </p>

            </div>
        `;

        incidentSummary.textContent =
            "No incident summary generated.";

        recommendations.innerHTML = "";

        latestReport = "";
        detectedIOCs = [];

        setProcessingProgress(
            0,
            "Waiting for a file",
            ""
        );

        searchInput.value = "";
        severityFilter.value = "All";

        if (eventChart) {
            eventChart.destroy();
            eventChart = null;
        }

        showToast(
            "Log Analyzer cleared",
            "fa-rotate-left"
        );
    }
);

themeToggle.addEventListener(
    "click",
    toggleTheme
);

function initializeLogAnalyzer() {
    applySavedTheme();

    setProcessingProgress(
        0,
        "Waiting for a file",
        ""
    );

    updateSelectedFile(null);

    updateThreatSphere(
        0,
        "Low"
    );
}

initializeLogAnalyzer();