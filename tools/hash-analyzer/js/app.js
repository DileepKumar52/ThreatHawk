"use strict";

/* =========================================================
   THREATHAWK HASH ANALYZER
   Complete JavaScript

   Features:
   - Manual Analyze button
   - Multiple file upload
   - Drag-and-drop support
   - TXT, CSV and LOG input
   - Manual pasted input
   - MD5, SHA-1, SHA-256 and SHA-512 detection
   - Duplicate detection and highlighting
   - Animated statistics
   - Per-row copy controls
   - TXT, JSON, CSV and PDF exports
   - Clear/reset behavior
   - Persistent light/dark theme
   - Toast notifications
========================================================= */


/* =========================================================
   1. DOM ELEMENTS
========================================================= */

const dropZone =
    document.getElementById("dropZone");

const hashFilesInput =
    document.getElementById("hashFiles");

const dropIcon =
    document.getElementById("dropIcon");

const dropTitle =
    document.getElementById("dropTitle");

const dropText =
    document.getElementById("dropText");

const selectedFilesContainer =
    document.getElementById("selectedFiles");

const hashInput =
    document.getElementById("hashInput");

const analyzeBtn =
    document.getElementById("analyzeBtn");

const clearBtn =
    document.getElementById("clearBtn");

const totalHashes =
    document.getElementById("totalHashes");

const validHashes =
    document.getElementById("validHashes");

const invalidHashes =
    document.getElementById("invalidHashes");

const duplicateHashes =
    document.getElementById("duplicateHashes");

const hashResultsBody =
    document.getElementById("hashResultsBody");

const resultCountBadge =
    document.getElementById("resultCountBadge");

const exportMenuBtn =
    document.getElementById("exportMenuBtn");

const exportOptions =
    document.getElementById("exportOptions");

const themeToggle =
    document.getElementById("themeToggle");

const toast =
    document.getElementById("toast");

const toastMessage =
    document.getElementById("toastMessage");


/* =========================================================
   2. APPLICATION STATE
========================================================= */

const SUPPORTED_FILE_EXTENSIONS = [
    "txt",
    "csv",
    "log"
];

let selectedFiles = [];
let currentResults = [];
let toastTimer = null;


/* =========================================================
   3. GENERAL HELPERS
========================================================= */

function escapeHTML(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function formatFileSize(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) {
        return "0 B";
    }

    const units = [
        "B",
        "KB",
        "MB",
        "GB"
    ];

    const unitIndex = Math.min(
        Math.floor(
            Math.log(bytes) /
            Math.log(1024)
        ),
        units.length - 1
    );

    const value =
        bytes / 1024 ** unitIndex;

    return `${value.toFixed(
        unitIndex === 0 ? 0 : 1
    )} ${units[unitIndex]}`;
}

function getFileExtension(filename) {
    const parts =
        filename.toLowerCase().split(".");

    return parts.length > 1
        ? parts.pop()
        : "";
}

function createTimestamp() {
    return new Date()
        .toISOString()
        .replaceAll(":", "-")
        .replace(/\.\d{3}Z$/, "Z");
}

function pluralize(
    amount,
    singular,
    plural = `${singular}s`
) {
    return amount === 1
        ? singular
        : plural;
}


/* =========================================================
   4. TOAST NOTIFICATIONS
========================================================= */

function showToast(
    message,
    iconClass = "fa-check"
) {
    if (!toast || !toastMessage) {
        return;
    }

    toastMessage.textContent =
        message;

    const icon =
        toast.querySelector("i");

    if (icon) {
        icon.className =
            `fa-solid ${iconClass}`;
    }

    toast.classList.add("show");

    window.clearTimeout(toastTimer);

    toastTimer =
        window.setTimeout(() => {
            toast.classList.remove(
                "show"
            );
        }, 2300);
}


/* =========================================================
   5. THEME
========================================================= */

function updateThemeButton(
    lightModeEnabled
) {
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
    let savedTheme = null;

    try {
        savedTheme =
            localStorage.getItem(
                "threathawk-hash-theme"
            );
    } catch (error) {
        console.warn(
            "Theme preference could not be read:",
            error
        );
    }

    const lightModeEnabled =
        savedTheme === "light";

    document.body.classList.toggle(
        "light-mode",
        lightModeEnabled
    );

    updateThemeButton(
        lightModeEnabled
    );
}


/* =========================================================
   6. HASH NORMALIZATION AND DETECTION
========================================================= */

function normalizeHash(value) {
    return String(value)
        .trim()
        .replace(/^["']|["']$/g, "")
        .trim();
}

function detectHashType(hash) {
    if (!/^[a-fA-F0-9]+$/.test(hash)) {
        return {
            type: "Unknown",
            valid: false
        };
    }

    const length = hash.length;

    switch (length) {
        case 32:
            return {
                type: "MD5",
                valid: true
            };

        case 40:
            return {
                type: "SHA-1",
                valid: true
            };

        case 64:
            return {
                type: "SHA-256",
                valid: true
            };

        case 128:
            return {
                type: "SHA-512",
                valid: true
            };

        default:
            return {
                type: "Unknown",
                valid: false
            };
    }
}

function extractHashesFromText(text) {
    return String(text)
        .split(/[\s,;|]+/)
        .map(normalizeHash)
        .filter(Boolean);
}


/* =========================================================
   7. FILE VALIDATION AND READING
========================================================= */

function validateFile(file) {
    const extension =
        getFileExtension(file.name);

    return SUPPORTED_FILE_EXTENSIONS
        .includes(extension);
}

function getFileKey(file) {
    return [
        file.name,
        file.size,
        file.lastModified
    ].join("-");
}

function addFiles(files) {
    const incomingFiles =
        Array.from(files);

    if (incomingFiles.length === 0) {
        return;
    }

    const validFiles = [];
    const rejectedFiles = [];

    const existingKeys =
        new Set(
            selectedFiles.map(getFileKey)
        );

    incomingFiles.forEach(file => {
        if (!validateFile(file)) {
            rejectedFiles.push(file.name);
            return;
        }

        const key =
            getFileKey(file);

        if (!existingKeys.has(key)) {
            validFiles.push(file);
            existingKeys.add(key);
        }
    });

    selectedFiles = [
        ...selectedFiles,
        ...validFiles
    ];

    renderSelectedFiles();

    if (validFiles.length > 0) {
        showToast(
            `${validFiles.length} ${pluralize(
                validFiles.length,
                "file"
            )} selected`,
            "fa-file-circle-check"
        );
    }

    if (rejectedFiles.length > 0) {
        showToast(
            "Some unsupported files were ignored",
            "fa-triangle-exclamation"
        );
    }

    hashFilesInput.value = "";
}

function readFileAsText(file) {
    return new Promise(
        (resolve, reject) => {
            const reader =
                new FileReader();

            reader.onload = () => {
                resolve(
                    String(reader.result || "")
                );
            };

            reader.onerror = () => {
                reject(
                    new Error(
                        `Could not read ${file.name}.`
                    )
                );
            };

            reader.readAsText(file);
        }
    );
}

async function readSelectedFiles() {
    if (selectedFiles.length === 0) {
        return [];
    }

    dropZone.classList.add(
        "is-processing"
    );

    analyzeBtn.disabled = true;

    try {
        const contents =
            await Promise.all(
                selectedFiles.map(
                    readFileAsText
                )
            );

        return contents.flatMap(
            extractHashesFromText
        );
    } finally {
        dropZone.classList.remove(
            "is-processing"
        );

        analyzeBtn.disabled = false;
    }
}


/* =========================================================
   8. SELECTED FILE RENDERING
========================================================= */

function renderSelectedFiles() {
    if (selectedFiles.length === 0) {
        selectedFilesContainer.className =
            "selected-files empty-files";

        selectedFilesContainer.innerHTML = `
            <i class="fa-regular fa-folder-open"></i>
            <span>No files selected</span>
        `;

        dropTitle.textContent =
            "Drop hash files here";

        dropText.textContent =
            "Drag and drop files or click to browse";

        return;
    }

    selectedFilesContainer.className =
        "selected-files";

    selectedFilesContainer.innerHTML =
        selectedFiles
            .map(
                (file, index) => `
                    <div class="selected-file-item">

                        <div class="selected-file-info">

                            <span class="selected-file-icon">
                                <i class="fa-regular fa-file-lines"></i>
                            </span>

                            <div>
                                <strong title="${escapeHTML(file.name)}">
                                    ${escapeHTML(file.name)}
                                </strong>

                                <span>
                                    ${formatFileSize(file.size)}
                                </span>
                            </div>

                        </div>

                        <button
                            type="button"
                            class="remove-file-btn"
                            data-file-index="${index}"
                            aria-label="Remove ${escapeHTML(file.name)}"
                            title="Remove file"
                        >
                            <i class="fa-solid fa-xmark"></i>
                        </button>

                    </div>
                `
            )
            .join("");

    dropTitle.textContent =
        `${selectedFiles.length} ${pluralize(
            selectedFiles.length,
            "file"
        )} ready`;

    dropText.textContent =
        "Add more files or begin analysis";
}

function removeSelectedFile(index) {
    if (
        index < 0 ||
        index >= selectedFiles.length
    ) {
        return;
    }

    const removedFile =
        selectedFiles[index];

    selectedFiles.splice(index, 1);

    renderSelectedFiles();

    showToast(
        `${removedFile.name} removed`,
        "fa-trash"
    );
}


/* =========================================================
   9. RESULT GENERATION
========================================================= */

function buildAnalysisResults(hashes) {
    const occurrenceMap =
        new Map();

    hashes.forEach(hash => {
        const key =
            hash.toLowerCase();

        occurrenceMap.set(
            key,
            (occurrenceMap.get(key) || 0) + 1
        );
    });

    const processedKeys =
        new Set();

    const results = [];

    hashes.forEach(hash => {
        const key =
            hash.toLowerCase();

        if (processedKeys.has(key)) {
            return;
        }

        processedKeys.add(key);

        const detection =
            detectHashType(hash);

        const occurrences =
            occurrenceMap.get(key) || 1;

        results.push({
            hash,
            length: hash.length,
            type: detection.type,
            valid: detection.valid,
            status: detection.valid
                ? "Valid"
                : "Invalid",
            occurrences,
            duplicate:
                occurrences > 1
        });
    });

    return results;
}

function calculateSummary(
    rawHashes,
    results
) {
    const validCount =
        rawHashes.filter(hash =>
            detectHashType(hash).valid
        ).length;

    const invalidCount =
        rawHashes.length -
        validCount;

    const duplicateCount =
        results.reduce(
            (
                total,
                result
            ) => {
                return total +
                    Math.max(
                        result.occurrences - 1,
                        0
                    );
            },
            0
        );

    return {
        total: rawHashes.length,
        valid: validCount,
        invalid: invalidCount,
        duplicates: duplicateCount
    };
}


/* =========================================================
   10. ANIMATED STATISTICS
========================================================= */

function animateStatistic(
    element,
    targetValue,
    duration = 500
) {
    if (!element) {
        return;
    }

    const startValue =
        Number.parseInt(
            element.textContent,
            10
        ) || 0;

    const difference =
        targetValue - startValue;

    const startTime =
        performance.now();

    element.classList.remove(
        "updated",
        "counting"
    );

    element.classList.add(
        "counting"
    );

    function update(currentTime) {
        const elapsed =
            currentTime - startTime;

        const progress =
            Math.min(
                elapsed / duration,
                1
            );

        const easedProgress =
            1 -
            Math.pow(
                1 - progress,
                3
            );

        const displayedValue =
            Math.round(
                startValue +
                difference *
                easedProgress
            );

        element.textContent =
            displayedValue.toLocaleString();

        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            element.textContent =
                targetValue.toLocaleString();

            element.classList.remove(
                "counting"
            );

            element.classList.add(
                "updated"
            );
        }
    }

    requestAnimationFrame(update);
}

function updateStatistics(summary) {
    animateStatistic(
        totalHashes,
        summary.total
    );

    animateStatistic(
        validHashes,
        summary.valid
    );

    animateStatistic(
        invalidHashes,
        summary.invalid
    );

    animateStatistic(
        duplicateHashes,
        summary.duplicates
    );
}


/* =========================================================
   11. RESULTS TABLE
========================================================= */

function renderEmptyResults() {
    hashResultsBody.innerHTML = `
        <tr class="empty-row">

            <td colspan="7">

                <div class="table-empty-state">

                    <div class="empty-state-icon">
                        <i class="fa-solid fa-fingerprint"></i>
                    </div>

                    <strong>
                        No hashes analyzed
                    </strong>

                    <p>
                        Upload files or paste hashes,
                        then click Analyze Hashes.
                    </p>

                </div>

            </td>

        </tr>
    `;

    resultCountBadge.textContent =
        "0 results";
}

function renderResults(results) {
    if (results.length === 0) {
        renderEmptyResults();
        return;
    }

    resultCountBadge.textContent =
        `${results.length} ${pluralize(
            results.length,
            "result"
        )}`;

    hashResultsBody.innerHTML =
        results
            .map(
                (result, index) => {
                    const statusClass =
                        result.valid
                            ? "status-valid"
                            : "status-invalid";

                    const occurrenceMarkup =
                        result.duplicate
                            ? `
                                <span class="duplicate-badge">
                                    ${result.occurrences} copies
                                </span>
                            `
                            : `
                                <span class="unique-badge">
                                    Unique
                                </span>
                            `;

                    return `
                        <tr
                            class="${
                                result.duplicate
                                    ? "duplicate-row"
                                    : ""
                            }"
                        >
                            <td>
                                ${index + 1}
                            </td>

                            <td>
                                <div
                                    class="hash-value"
                                    title="${escapeHTML(result.hash)}"
                                >
                                    ${escapeHTML(result.hash)}
                                </div>
                            </td>

                            <td>
                                ${result.length}
                            </td>

                            <td>
                                <span class="hash-type-badge">
                                    ${escapeHTML(result.type)}
                                </span>
                            </td>

                            <td>
                                <span class="status-badge ${statusClass}">
                                    ${result.status}
                                </span>
                            </td>

                            <td>
                                ${occurrenceMarkup}
                            </td>

                            <td>
                                <button
                                    type="button"
                                    class="row-copy-btn"
                                    data-copy-index="${index}"
                                    aria-label="Copy hash"
                                    title="Copy hash"
                                >
                                    <i class="fa-regular fa-copy"></i>
                                </button>
                            </td>
                        </tr>
                    `;
                }
            )
            .join("");
}


/* =========================================================
   12. ANALYSIS
========================================================= */

async function analyzeHashes() {
    const pastedHashes =
        extractHashesFromText(
            hashInput.value
        );

    let fileHashes = [];

    try {
        fileHashes =
            await readSelectedFiles();
    } catch (error) {
        console.error(
            "File reading failed:",
            error
        );

        showToast(
            error.message ||
            "One or more files could not be read",
            "fa-xmark"
        );

        return;
    }

    const allHashes = [
        ...pastedHashes,
        ...fileHashes
    ];

    if (allHashes.length === 0) {
        showToast(
            "Paste hashes or select files first",
            "fa-circle-exclamation"
        );

        hashInput.focus();
        return;
    }

    analyzeBtn.disabled = true;

    try {
        currentResults =
            buildAnalysisResults(
                allHashes
            );

        const summary =
            calculateSummary(
                allHashes,
                currentResults
            );

        updateStatistics(summary);
        renderResults(currentResults);

        showToast(
            `${allHashes.length} ${pluralize(
                allHashes.length,
                "hash"
            )} analyzed`,
            "fa-magnifying-glass-chart"
        );
    } catch (error) {
        console.error(
            "Hash analysis failed:",
            error
        );

        showToast(
            "Hash analysis failed",
            "fa-xmark"
        );
    } finally {
        analyzeBtn.disabled = false;
    }
}


/* =========================================================
   13. CLIPBOARD
========================================================= */

async function copyText(text) {
    if (
        navigator.clipboard &&
        window.isSecureContext
    ) {
        await navigator.clipboard.writeText(
            text
        );

        return;
    }

    const temporaryTextArea =
        document.createElement("textarea");

    temporaryTextArea.value = text;
    temporaryTextArea.setAttribute(
        "readonly",
        ""
    );

    temporaryTextArea.style.position =
        "fixed";

    temporaryTextArea.style.opacity =
        "0";

    document.body.appendChild(
        temporaryTextArea
    );

    temporaryTextArea.select();

    const copied =
        document.execCommand("copy");

    temporaryTextArea.remove();

    if (!copied) {
        throw new Error(
            "Clipboard operation failed."
        );
    }
}

async function copyResultHash(
    index,
    button
) {
    const result =
        currentResults[index];

    if (!result) {
        return;
    }

    try {
        await copyText(result.hash);

        button.classList.remove(
            "copy-failed"
        );

        button.classList.add(
            "copied"
        );

        const icon =
            button.querySelector("i");

        if (icon) {
            icon.className =
                "fa-solid fa-check";
        }

        showToast(
            "Hash copied"
        );

        window.setTimeout(() => {
            button.classList.remove(
                "copied"
            );

            if (icon) {
                icon.className =
                    "fa-regular fa-copy";
            }
        }, 1400);
    } catch (error) {
        console.error(
            "Copy failed:",
            error
        );

        button.classList.add(
            "copy-failed"
        );

        const icon =
            button.querySelector("i");

        if (icon) {
            icon.className =
                "fa-solid fa-xmark";
        }

        showToast(
            "Hash could not be copied",
            "fa-xmark"
        );
    }
}


/* =========================================================
   14. EXPORT HELPERS
========================================================= */

function ensureResultsForExport() {
    if (currentResults.length === 0) {
        showToast(
            "Analyze hashes before exporting",
            "fa-circle-exclamation"
        );

        return false;
    }

    return true;
}

function downloadBlob(
    content,
    filename,
    mimeType
) {
    const blob =
        new Blob(
            [content],
            {
                type: mimeType
            }
        );

    const downloadURL =
        URL.createObjectURL(blob);

    const link =
        document.createElement("a");

    link.href = downloadURL;
    link.download = filename;

    document.body.appendChild(link);

    link.click();
    link.remove();

    URL.revokeObjectURL(
        downloadURL
    );
}

function createExportRows() {
    return currentResults.map(
        (result, index) => ({
            number: index + 1,
            hash: result.hash,
            length: result.length,
            algorithm: result.type,
            status: result.status,
            occurrences:
                result.occurrences,
            duplicate:
                result.duplicate
        })
    );
}

function createReportMetadata() {
    return {
        generatedBy:
            "ThreatHawk Hash Analyzer",
        generatedAt:
            new Date().toISOString(),
        uniqueResults:
            currentResults.length,
        validResults:
            currentResults.filter(
                result => result.valid
            ).length,
        invalidResults:
            currentResults.filter(
                result => !result.valid
            ).length,
        duplicatedValues:
            currentResults.filter(
                result => result.duplicate
            ).length
    };
}


/* =========================================================
   15. TXT EXPORT
========================================================= */

function exportTXT() {
    if (!ensureResultsForExport()) {
        return;
    }

    const metadata =
        createReportMetadata();

    const lines = [
        "THREATHAWK HASH ANALYSIS REPORT",
        "================================",
        "",
        `Generated: ${metadata.generatedAt}`,
        `Unique results: ${metadata.uniqueResults}`,
        `Valid results: ${metadata.validResults}`,
        `Invalid results: ${metadata.invalidResults}`,
        `Duplicated values: ${metadata.duplicatedValues}`,
        "",
        "RESULTS",
        "-------"
    ];

    currentResults.forEach(
        (result, index) => {
            lines.push(
                "",
                `#${index + 1}`,
                `Hash: ${result.hash}`,
                `Length: ${result.length}`,
                `Algorithm: ${result.type}`,
                `Status: ${result.status}`,
                `Occurrences: ${result.occurrences}`,
                `Duplicate: ${
                    result.duplicate
                        ? "Yes"
                        : "No"
                }`
            );
        }
    );

    downloadBlob(
        lines.join("\n"),
        `threathawk-hash-report-${createTimestamp()}.txt`,
        "text/plain;charset=utf-8"
    );
}


/* =========================================================
   16. JSON EXPORT
========================================================= */

function exportJSON() {
    if (!ensureResultsForExport()) {
        return;
    }

    const report = {
        metadata:
            createReportMetadata(),

        results:
            createExportRows()
    };

    downloadBlob(
        JSON.stringify(
            report,
            null,
            2
        ),
        `threathawk-hash-report-${createTimestamp()}.json`,
        "application/json;charset=utf-8"
    );
}


/* =========================================================
   17. CSV EXPORT
========================================================= */

function escapeCSV(value) {
    const stringValue =
        String(value);

    return `"${stringValue.replaceAll(
        '"',
        '""'
    )}"`;
}

function exportCSV() {
    if (!ensureResultsForExport()) {
        return;
    }

    const headers = [
        "Number",
        "Hash",
        "Length",
        "Algorithm",
        "Status",
        "Occurrences",
        "Duplicate"
    ];

    const rows =
        createExportRows()
            .map(result => [
                result.number,
                result.hash,
                result.length,
                result.algorithm,
                result.status,
                result.occurrences,
                result.duplicate
                    ? "Yes"
                    : "No"
            ]);

    const csvContent = [
        headers.map(escapeCSV).join(","),
        ...rows.map(
            row =>
                row.map(escapeCSV)
                    .join(",")
        )
    ].join("\n");

    downloadBlob(
        csvContent,
        `threathawk-hash-report-${createTimestamp()}.csv`,
        "text/csv;charset=utf-8"
    );
}


/* =========================================================
   18. PDF EXPORT
========================================================= */

function splitHashForPDF(
    pdf,
    hash,
    maximumWidth
) {
    return pdf.splitTextToSize(
        hash,
        maximumWidth
    );
}

function exportPDF() {
    if (!ensureResultsForExport()) {
        return;
    }

    if (
        !window.jspdf ||
        !window.jspdf.jsPDF
    ) {
        showToast(
            "PDF library is unavailable",
            "fa-xmark"
        );

        return;
    }

    const {
        jsPDF
    } = window.jspdf;

    const pdf =
        new jsPDF({
            orientation: "portrait",
            unit: "mm",
            format: "a4"
        });

    const pageWidth =
        pdf.internal.pageSize.getWidth();

    const pageHeight =
        pdf.internal.pageSize.getHeight();

    const margin = 16;
    const contentWidth =
        pageWidth - margin * 2;

    let y = 18;

    const metadata =
        createReportMetadata();

    function ensurePageSpace(
        requiredHeight
    ) {
        if (
            y + requiredHeight >
            pageHeight - 16
        ) {
            pdf.addPage();
            y = 18;
        }
    }

    pdf.setFont(
        "helvetica",
        "bold"
    );

    pdf.setFontSize(18);

    pdf.text(
        "ThreatHawk Hash Analysis Report",
        margin,
        y
    );

    y += 9;

    pdf.setFont(
        "helvetica",
        "normal"
    );

    pdf.setFontSize(9);

    pdf.text(
        `Generated: ${new Date(
            metadata.generatedAt
        ).toLocaleString()}`,
        margin,
        y
    );

    y += 6;

    pdf.text(
        `Unique results: ${metadata.uniqueResults} | Valid: ${metadata.validResults} | Invalid: ${metadata.invalidResults} | Duplicated values: ${metadata.duplicatedValues}`,
        margin,
        y
    );

    y += 10;

    currentResults.forEach(
        (result, index) => {
            const hashLines =
                splitHashForPDF(
                    pdf,
                    result.hash,
                    contentWidth - 8
                );

            const blockHeight =
                25 +
                hashLines.length * 4;

            ensurePageSpace(
                blockHeight
            );

            pdf.setFont(
                "helvetica",
                "bold"
            );

            pdf.setFontSize(10);

            pdf.text(
                `#${index + 1} - ${result.type} - ${result.status}`,
                margin,
                y
            );

            y += 5;

            pdf.setFont(
                "courier",
                "normal"
            );

            pdf.setFontSize(8);

            pdf.text(
                hashLines,
                margin + 3,
                y
            );

            y +=
                hashLines.length * 4 +
                3;

            pdf.setFont(
                "helvetica",
                "normal"
            );

            pdf.setFontSize(8);

            pdf.text(
                `Length: ${result.length} | Occurrences: ${result.occurrences} | Duplicate: ${
                    result.duplicate
                        ? "Yes"
                        : "No"
                }`,
                margin + 3,
                y
            );

            y += 8;

            pdf.setDrawColor(
                180,
                180,
                180
            );

            pdf.line(
                margin,
                y,
                pageWidth - margin,
                y
            );

            y += 7;
        }
    );

    pdf.save(
        `threathawk-hash-report-${createTimestamp()}.pdf`
    );
}


/* =========================================================
   19. EXPORT MENU
========================================================= */

function setExportMenuOpen(open) {
    exportOptions.classList.toggle(
        "show",
        open
    );

    exportMenuBtn.setAttribute(
        "aria-expanded",
        String(open)
    );

    const chevron =
        exportMenuBtn.querySelector(
            ".fa-chevron-down, .fa-chevron-up"
        );

    if (chevron) {
        chevron.className =
            open
                ? "fa-solid fa-chevron-up"
                : "fa-solid fa-chevron-down";
    }
}

function handleExport(format) {
    const exporters = {
        txt: exportTXT,
        json: exportJSON,
        csv: exportCSV,
        pdf: exportPDF
    };

    const exporter =
        exporters[format];

    if (!exporter) {
        showToast(
            "Unsupported export format",
            "fa-xmark"
        );

        return;
    }

    exporter();

    if (currentResults.length > 0) {
        showToast(
            `${format.toUpperCase()} report exported`,
            "fa-file-export"
        );
    }
}


/* =========================================================
   20. CLEAR AND RESET
========================================================= */

function resetStatistics() {
    totalHashes.textContent = "0";
    validHashes.textContent = "0";
    invalidHashes.textContent = "0";
    duplicateHashes.textContent = "0";
}

function clearAnalyzer() {
    selectedFiles = [];
    currentResults = [];

    hashFilesInput.value = "";
    hashInput.value = "";

    renderSelectedFiles();
    renderEmptyResults();
    resetStatistics();

    setExportMenuOpen(false);

    showToast(
        "Hash Analyzer cleared",
        "fa-rotate-left"
    );

    hashInput.focus();
}


/* =========================================================
   21. EVENT LISTENERS
========================================================= */

dropZone.addEventListener(
    "click",
    () => {
        hashFilesInput.click();
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
            hashFilesInput.click();
        }
    }
);

hashFilesInput.addEventListener(
    "change",
    event => {
        addFiles(
            event.target.files
        );
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
            event.stopPropagation();

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
            event.stopPropagation();

            dropZone.classList.remove(
                "is-dragging"
            );
        }
    );
});

dropZone.addEventListener(
    "drop",
    event => {
        addFiles(
            event.dataTransfer.files
        );
    }
);

selectedFilesContainer.addEventListener(
    "click",
    event => {
        const removeButton =
            event.target.closest(
                "[data-file-index]"
            );

        if (!removeButton) {
            return;
        }

        const index =
            Number.parseInt(
                removeButton.dataset.fileIndex,
                10
            );

        removeSelectedFile(index);
    }
);

analyzeBtn.addEventListener(
    "click",
    analyzeHashes
);

clearBtn.addEventListener(
    "click",
    clearAnalyzer
);

hashInput.addEventListener(
    "keydown",
    event => {
        if (
            event.key === "Enter" &&
            event.ctrlKey
        ) {
            event.preventDefault();
            analyzeHashes();
        }
    }
);

hashResultsBody.addEventListener(
    "click",
    event => {
        const copyButton =
            event.target.closest(
                "[data-copy-index]"
            );

        if (!copyButton) {
            return;
        }

        const index =
            Number.parseInt(
                copyButton.dataset.copyIndex,
                10
            );

        copyResultHash(
            index,
            copyButton
        );
    }
);

exportMenuBtn.addEventListener(
    "click",
    event => {
        event.stopPropagation();

        const currentlyOpen =
            exportOptions.classList.contains(
                "show"
            );

        setExportMenuOpen(
            !currentlyOpen
        );
    }
);

exportOptions.addEventListener(
    "click",
    event => {
        const formatButton =
            event.target.closest(
                "[data-format]"
            );

        if (!formatButton) {
            return;
        }

        handleExport(
            formatButton.dataset.format
        );

        setExportMenuOpen(false);
    }
);

document.addEventListener(
    "click",
    event => {
        if (
            !event.target.closest(
                ".export-menu"
            )
        ) {
            setExportMenuOpen(false);
        }
    }
);

document.addEventListener(
    "keydown",
    event => {
        if (event.key === "Escape") {
            setExportMenuOpen(false);
        }
    }
);

themeToggle.addEventListener(
    "click",
    () => {
        const lightModeEnabled =
            !document.body.classList.contains(
                "light-mode"
            );

        document.body.classList.toggle(
            "light-mode",
            lightModeEnabled
        );

        updateThemeButton(
            lightModeEnabled
        );

        try {
            localStorage.setItem(
                "threathawk-hash-theme",
                lightModeEnabled
                    ? "light"
                    : "dark"
            );
        } catch (error) {
            console.warn(
                "Theme preference could not be saved:",
                error
            );
        }
    }
);


/* =========================================================
   22. INITIALIZATION
========================================================= */

function initializeHashAnalyzer() {
    applySavedTheme();

    renderSelectedFiles();
    renderEmptyResults();
    resetStatistics();

    exportMenuBtn.setAttribute(
        "aria-expanded",
        "false"
    );
}

initializeHashAnalyzer();