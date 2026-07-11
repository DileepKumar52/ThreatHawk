const hashInput = document.getElementById("hashInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");

const totalHashes = document.getElementById("totalHashes");
const validHashes = document.getElementById("validHashes");
const invalidHashes = document.getElementById("invalidHashes");

const hashResultsBody = document.getElementById("hashResultsBody");

const exportMenuBtn = document.getElementById("exportMenuBtn");
const exportOptions = document.getElementById("exportOptions");

const dropZone = document.getElementById("dropZone");
const hashFiles = document.getElementById("hashFiles");

const selectedFiles = document.getElementById("selectedFiles");
const dropIcon = document.getElementById("dropIcon");
const dropTitle = document.getElementById("dropTitle");
const dropText = document.getElementById("dropText");

const duplicateHashes = document.getElementById("duplicateHashes");

let loadedFiles = [];

let analysisResults = [];

function detectHashType(hash) {
    const hexPattern = /^[a-fA-F0-9]+$/;

    if (!hexPattern.test(hash)) {
        return null;
    }

    const hashTypes = {
        32: "MD5",
        40: "SHA-1",
        56: "SHA-224 / SHA3-224",
        64: "SHA-256 / SHA3-256",
        96: "SHA-384 / SHA3-384",
        128: "SHA-512 / SHA3-512"
    };

    if (hashTypes[hash.length]) {
        return hashTypes[hash.length];
    }

    /*
     * Unknown algorithms may still produce valid hexadecimal digests.
     * Hexadecimal data must contain complete bytes, so its length must be even.
     */
    if (hash.length >= 16 && hash.length % 2 === 0) {
        return "Custom Hex Digest";
    }

    return null;
}

function shortenHash(hash, visibleCharacters = 24) {
    if (hash.length <= visibleCharacters * 2) {
        return hash;
    }

    const beginning = hash.slice(0, visibleCharacters);
    const ending = hash.slice(-visibleCharacters);

    return `${beginning}...${ending}`;
}

function escapeHTML(value) {
    return value
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function getHashesFromInput() {
    return hashInput.value
        .split(/\r?\n/)
        .map(hash => hash.trim())
        .filter(hash => hash.length > 0);
}

function resetResults() {
    totalHashes.textContent = "0";
    validHashes.textContent = "0";
    invalidHashes.textContent = "0";
    duplicateHashes.textContent = "0";

    hashResultsBody.innerHTML = `
        <tr class="empty-row">
            <td colspan="7">No hashes analyzed yet.</td>
        </tr>
    `;
}

function ensureResultsExist() {
    if (analysisResults.length === 0) {
        alert("Analyze at least one hash before exporting.");
        return false;
    }

    return true;
}

function getReportMetadata() {
    const validCount = analysisResults.filter(
        result => result.status === "Valid"
    ).length;

    const invalidCount = analysisResults.length - validCount;

    return {
        generatedAt: new Date().toLocaleString(),
        totalHashes: analysisResults.length,
        validHashes: validCount,
        invalidHashes: invalidCount
    };
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], {
        type: mimeType
    });

    const downloadUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = downloadUrl;
    link.download = filename;

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(downloadUrl);
}

function getReportFilename(extension) {
    const timestamp = new Date()
        .toISOString()
        .replaceAll(":", "-")
        .replaceAll(".", "-");

    return `threathawk-hash-report-${timestamp}.${extension}`;
}

function exportTXT() {
    if (!ensureResultsExist()) {
        return;
    }

    const metadata = getReportMetadata();

    const resultSections = analysisResults.map(result => {
        return [
            `#${result.id}`,
            `Hash   : ${result.hash}`,
            `Length : ${result.length}`,
            `Type   : ${result.type}`,
            `Status : ${result.status}`,
            "------------------------------------------------------------"
        ].join("\n");
    });

    const report = [
        "============================================================",
        "              THREATHAWK HASH ANALYSIS REPORT",
        "============================================================",
        "",
        `Generated: ${metadata.generatedAt}`,
        "",
        "SUMMARY",
        "------------------------------------------------------------",
        `Total Hashes   : ${metadata.totalHashes}`,
        `Valid Hashes   : ${metadata.validHashes}`,
        `Invalid Hashes : ${metadata.invalidHashes}`,
        "",
        "ANALYSIS RESULTS",
        "------------------------------------------------------------",
        "",
        resultSections.join("\n\n"),
        "",
        "NOTES",
        "------------------------------------------------------------",
        "Hash types are inferred using hexadecimal format and digest length.",
        "Identical digest lengths may belong to more than one algorithm.",
        "Validation confirms format only; it does not establish reputation or safety.",
        "",
        "Generated by ThreatHawk",
        "============================================================"
    ].join("\n");

    downloadFile(
        report,
        getReportFilename("txt"),
        "text/plain;charset=utf-8"
    );
}

function exportJSON() {
    if (!ensureResultsExist()) {
        return;
    }

    const report = {
        tool: "ThreatHawk Hash Analyzer",
        metadata: getReportMetadata(),
        results: analysisResults
    };

    downloadFile(
        JSON.stringify(report, null, 2),
        getReportFilename("json"),
        "application/json;charset=utf-8"
    );
}

function escapeCSVValue(value) {
    const stringValue = String(value);

    return `"${stringValue.replaceAll('"', '""')}"`;
}

function exportCSV() {
    if (!ensureResultsExist()) {
        return;
    }

    const headers = [
        "ID",
        "Hash",
        "Length",
        "Type",
        "Status"
    ];

    const rows = analysisResults.map(result => {
        return [
            result.id,
            result.hash,
            result.length,
            result.type,
            result.status
        ]
            .map(escapeCSVValue)
            .join(",");
    });

    const csvContent = [
        headers.map(escapeCSVValue).join(","),
        ...rows
    ].join("\n");

    /*
     * UTF-8 BOM helps spreadsheet applications recognize
     * the file encoding correctly.
     */
    downloadFile(
        `\uFEFF${csvContent}`,
        getReportFilename("csv"),
        "text/csv;charset=utf-8"
    );
}

function exportPDF() {
    if (!ensureResultsExist()) {
        return;
    }

    if (!window.jspdf?.jsPDF) {
        alert("PDF library failed to load. Check your internet connection.");
        return;
    }

    const { jsPDF } = window.jspdf;
    const documentPDF = new jsPDF();

    const metadata = getReportMetadata();

    const pageWidth = documentPDF.internal.pageSize.getWidth();
    const pageHeight = documentPDF.internal.pageSize.getHeight();

    const leftMargin = 15;
    const rightMargin = 15;
    const usableWidth = pageWidth - leftMargin - rightMargin;

    let currentY = 18;

    function addPageIfNeeded(requiredHeight = 20) {
        if (currentY + requiredHeight > pageHeight - 18) {
            documentPDF.addPage();
            currentY = 18;
        }
    }

    function addWrappedText(text, options = {}) {
        const {
            fontSize = 10,
            fontStyle = "normal",
            gapAfter = 5
        } = options;

        documentPDF.setFont("helvetica", fontStyle);
        documentPDF.setFontSize(fontSize);

        const lines = documentPDF.splitTextToSize(
            String(text),
            usableWidth
        );

        const lineHeight = fontSize * 0.45;
        const requiredHeight = lines.length * lineHeight + gapAfter;

        addPageIfNeeded(requiredHeight);

        documentPDF.text(lines, leftMargin, currentY);

        currentY += requiredHeight;
    }

    documentPDF.setFont("helvetica", "bold");
    documentPDF.setFontSize(20);
    documentPDF.text(
        "ThreatHawk Hash Analysis Report",
        leftMargin,
        currentY
    );

    currentY += 10;

    documentPDF.setFont("helvetica", "normal");
    documentPDF.setFontSize(10);
    documentPDF.text(
        `Generated: ${metadata.generatedAt}`,
        leftMargin,
        currentY
    );

    currentY += 12;

    addWrappedText("Summary", {
        fontSize: 15,
        fontStyle: "bold",
        gapAfter: 7
    });

    addWrappedText(
        `Total Hashes: ${metadata.totalHashes}`,
        { gapAfter: 4 }
    );

    addWrappedText(
        `Valid Hashes: ${metadata.validHashes}`,
        { gapAfter: 4 }
    );

    addWrappedText(
        `Invalid Hashes: ${metadata.invalidHashes}`,
        { gapAfter: 9 }
    );

    addWrappedText("Analysis Results", {
        fontSize: 15,
        fontStyle: "bold",
        gapAfter: 8
    });

    analysisResults.forEach(result => {
        addPageIfNeeded(38);

        addWrappedText(`#${result.id}`, {
            fontSize: 11,
            fontStyle: "bold",
            gapAfter: 4
        });

        addWrappedText(`Hash: ${result.hash}`, {
            fontSize: 9,
            gapAfter: 4
        });

        addWrappedText(`Length: ${result.length}`, {
            gapAfter: 4
        });

        addWrappedText(`Type: ${result.type}`, {
            gapAfter: 4
        });

        addWrappedText(`Status: ${result.status}`, {
            gapAfter: 8
        });

        documentPDF.setDrawColor(190);
        documentPDF.line(
            leftMargin,
            currentY,
            pageWidth - rightMargin,
            currentY
        );

        currentY += 8;
    });

    addPageIfNeeded(35);

    addWrappedText("Notes", {
        fontSize: 15,
        fontStyle: "bold",
        gapAfter: 7
    });

    addWrappedText(
        "Hash types are inferred using hexadecimal format and digest length."
    );

    addWrappedText(
        "Identical digest lengths may belong to more than one algorithm."
    );

    addWrappedText(
        "Validation confirms format only and does not establish whether a hash is safe or malicious."
    );

    documentPDF.save(getReportFilename("pdf"));
}

const supportedExtensions = ["txt", "csv", "log"];

function getFileExtension(filename) {
    return filename
        .split(".")
        .pop()
        .toLowerCase();
}

function isSupportedFile(file) {
    return supportedExtensions.includes(
        getFileExtension(file.name)
    );
}

function extractValuesFromFile(content) {
    return content
        /*
         * Supports:
         * - one hash per line
         * - comma-separated CSV values
         * - semicolon-separated values
         * - tab-separated values
         */
        .split(/[\r\n,;\t]+/)
        .map(value => value.trim())
        .filter(value => value.length > 0);
}

function readFileAsText(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();

        reader.onload = event => {
            resolve(event.target.result);
        };

        reader.onerror = () => {
            reject(
                new Error(`Could not read ${file.name}`)
            );
        };

        reader.readAsText(file);
    });
}

function renderSelectedFiles() {
    if (loadedFiles.length === 0) {
        selectedFiles.textContent = "No files selected";

        dropIcon.textContent = "📂";
        dropTitle.textContent = "Drop hash files here";
        dropText.textContent =
            "or click to select multiple files";

        return;
    }

    selectedFiles.innerHTML = loadedFiles
        .map((file, index) => {
            return `
                <div class="selected-file-item">
                    <div class="selected-file-info">
                        <span class="selected-file-icon">📄</span>

                        <div>
                            <strong>${escapeHTML(file.name)}</strong>
                            <span>${formatFileSize(file.size)}</span>
                        </div>
                    </div>

                    <button
                        type="button"
                        class="remove-file-btn"
                        data-file-index="${index}"
                        aria-label="Remove ${escapeHTML(file.name)}"
                        title="Remove file"
                    >
                        ×
                    </button>
                </div>
            `;
        })
        .join("");

    dropIcon.textContent = "✓";
    dropTitle.textContent =
        `${loadedFiles.length} file${loadedFiles.length === 1 ? "" : "s"} selected`;

    dropText.textContent =
        "Drop more files or click to add";
}

function formatFileSize(bytes) {
    if (bytes < 1024) {
        return `${bytes} B`;
    }

    if (bytes < 1024 * 1024) {
        return `${(bytes / 1024).toFixed(1)} KB`;
    }

    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

async function handleFiles(fileList) {
    const incomingFiles = Array.from(fileList);

    if (incomingFiles.length === 0) {
        return;
    }

    const supportedFiles = incomingFiles.filter(isSupportedFile);
    const rejectedFiles = incomingFiles.filter(
        file => !isSupportedFile(file)
    );

    if (rejectedFiles.length > 0) {
        alert(
            `Unsupported files skipped:\n${rejectedFiles
                .map(file => file.name)
                .join("\n")}`
        );
    }

    if (supportedFiles.length === 0) {
        return;
    }

    dropZone.classList.add("is-processing");
    dropIcon.textContent = "⏳";
    dropTitle.textContent = "Reading files...";
    dropText.textContent = "Please wait";

    try {
        const newHashValues = [];

        for (const file of supportedFiles) {
            const content = await readFileAsText(file);
            const values = extractValuesFromFile(content);

            newHashValues.push(...values);
        }

        loadedFiles.push(...supportedFiles);

        const existingValues = getHashesFromInput();

        hashInput.value = [
            ...existingValues,
            ...newHashValues
        ].join("\n");

        renderSelectedFiles();

        dropText.textContent =
            `${newHashValues.length} value${newHashValues.length === 1 ? "" : "s"} loaded`;
    } catch (error) {
        console.error(error);

        alert(
            "One or more files could not be read."
        );

        renderSelectedFiles();
    } finally {
        dropZone.classList.remove("is-processing");

        /*
         * Reset allows selecting the same file again later.
         */
        hashFiles.value = "";
    }
}

function analyzeHashes() {
    const hashes = getHashesFromInput();

    if (hashes.length === 0) {
        resetResults();

        hashResultsBody.innerHTML = `
            <tr class="empty-row">
                <td colspan="7">Please enter at least one hash.</td>
            </tr>
        `;

        return;
    }

    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "Analyzing...";

    setTimeout(() => {
        let validCount = 0;
        let invalidCount = 0;

        analysisResults = [];

        const occurrenceMap = new Map();

        hashes.forEach(hash => {
            const normalizedHash = hash.toLowerCase();

            occurrenceMap.set(
                normalizedHash,
                (occurrenceMap.get(normalizedHash) || 0) + 1
            );
        });

        hashResultsBody.innerHTML = "";

        hashes.forEach((hash, index) => {
            const hashType = detectHashType(hash);
            const isValid = hashType !== null;
            const normalizedHash = hash.toLowerCase();
            const occurrenceCount = occurrenceMap.get(normalizedHash) || 1;
            const isDuplicate = occurrenceCount > 1;

            analysisResults.push({
                id: index + 1,
                hash,
                length: hash.length,
                type: hashType || "Unknown",
                status: isValid ? "Valid" : "Invalid",
                occurrences: occurrenceCount,
                duplicate: isDuplicate
            });
            const safeHash = escapeHTML(hash);
            const displayedHash = escapeHTML(shortenHash(hash));

            if (isValid) {
                validCount++;
            } else {
                invalidCount++;
            }

            const row = document.createElement("tr");

            if (isDuplicate) {
                row.classList.add("duplicate-row");
            }

            row.innerHTML = `
                <td>${index + 1}</td>

                <td
                    class="hash-value"
                    title="${safeHash}"
                    data-full-hash="${safeHash}"
                >
                    ${displayedHash}
                </td>

                <td>${hash.length}</td>

                <td>
                    ${hashType || "Unknown"}
                </td>

                <td>
                    <span class="status-badge ${
                        isValid ? "status-valid" : "status-invalid"
                    }">
                        ${isValid ? "Valid" : "Invalid"}
                    </span>
                </td>

                <td>
                    ${
                        isDuplicate
                        ? `<span class="duplicate-badge">${occurrenceCount}× Duplicate</span>`
                        : `<span class="unique-badge">1×</span>`
                    }
                </td>

                <td>
                    <button
                        type="button"
                        class="row-copy-btn"
                        data-hash="${safeHash}"
                        aria-label="Copy hash"
                        title="Copy full hash"
                    >
                        📋
                    </button>
                </td>
            `;

            hashResultsBody.appendChild(row);
        });

        const duplicateEntryCount = Array.from(
            occurrenceMap.values()
        ).reduce((total, count) => {
            return total + Math.max(count - 1, 0);
        }, 0);

        totalHashes.textContent = hashes.length;
        validHashes.textContent = validCount;
        invalidHashes.textContent = invalidCount;

        analyzeBtn.disabled = false;
        analyzeBtn.textContent = "Analyze Hashes";
    }, 300);
}

analyzeBtn.addEventListener("click", analyzeHashes);

clearBtn.addEventListener("click", () => {
    hashInput.value = "";

    loadedFiles = [];
    analysisResults = [];

    hashFiles.value = "";

    renderSelectedFiles();
    resetResults();

    exportOptions?.classList.remove("show");
});

hashInput.addEventListener("keydown", event => {
    if (event.key === "Enter" && event.ctrlKey) {
        event.preventDefault();
        analyzeHashes();
    }
});

hashResultsBody.addEventListener("click", async event => {
    const copyButton = event.target.closest(".row-copy-btn");

    if (!copyButton) {
        return;
    }

    const hash = copyButton.dataset.hash;

    try {
        await navigator.clipboard.writeText(hash);

        copyButton.textContent = "✓";
        copyButton.classList.add("copied");

        setTimeout(() => {
            copyButton.textContent = "📋";
            copyButton.classList.remove("copied");
        }, 1200);
    } catch (error) {
        console.error("Copy failed:", error);

        copyButton.textContent = "!";
        copyButton.classList.add("copy-failed");

        setTimeout(() => {
            copyButton.textContent = "📋";
            copyButton.classList.remove("copy-failed");
        }, 1200);
    }
});

exportMenuBtn.addEventListener("click", event => {
    event.stopPropagation();
    exportOptions.classList.toggle("show");
});

exportOptions.addEventListener("click", event => {
    const exportButton = event.target.closest("[data-format]");

    if (!exportButton) {
        return;
    }

    const format = exportButton.dataset.format;

    const exporters = {
        txt: exportTXT,
        json: exportJSON,
        csv: exportCSV,
        pdf: exportPDF
    };

    const selectedExporter = exporters[format];

    if (selectedExporter) {
        selectedExporter();
    }

    exportOptions.classList.remove("show");
});

document.addEventListener("click", event => {
    if (!event.target.closest(".export-menu")) {
        exportOptions.classList.remove("show");
    }
});

dropZone.addEventListener("click", () => {
    hashFiles.click();
});

dropZone.addEventListener("keydown", event => {
    if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        hashFiles.click();
    }
});

hashFiles.addEventListener("change", event => {
    handleFiles(event.target.files);
});

dropZone.addEventListener("dragenter", event => {
    event.preventDefault();
    dropZone.classList.add("is-dragging");
});

dropZone.addEventListener("dragover", event => {
    event.preventDefault();
    dropZone.classList.add("is-dragging");

    if (event.dataTransfer) {
        event.dataTransfer.dropEffect = "copy";
    }
});

dropZone.addEventListener("dragleave", event => {
    /*
     * Prevent flickering when dragging over child elements.
     */
    if (!dropZone.contains(event.relatedTarget)) {
        dropZone.classList.remove("is-dragging");
    }
});

dropZone.addEventListener("drop", event => {
    event.preventDefault();
    dropZone.classList.remove("is-dragging");

    handleFiles(event.dataTransfer.files);
});

selectedFiles.addEventListener("click", event => {
    const removeButton = event.target.closest(
        ".remove-file-btn"
    );

    if (!removeButton) {
        return;
    }

    const fileIndex = Number(
        removeButton.dataset.fileIndex
    );

    loadedFiles.splice(fileIndex, 1);
    renderSelectedFiles();
});