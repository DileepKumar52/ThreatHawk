"use strict";

/* =========================================================
   ThreatHawk Encoder & Decoder
   Part 1: Application State, DOM and UI Helpers
========================================================= */


/* =========================================================
   DOM Elements
========================================================= */

const themeToggle = document.getElementById("themeToggle");

const formatSelect = document.getElementById("formatSelect");

const encodeOperation = document.getElementById("encodeOperation");
const decodeOperation = document.getElementById("decodeOperation");

const operationOptions = document.querySelectorAll(
    ".operation-option"
);

const inputText = document.getElementById("inputText");
const outputText = document.getElementById("outputText");

const inputPanelTitle = document.getElementById(
    "inputPanelTitle"
);

const outputPanelTitle = document.getElementById(
    "outputPanelTitle"
);

const inputCharacterCount = document.getElementById(
    "inputCharacterCount"
);

const inputByteCount = document.getElementById(
    "inputByteCount"
);

const outputCharacterCount = document.getElementById(
    "outputCharacterCount"
);

const outputByteCount = document.getElementById(
    "outputByteCount"
);

const pasteBtn = document.getElementById("pasteBtn");
const clearInputBtn = document.getElementById(
    "clearInputBtn"
);

const copyOutputBtn = document.getElementById(
    "copyOutputBtn"
);

const downloadOutputBtn = document.getElementById(
    "downloadOutputBtn"
);

const convertBtn = document.getElementById("convertBtn");
const swapBtn = document.getElementById("swapBtn");
const clearAllBtn = document.getElementById("clearAllBtn");

const conversionStatus = document.getElementById(
    "conversionStatus"
);

const statusIcon = document.getElementById("statusIcon");
const statusText = document.getElementById("statusText");

const selectedFormatStatus = document.getElementById(
    "selectedFormatStatus"
);

const selectedOperationStatus = document.getElementById(
    "selectedOperationStatus"
);

const conversionTime = document.getElementById(
    "conversionTime"
);

const toast = document.getElementById("toast");
const toastIcon = document.getElementById("toastIcon");
const toastMessage = document.getElementById(
    "toastMessage"
);


/* =========================================================
   Application State
========================================================= */

const appState = {
    format: "base64",
    operation: "encode",
    lastConversionTime: 0,
    toastTimer: null
};


/* =========================================================
   Format Configuration
========================================================= */

const formatConfig = {
    base64: {
        name: "Base64",
        encodeInputTitle: "Plain Text",
        encodeOutputTitle: "Base64 Encoded Text",
        decodeInputTitle: "Base64 Encoded Text",
        decodeOutputTitle: "Decoded Text",
        encodePlaceholder: "Enter or paste plain text here...",
        decodePlaceholder: "Enter or paste Base64 data here...",
        supportsDecode: true
    },

    base64url: {
        name: "Base64 URL",
        encodeInputTitle: "Plain Text",
        encodeOutputTitle: "Base64 URL Encoded Text",
        decodeInputTitle: "Base64 URL Encoded Text",
        decodeOutputTitle: "Decoded Text",
        encodePlaceholder: "Enter or paste plain text here...",
        decodePlaceholder: "Enter Base64 URL-safe data here...",
        supportsDecode: true
    },

    url: {
        name: "URL Encoding",
        encodeInputTitle: "Plain Text or URL Data",
        encodeOutputTitle: "URL Encoded Text",
        decodeInputTitle: "URL Encoded Text",
        decodeOutputTitle: "Decoded Text",
        encodePlaceholder: "Enter text, a URL or query value...",
        decodePlaceholder: "Enter URL-encoded data here...",
        supportsDecode: true
    },

    html: {
        name: "HTML Entities",
        encodeInputTitle: "HTML or Plain Text",
        encodeOutputTitle: "HTML Entity Encoded Text",
        decodeInputTitle: "HTML Entity Encoded Text",
        decodeOutputTitle: "Decoded HTML Text",
        encodePlaceholder: "Enter HTML or plain text here...",
        decodePlaceholder: "Enter HTML entities here...",
        supportsDecode: true
    },

    hex: {
        name: "Hexadecimal",
        encodeInputTitle: "Plain Text",
        encodeOutputTitle: "Hexadecimal Data",
        decodeInputTitle: "Hexadecimal Data",
        decodeOutputTitle: "Decoded Text",
        encodePlaceholder: "Enter or paste plain text here...",
        decodePlaceholder: "Enter hexadecimal values here...",
        supportsDecode: true
    },

    binary: {
        name: "Binary",
        encodeInputTitle: "Plain Text",
        encodeOutputTitle: "Binary Data",
        decodeInputTitle: "Binary Data",
        decodeOutputTitle: "Decoded Text",
        encodePlaceholder: "Enter or paste plain text here...",
        decodePlaceholder: "Enter binary byte values here...",
        supportsDecode: true
    },

    rot13: {
        name: "ROT13",
        encodeInputTitle: "Original Text",
        encodeOutputTitle: "ROT13 Transformed Text",
        decodeInputTitle: "ROT13 Text",
        decodeOutputTitle: "Original Text",
        encodePlaceholder: "Enter text to transform with ROT13...",
        decodePlaceholder: "Enter ROT13 text to reverse...",
        supportsDecode: true
    }
};


/* =========================================================
   General Helpers
========================================================= */

function getByteCount(value) {
    return new TextEncoder().encode(value).length;
}


function getCurrentOperation() {
    return decodeOperation.checked
        ? "decode"
        : "encode";
}


function getCurrentFormat() {
    return formatSelect.value;
}


function capitalize(value) {
    if (!value) {
        return "";
    }

    return value.charAt(0).toUpperCase() + value.slice(1);
}


/* =========================================================
   Counter Helpers
========================================================= */

function updateInputCounters() {
    const value = inputText.value;

    inputCharacterCount.textContent = value.length;
    inputByteCount.textContent = getByteCount(value);
}


function updateOutputCounters() {
    const value = outputText.value;

    outputCharacterCount.textContent = value.length;
    outputByteCount.textContent = getByteCount(value);
}


function updateAllCounters() {
    updateInputCounters();
    updateOutputCounters();
}


/* =========================================================
   Toast Notifications
========================================================= */

function showToast(
    message,
    type = "success"
) {
    if (!toast || !toastMessage || !toastIcon) {
        return;
    }

    if (appState.toastTimer) {
        window.clearTimeout(appState.toastTimer);
    }

    toastMessage.textContent = message;

    toastIcon.className = "";

    const iconClasses = {
        success: "fa-solid fa-check",
        error: "fa-solid fa-triangle-exclamation",
        warning: "fa-solid fa-circle-exclamation",
        info: "fa-solid fa-circle-info"
    };

    toastIcon.className =
        iconClasses[type] || iconClasses.info;

    toast.dataset.type = type;
    toast.classList.add("show");

    appState.toastTimer = window.setTimeout(() => {
        toast.classList.remove("show");
    }, 2800);
}


/* =========================================================
   Status Helpers
========================================================= */

function updateStatus({
    message,
    type = "info",
    time = null
}) {
    const statusIcons = {
        info: "fa-solid fa-circle-info",
        success: "fa-solid fa-circle-check",
        error: "fa-solid fa-triangle-exclamation",
        warning: "fa-solid fa-circle-exclamation",
        processing: "fa-solid fa-spinner fa-spin"
    };

    statusText.textContent = message;

    statusIcon.className =
        statusIcons[type] || statusIcons.info;

    conversionStatus.dataset.status = type;

    selectedFormatStatus.textContent =
        formatConfig[appState.format]?.name ||
        capitalize(appState.format);

    selectedOperationStatus.textContent =
        capitalize(appState.operation);

    if (typeof time === "number") {
        conversionTime.textContent =
            `${time.toFixed(2)} ms`;
    }
}


function setWaitingStatus() {
    appState.lastConversionTime = 0;

    conversionTime.textContent = "0 ms";

    updateStatus({
        message: "Waiting for input",
        type: "info"
    });
}


function setProcessingStatus() {
    updateStatus({
        message: "Converting data...",
        type: "processing"
    });
}


function setSuccessStatus(time) {
    appState.lastConversionTime = time;

    updateStatus({
        message: "Conversion completed successfully",
        type: "success",
        time
    });
}


function setErrorStatus(message) {
    appState.lastConversionTime = 0;
    conversionTime.textContent = "0 ms";

    updateStatus({
        message,
        type: "error"
    });
}


/* =========================================================
   Output Button State
========================================================= */

function updateOutputButtons() {
    const hasOutput = outputText.value.length > 0;

    copyOutputBtn.disabled = !hasOutput;
    downloadOutputBtn.disabled = !hasOutput;
}


/* =========================================================
   Dynamic Panel Labels
========================================================= */

function updatePanelLabels() {
    appState.format = getCurrentFormat();
    appState.operation = getCurrentOperation();

    const config = formatConfig[appState.format];

    if (!config) {
        return;
    }

    const isDecode = appState.operation === "decode";

    inputPanelTitle.textContent = isDecode
        ? config.decodeInputTitle
        : config.encodeInputTitle;

    outputPanelTitle.textContent = isDecode
        ? config.decodeOutputTitle
        : config.encodeOutputTitle;

    inputText.placeholder = isDecode
        ? config.decodePlaceholder
        : config.encodePlaceholder;

    selectedFormatStatus.textContent = config.name;

    selectedOperationStatus.textContent =
        capitalize(appState.operation);

    operationOptions.forEach((option) => {
        const radio = option.querySelector(
            'input[type="radio"]'
        );

        option.classList.toggle(
            "active",
            Boolean(radio?.checked)
        );
    });
}


/* =========================================================
   Theme Management
========================================================= */

function updateThemeButton(isLightTheme) {
    if (!themeToggle) {
        return;
    }

    const icon = themeToggle.querySelector("i");
    const label = themeToggle.querySelector("span");

    if (isLightTheme) {
        icon.className = "fa-regular fa-moon";
        label.textContent = "Dark Mode";

        themeToggle.setAttribute(
            "aria-label",
            "Switch to dark mode"
        );
    } else {
        icon.className = "fa-regular fa-sun";
        label.textContent = "Light Mode";

        themeToggle.setAttribute(
            "aria-label",
            "Switch to light mode"
        );
    }
}


function initializeTheme() {
    const savedTheme =
        localStorage.getItem("threathawk-theme");

    const prefersLight =
        window.matchMedia &&
        window.matchMedia(
            "(prefers-color-scheme: light)"
        ).matches;

    const shouldUseLightTheme =
        savedTheme === "light" ||
        (!savedTheme && prefersLight);

    document.body.classList.toggle(
        "light-theme",
        shouldUseLightTheme
    );

    updateThemeButton(shouldUseLightTheme);
}


function toggleTheme() {
    const isLightTheme =
        document.body.classList.toggle(
            "light-theme"
        );

    localStorage.setItem(
        "threathawk-theme",
        isLightTheme ? "light" : "dark"
    );

    updateThemeButton(isLightTheme);

    showToast(
        `${isLightTheme ? "Light" : "Dark"} mode enabled`,
        "info"
    );
}


/* =========================================================
   Reset Output
========================================================= */

function resetOutput({
    preserveStatus = false
} = {}) {
    outputText.value = "";

    updateOutputCounters();
    updateOutputButtons();

    if (!preserveStatus) {
        setWaitingStatus();
    }
}

/* =========================================================
   Part 2: Conversion Engine
========================================================= */


/* =========================================================
   UTF-8 Helpers
========================================================= */

function utf8ToBase64(text) {
    const bytes = new TextEncoder().encode(text);

    let binary = "";

    bytes.forEach(byte => {
        binary += String.fromCharCode(byte);
    });

    return btoa(binary);
}


function base64ToUtf8(base64) {
    const binary = atob(base64);

    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));

    return new TextDecoder().decode(bytes);
}


/* =========================================================
   Base64
========================================================= */

function encodeBase64(text) {
    return utf8ToBase64(text);
}


function decodeBase64(text) {

    const clean = text.trim();

    if (!clean) {
        throw new Error("Please enter Base64 data.");
    }

    return base64ToUtf8(clean);
}


/* =========================================================
   Base64 URL
========================================================= */

function encodeBase64URL(text) {

    return encodeBase64(text)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}


function decodeBase64URL(text) {

    let value = text.trim()
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    while (value.length % 4 !== 0) {
        value += "=";
    }

    return decodeBase64(value);
}


/* =========================================================
   URL Encoding
========================================================= */

function encodeURL(text) {
    return encodeURIComponent(text);
}


function decodeURL(text) {
    return decodeURIComponent(text);
}


/* =========================================================
   HTML Entities
========================================================= */

function encodeHTML(text) {

    const div = document.createElement("div");

    div.textContent = text;

    return div.innerHTML;
}


function decodeHTML(text) {

    const textarea = document.createElement("textarea");

    textarea.innerHTML = text;

    return textarea.value;
}


/* =========================================================
   Hex
========================================================= */

function encodeHex(text) {

    return Array.from(
        new TextEncoder().encode(text)
    )
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join(" ");
}


function decodeHex(text) {

    const clean = text
        .trim()
        .replace(/\s+/g, " ");

    if (!clean.length) {
        throw new Error("Please enter hexadecimal data.");
    }

    const bytes = clean
        .split(" ")
        .map(hex => {

            if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
                throw new Error("Invalid hexadecimal value.");
            }

            return parseInt(hex, 16);
        });

    return new TextDecoder().decode(
        new Uint8Array(bytes)
    );
}


/* =========================================================
   Binary
========================================================= */

function encodeBinary(text) {

    return Array.from(
        new TextEncoder().encode(text)
    )
        .map(byte => byte.toString(2).padStart(8, "0"))
        .join(" ");
}


function decodeBinary(text) {

    const clean = text
        .trim()
        .replace(/\s+/g, " ");

    if (!clean.length) {
        throw new Error("Please enter binary data.");
    }

    const bytes = clean
        .split(" ")
        .map(binary => {

            if (!/^[01]{8}$/.test(binary)) {
                throw new Error("Invalid binary byte.");
            }

            return parseInt(binary, 2);
        });

    return new TextDecoder().decode(
        new Uint8Array(bytes)
    );
}


/* =========================================================
   ROT13
========================================================= */

function rot13(text) {

    return text.replace(/[a-zA-Z]/g, character => {

        const base =
            character <= "Z"
                ? 65
                : 97;

        return String.fromCharCode(
            ((character.charCodeAt(0) - base + 13) % 26) + base
        );

    });

}


/* =========================================================
   Conversion Dispatcher
========================================================= */

function performConversion() {

    const format = appState.format;

    const operation = appState.operation;

    const value = inputText.value;

    switch (format) {

        case "base64":

            return operation === "encode"
                ? encodeBase64(value)
                : decodeBase64(value);

        case "base64url":

            return operation === "encode"
                ? encodeBase64URL(value)
                : decodeBase64URL(value);

        case "url":

            return operation === "encode"
                ? encodeURL(value)
                : decodeURL(value);

        case "html":

            return operation === "encode"
                ? encodeHTML(value)
                : decodeHTML(value);

        case "hex":

            return operation === "encode"
                ? encodeHex(value)
                : decodeHex(value);

        case "binary":

            return operation === "encode"
                ? encodeBinary(value)
                : decodeBinary(value);

        case "rot13":

            return rot13(value);

        default:

            throw new Error("Unsupported conversion format.");

    }

}


/* =========================================================
   Validation
========================================================= */

function validateInput() {

    if (!inputText.value.trim()) {

        throw new Error(
            "Please enter some text before converting."
        );

    }

}

/* =========================================================
   Part 3A: Application Actions and Event Handlers
========================================================= */


/* =========================================================
   Convert Handler
========================================================= */

function handleConvert() {
    try {
        validateInput();

        appState.format = getCurrentFormat();
        appState.operation = getCurrentOperation();

        setProcessingStatus();

        const startTime = performance.now();

        const result = performConversion();

        const endTime = performance.now();
        const elapsedTime = endTime - startTime;

        outputText.value = result;

        updateOutputCounters();
        updateOutputButtons();

        setSuccessStatus(elapsedTime);

        showToast(
            `${formatConfig[appState.format].name} conversion completed`,
            "success"
        );
    } catch (error) {
        outputText.value = "";

        updateOutputCounters();
        updateOutputButtons();

        const message =
            error instanceof Error
                ? error.message
                : "Conversion failed.";

        setErrorStatus(message);
        showToast(message, "error");
    }
}


/* =========================================================
   Paste Handler
========================================================= */

async function handlePaste() {
    try {
        if (!navigator.clipboard) {
            throw new Error(
                "Clipboard access is not supported in this browser."
            );
        }

        const clipboardText =
            await navigator.clipboard.readText();

        if (!clipboardText) {
            showToast(
                "Your clipboard is empty.",
                "warning"
            );

            return;
        }

        inputText.value = clipboardText;

        updateInputCounters();

        resetOutput();

        showToast(
            "Clipboard content pasted.",
            "success"
        );

        inputText.focus();
    } catch (error) {
        const message =
            error instanceof Error
                ? error.message
                : "Unable to read clipboard.";

        showToast(message, "error");
    }
}


/* =========================================================
   Copy Output Handler
========================================================= */

async function handleCopyOutput() {
    const value = outputText.value;

    if (!value) {
        showToast(
            "There is no output to copy.",
            "warning"
        );

        return;
    }

    try {
        if (navigator.clipboard) {
            await navigator.clipboard.writeText(value);
        } else {
            outputText.select();

            const successful =
                document.execCommand("copy");

            if (!successful) {
                throw new Error(
                    "Copy command was unsuccessful."
                );
            }

            window.getSelection()?.removeAllRanges();
        }

        showToast(
            "Output copied to clipboard.",
            "success"
        );
    } catch (error) {
        const message =
            error instanceof Error
                ? error.message
                : "Unable to copy output.";

        showToast(message, "error");
    }
}


/* =========================================================
   Download Handler
========================================================= */

function handleDownloadOutput() {
    const value = outputText.value;

    if (!value) {
        showToast(
            "There is no output to download.",
            "warning"
        );

        return;
    }

    try {
        const formatName =
            appState.format || "converted";

        const operationName =
            appState.operation || "output";

        const fileName =
            `threathawk-${formatName}-${operationName}.txt`;

        const blob = new Blob(
            [value],
            {
                type: "text/plain;charset=utf-8"
            }
        );

        const objectUrl =
            URL.createObjectURL(blob);

        const downloadLink =
            document.createElement("a");

        downloadLink.href = objectUrl;
        downloadLink.download = fileName;

        document.body.appendChild(downloadLink);

        downloadLink.click();
        downloadLink.remove();

        URL.revokeObjectURL(objectUrl);

        showToast(
            "Output downloaded successfully.",
            "success"
        );
    } catch (error) {
        const message =
            error instanceof Error
                ? error.message
                : "Unable to download output.";

        showToast(message, "error");
    }
}


/* =========================================================
   Clear Input Handler
========================================================= */

function handleClearInput() {
    if (!inputText.value) {
        showToast(
            "Input is already empty.",
            "info"
        );

        return;
    }

    inputText.value = "";

    updateInputCounters();

    resetOutput();

    inputText.focus();

    showToast(
        "Input cleared.",
        "success"
    );
}


/* =========================================================
   Clear All Handler
========================================================= */

function handleClearAll() {
    const alreadyEmpty =
        !inputText.value &&
        !outputText.value;

    inputText.value = "";
    outputText.value = "";

    updateAllCounters();
    updateOutputButtons();

    setWaitingStatus();

    inputText.focus();

    showToast(
        alreadyEmpty
            ? "Workspace is already empty."
            : "Workspace cleared.",
        alreadyEmpty ? "info" : "success"
    );
}


/* =========================================================
   Swap Handler
========================================================= */

function handleSwap() {
    const currentInput = inputText.value;
    const currentOutput = outputText.value;

    if (!currentInput && !currentOutput) {
        showToast(
            "There is nothing to swap.",
            "warning"
        );

        return;
    }

    inputText.value = currentOutput;
    outputText.value = currentInput;

    if (appState.operation === "encode") {
        decodeOperation.checked = true;
        encodeOperation.checked = false;
    } else {
        encodeOperation.checked = true;
        decodeOperation.checked = false;
    }

    appState.operation = getCurrentOperation();

    updatePanelLabels();
    updateAllCounters();
    updateOutputButtons();

    if (outputText.value) {
        updateStatus({
            message: "Input and output swapped",
            type: "info"
        });
    } else {
        setWaitingStatus();
    }

    inputText.focus();

    showToast(
        "Input and output swapped.",
        "success"
    );
}


/* =========================================================
   Input Change Handler
========================================================= */

function handleInputChange() {
    updateInputCounters();

    if (outputText.value) {
        resetOutput();
    } else {
        setWaitingStatus();
    }
}


/* =========================================================
   Format Change Handler
========================================================= */

function handleFormatChange() {
    appState.format = getCurrentFormat();

    updatePanelLabels();

    resetOutput();

    showToast(
        `${formatConfig[appState.format].name} selected`,
        "info"
    );
}


/* =========================================================
   Operation Change Handler
========================================================= */

function handleOperationChange() {
    appState.operation = getCurrentOperation();

    updatePanelLabels();

    resetOutput();

    showToast(
        `${capitalize(appState.operation)} mode selected`,
        "info"
    );
}


/* =========================================================
   Keyboard Shortcut Handler
========================================================= */

function handleKeyboardShortcuts(event) {
    const isControlPressed =
        event.ctrlKey || event.metaKey;

    if (
        isControlPressed &&
        event.key === "Enter"
    ) {
        event.preventDefault();
        handleConvert();
        return;
    }

    if (
        isControlPressed &&
        event.shiftKey &&
        event.key.toLowerCase() === "c"
    ) {
        event.preventDefault();
        handleCopyOutput();
        return;
    }

    if (
        event.key === "Escape" &&
        document.activeElement === inputText
    ) {
        inputText.blur();
    }
}

/* =========================================================
   Part 3B: Event Listeners & Application Initialization
========================================================= */


/* =========================================================
   Event Registration
========================================================= */

function registerEventListeners() {

    /* Theme */

    if (themeToggle) {
        themeToggle.addEventListener(
            "click",
            toggleTheme
        );
    }


    /* Format */

    formatSelect.addEventListener(
        "change",
        handleFormatChange
    );


    /* Operation */

    encodeOperation.addEventListener(
        "change",
        handleOperationChange
    );

    decodeOperation.addEventListener(
        "change",
        handleOperationChange
    );


    /* Input */

    inputText.addEventListener(
        "input",
        handleInputChange
    );


    inputText.addEventListener(
        "keydown",
        event => {

            if (
                (event.ctrlKey || event.metaKey) &&
                event.key === "Enter"
            ) {
                event.preventDefault();
                handleConvert();
            }

        }
    );


    /* Buttons */

    convertBtn.addEventListener(
        "click",
        handleConvert
    );

    pasteBtn.addEventListener(
        "click",
        handlePaste
    );

    clearInputBtn.addEventListener(
        "click",
        handleClearInput
    );

    copyOutputBtn.addEventListener(
        "click",
        handleCopyOutput
    );

    downloadOutputBtn.addEventListener(
        "click",
        handleDownloadOutput
    );

    swapBtn.addEventListener(
        "click",
        handleSwap
    );

    clearAllBtn.addEventListener(
        "click",
        handleClearAll
    );


    /* Global shortcuts */

    document.addEventListener(
        "keydown",
        handleKeyboardShortcuts
    );

}


/* =========================================================
   Initial UI State
========================================================= */

function initializeUI() {

    appState.format = getCurrentFormat();
    appState.operation = getCurrentOperation();

    updatePanelLabels();

    updateAllCounters();

    updateOutputButtons();

    setWaitingStatus();

}


/* =========================================================
   Browser Compatibility Check
========================================================= */

function performCompatibilityChecks() {

    if (!window.TextEncoder) {

        showToast(
            "Your browser does not support UTF-8 encoding.",
            "error"
        );

    }

    if (!window.TextDecoder) {

        showToast(
            "Your browser does not support UTF-8 decoding.",
            "error"
        );

    }

}


/* =========================================================
   Application Initialization
========================================================= */

function initializeApplication() {

    initializeTheme();

    initializeUI();

    registerEventListeners();

    performCompatibilityChecks();

    console.log(
        "%cThreatHawk Encoder & Decoder Loaded",
        "color:#e63946;font-size:14px;font-weight:bold;"
    );

    console.log(
        "Ready to transform data locally."
    );

}


/* =========================================================
   DOM Ready
========================================================= */

if (
    document.readyState === "loading"
) {

    document.addEventListener(
        "DOMContentLoaded",
        initializeApplication
    );

} else {

    initializeApplication();

}