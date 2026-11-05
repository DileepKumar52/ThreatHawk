/**
 * ThreatHawk Data Encoder, Decoder & JWT Inspector
 * 100% crash-free UTF-8 conversions, format auto-detection, and JWT payload decoding.
 */

"use strict";

(function () {
    const inputText = document.getElementById("inputText");
    const outputText = document.getElementById("outputText");
    const swapBtn = document.getElementById("swapBtn");
    const clearBtn = document.getElementById("clearBtn");
    const copyOutputBtn = document.getElementById("copyOutputBtn");
    const downloadOutputBtn = document.getElementById("downloadOutputBtn");

    const inputCharCount = document.getElementById("inputCharCount");
    const inputByteCount = document.getElementById("inputByteCount");
    const outputCharCount = document.getElementById("outputCharCount");
    const outputByteCount = document.getElementById("outputByteCount");

    const jwtInspectorCard = document.getElementById("jwtInspectorCard");
    const jwtHeaderBox = document.getElementById("jwtHeaderBox");
    const jwtPayloadBox = document.getElementById("jwtPayloadBox");
    const jwtMetaBox = document.getElementById("jwtMetaBox");

    let currentFormat = "base64";
    let currentOperation = "encode"; // "encode" or "decode"

    // --------------------------------------------------------------------------
    // 1. ROBUST UTF-8 SAFE ENCODING & DECODING
    // --------------------------------------------------------------------------
    const UTF8 = {
        // Base64 & Base64URL
        encodeBase64(str, urlSafe = false) {
            const bytes = new TextEncoder().encode(str);
            let bin = "";
            for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
            let b64 = btoa(bin);
            if (urlSafe) {
                b64 = b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
            }
            return b64;
        },

        decodeBase64(b64) {
            let clean = b64.trim().replace(/-/g, "+").replace(/_/g, "/");
            while (clean.length % 4 !== 0) clean += "=";
            const bin = atob(clean);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            return new TextDecoder().decode(bytes);
        },

        // Hexadecimal
        encodeHex(str) {
            const bytes = new TextEncoder().encode(str);
            return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join(" ");
        },

        decodeHex(hex) {
            const clean = hex.replace(/[\s0x\\,]/g, "");
            if (clean.length % 2 !== 0) throw new Error("Invalid hex string (uneven length)");
            const bytes = new Uint8Array(clean.length / 2);
            for (let i = 0; i < clean.length; i += 2) {
                const b = parseInt(clean.substring(i, i + 2), 16);
                if (isNaN(b)) throw new Error("Invalid hex character detected");
                bytes[i / 2] = b;
            }
            return new TextDecoder().decode(bytes);
        },

        // URL / Percent Encoding
        encodeURL(str) {
            return encodeURIComponent(str);
        },

        decodeURL(str) {
            return decodeURIComponent(str);
        },

        // HTML Entities
        encodeHTML(str) {
            return str.replace(/[\u00A0-\u9999<>\&"']/gim, i => '&#' + i.charCodeAt(0) + ';');
        },

        decodeHTML(str) {
            const doc = new DOMParser().parseFromString(str, "text/html");
            return doc.documentElement.textContent || "";
        },

        // Binary (8-bit)
        encodeBinary(str) {
            const bytes = new TextEncoder().encode(str);
            return Array.from(bytes).map(b => b.toString(2).padStart(8, "0")).join(" ");
        },

        decodeBinary(bin) {
            const clean = bin.replace(/[\s]/g, "");
            if (clean.length % 8 !== 0) throw new Error("Binary string length must be a multiple of 8");
            const bytes = new Uint8Array(clean.length / 8);
            for (let i = 0; i < clean.length; i += 8) {
                const byteVal = parseInt(clean.substring(i, i + 8), 2);
                if (isNaN(byteVal)) throw new Error("Invalid binary character");
                bytes[i / 8] = byteVal;
            }
            return new TextDecoder().decode(bytes);
        },

        // ROT13
        rot13(str) {
            return str.replace(/[a-zA-Z]/g, c => {
                const code = c.charCodeAt(0);
                const base = code >= 97 ? 97 : 65;
                return String.fromCharCode(((code - base + 13) % 26) + base);
            });
        }
    };

    // --------------------------------------------------------------------------
    // 2. JWT INSPECTION ENGINE
    // --------------------------------------------------------------------------
    function inspectJWT(str) {
        const parts = str.trim().split(".");
        if (parts.length !== 3) return null;

        try {
            const headerJson = UTF8.decodeBase64(parts[0]);
            const payloadJson = UTF8.decodeBase64(parts[1]);

            const header = JSON.parse(headerJson);
            const payload = JSON.parse(payloadJson);

            // Decode dates in payload
            const meta = [];
            if (payload.iat) meta.push(`Issued At (iat): ${new Date(payload.iat * 1000).toUTCString()}`);
            if (payload.exp) {
                const expDate = new Date(payload.exp * 1000);
                const isExpired = Date.now() > expDate.getTime();
                meta.push(`Expires (exp): ${expDate.toUTCString()} ${isExpired ? "(EXPIRED)" : "(ACTIVE)"}`);
            }
            if (payload.nbf) meta.push(`Not Before (nbf): ${new Date(payload.nbf * 1000).toUTCString()}`);

            return {
                header: JSON.stringify(header, null, 2),
                payload: JSON.stringify(payload, null, 2),
                meta: meta.join("\n") || "No standard exp/iat timestamps found."
            };
        } catch (e) {
            return null;
        }
    }

    // --------------------------------------------------------------------------
    // 3. TRANSFORMATION CONTROLLER
    // --------------------------------------------------------------------------
    function performTransformation() {
        const input = inputText.value;

        // Update input counters
        if (inputCharCount) inputCharCount.textContent = `${input.length} chars`;
        if (inputByteCount) inputByteCount.textContent = `${new TextEncoder().encode(input).length} bytes`;

        if (!input) {
            outputText.value = "";
            if (outputCharCount) outputCharCount.textContent = "0 chars";
            if (outputByteCount) outputByteCount.textContent = "0 bytes";
            if (jwtInspectorCard) jwtInspectorCard.style.display = "none";
            return;
        }

        // Check if JWT token is provided
        const jwtData = inspectJWT(input);
        if (jwtData && (currentFormat === "jwt" || currentFormat === "base64url" || currentFormat === "base64")) {
            if (jwtInspectorCard) {
                jwtInspectorCard.style.display = "flex";
                if (jwtHeaderBox) jwtHeaderBox.textContent = jwtData.header;
                if (jwtPayloadBox) jwtPayloadBox.textContent = jwtData.payload;
                if (jwtMetaBox) jwtMetaBox.textContent = jwtData.meta;
            }
        } else {
            if (jwtInspectorCard) jwtInspectorCard.style.display = "none";
        }

        try {
            let result = "";

            if (currentFormat === "jwt") {
                if (jwtData) {
                    result = `// HEADER:\n${jwtData.header}\n\n// PAYLOAD:\n${jwtData.payload}\n\n// TIMESTAMPS:\n${jwtData.meta}`;
                } else {
                    result = "Invalid JWT token structure (must have 3 base64url segments separated by dots).";
                }
            } else if (currentOperation === "encode") {
                switch (currentFormat) {
                    case "base64": result = UTF8.encodeBase64(input, false); break;
                    case "base64url": result = UTF8.encodeBase64(input, true); break;
                    case "hex": result = UTF8.encodeHex(input); break;
                    case "url": result = UTF8.encodeURL(input); break;
                    case "html": result = UTF8.encodeHTML(input); break;
                    case "binary": result = UTF8.encodeBinary(input); break;
                    case "rot13": result = UTF8.rot13(input); break;
                    default: result = input;
                }
            } else {
                switch (currentFormat) {
                    case "base64": result = UTF8.decodeBase64(input); break;
                    case "base64url": result = UTF8.decodeBase64(input); break;
                    case "hex": result = UTF8.decodeHex(input); break;
                    case "url": result = UTF8.decodeURL(input); break;
                    case "html": result = UTF8.decodeHTML(input); break;
                    case "binary": result = UTF8.decodeBinary(input); break;
                    case "rot13": result = UTF8.rot13(input); break;
                    default: result = input;
                }
            }

            outputText.value = result;
            if (outputCharCount) outputCharCount.textContent = `${result.length} chars`;
            if (outputByteCount) outputByteCount.textContent = `${new TextEncoder().encode(result).length} bytes`;
        } catch (err) {
            outputText.value = `[Error: ${err.message}]`;
        }
    }

    // --------------------------------------------------------------------------
    // 4. EVENT LISTENERS
    // --------------------------------------------------------------------------
    document.addEventListener("DOMContentLoaded", () => {
        if (!inputText) return;

        inputText.addEventListener("input", performTransformation);

        // Format selector pills
        document.querySelectorAll(".format-pill-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                document.querySelectorAll(".format-pill-btn").forEach(b => b.classList.remove("active"));
                btn.classList.add("active");
                currentFormat = btn.dataset.format || "base64";
                performTransformation();
            });
        });

        // Operation toggle buttons (Encode / Decode)
        const opEncode = document.getElementById("opEncode");
        const opDecode = document.getElementById("opDecode");

        if (opEncode && opDecode) {
            opEncode.addEventListener("click", () => {
                opEncode.classList.add("active");
                opDecode.classList.remove("active");
                currentOperation = "encode";
                performTransformation();
            });

            opDecode.addEventListener("click", () => {
                opDecode.classList.add("active");
                opEncode.classList.remove("active");
                currentOperation = "decode";
                performTransformation();
            });
        }

        // Swap button
        if (swapBtn) {
            swapBtn.addEventListener("click", () => {
                const currentOutput = outputText.value;
                if (!currentOutput || currentOutput.startsWith("[Error:")) return;
                inputText.value = currentOutput;
                // Invert operation
                if (currentOperation === "encode") {
                    opDecode?.click();
                } else {
                    opEncode?.click();
                }
                if (window.ThreatHawk) window.ThreatHawk.toast("Swapped input and output", "fa-arrow-right-arrow-left");
            });
        }

        // Clear button
        if (clearBtn) {
            clearBtn.addEventListener("click", () => {
                inputText.value = "";
                outputText.value = "";
                performTransformation();
                inputText.focus();
                if (window.ThreatHawk) window.ThreatHawk.toast("Cleared editors", "fa-rotate-left");
            });
        }

        // Copy button
        if (copyOutputBtn) {
            copyOutputBtn.addEventListener("click", async () => {
                if (!outputText.value) {
                    if (window.ThreatHawk) window.ThreatHawk.toast("No output to copy", "fa-triangle-exclamation");
                    return;
                }
                if (window.ThreatHawk) {
                    await window.ThreatHawk.copyToClipboard(outputText.value, "Output copied to clipboard");
                }
            });
        }

        // Download button
        if (downloadOutputBtn) {
            downloadOutputBtn.addEventListener("click", () => {
                if (!outputText.value) return;
                const blob = new Blob([outputText.value], { type: "text/plain;charset=utf-8" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `threathawk-${currentFormat}-${currentOperation}.txt`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            });
        }

        performTransformation();
    });
})();
