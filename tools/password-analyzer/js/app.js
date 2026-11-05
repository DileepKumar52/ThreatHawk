/**
 * ThreatHawk Password Intelligence
 * High-precision entropy analysis, multi-tier offline crack estimation, pattern detection, and secure generator.
 */

"use strict";

(function () {
    const passwordInput = document.getElementById("passwordInput");
    const togglePassword = document.getElementById("togglePassword");
    const copyPassword = document.getElementById("copyPassword");
    const generatePassword = document.getElementById("generatePassword");
    const strengthPercent = document.getElementById("strengthPercent");
    const strengthText = document.getElementById("strengthText");
    const resultContent = document.getElementById("resultContent");
    const suggestionsContent = document.getElementById("suggestionsContent");
    const meterBar = document.getElementById("meterBar");

    const requirementElements = {
        length: document.getElementById("reqLength"),
        upper: document.getElementById("reqUpper"),
        lower: document.getElementById("reqLower"),
        number: document.getElementById("reqNumber"),
        special: document.getElementById("reqSpecial")
    };

    const REQUIREMENT_LABELS = {
        length: "At least 8 characters",
        upper: "One uppercase letter",
        lower: "One lowercase letter",
        number: "One number",
        special: "One special character"
    };

    const COMMON_PASSWORDS = new Set([
        "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
        "111111", "1234567", "dragon", "123123", "baseball", "football", "iloveyou",
        "letmein", "monkey", "sunshine", "princess", "shadow", "master", "superman",
        "welcome", "login", "admin", "admin123", "password123", "passw0rd", "p@ssword",
        "p@ssw0rd", "asdfgh", "zxcvbn", "1q2w3e", "1qaz2wsx", "trustno1"
    ]);

    const PREDICTABLE_WORDS = [
        "password", "admin", "qwerty", "welcome", "login", "letmein", "user",
        "guest", "default", "system", "service", "summer", "winter", "spring", "autumn"
    ];

    let selectedGeneratorLength = 18;

    // --------------------------------------------------------------------------
    // 1. REQUIREMENTS & ENTROPY
    // --------------------------------------------------------------------------
    function evaluateRequirements(password) {
        return {
            length: password.length >= 8,
            upper: /[A-Z]/.test(password),
            lower: /[a-z]/.test(password),
            number: /[0-9]/.test(password),
            special: /[^A-Za-z0-9]/.test(password)
        };
    }

    function getCharacterSetPool(password) {
        let pool = 0;
        if (/[a-z]/.test(password)) pool += 26;
        if (/[A-Z]/.test(password)) pool += 26;
        if (/[0-9]/.test(password)) pool += 10;
        if (/[^A-Za-z0-9]/.test(password)) pool += 33;
        return pool;
    }

    function calculateEntropy(password) {
        const pool = getCharacterSetPool(password);
        if (password.length === 0 || pool === 0) return 0;
        return Math.round(password.length * Math.log2(pool) * 10) / 10;
    }

    // --------------------------------------------------------------------------
    // 2. PATTERN DETECTION
    // --------------------------------------------------------------------------
    function detectPatterns(password) {
        const lower = password.toLowerCase();
        const patterns = {
            commonPassword: COMMON_PASSWORDS.has(lower),
            predictableWord: PREDICTABLE_WORDS.find(w => lower.includes(w)) || null,
            numberSequence: /(?:0123|1234|2345|3456|4567|5678|6789|7890)/.test(lower),
            reverseNumberSequence: /(?:9876|8765|7654|6543|5432|4321|3210)/.test(lower),
            yearPattern: /(?:19[5-9]\d|20[0-3]\d)/.test(lower),
            keyboardSequence: /(?:qwerty|asdf|zxcv|qazwsx)/.test(lower),
            repeatedCharacters: /(.)\1{2,}/.test(password),
            repeatedBlock: /(.{2,4})\1{1,}/i.test(password),
            onlyLetters: /^[a-z]+$/i.test(password),
            onlyNumbers: /^\d+$/.test(password),
            lowUniqueness: false
        };

        if (password.length >= 8) {
            const uniqueChars = new Set(password).size;
            patterns.lowUniqueness = (uniqueChars / password.length) < 0.55;
        }

        return patterns;
    }

    // --------------------------------------------------------------------------
    // 3. STRENGTH SCORE CALCULATION
    // --------------------------------------------------------------------------
    function calculateStrengthScore(password, reqs, patterns) {
        if (!password) return 0;
        if (patterns.commonPassword) return 5;

        let score = 0;

        // Length tiers
        if (password.length >= 8) score += 15;
        if (password.length >= 12) score += 15;
        if (password.length >= 16) score += 15;
        if (password.length >= 20) score += 10;

        // Character diversity
        let types = 0;
        if (reqs.lower) types++;
        if (reqs.upper) types++;
        if (reqs.number) types++;
        if (reqs.special) types++;
        score += types * 5;

        // Uniqueness ratio
        const uniqueRatio = new Set(password).size / password.length;
        score += Math.round(uniqueRatio * 20);

        // Pattern penalties
        if (patterns.predictableWord) score -= 15;
        if (patterns.numberSequence || patterns.reverseNumberSequence) score -= 15;
        if (patterns.yearPattern) score -= 10;
        if (patterns.keyboardSequence) score -= 15;
        if (patterns.repeatedCharacters) score -= 15;
        if (patterns.repeatedBlock) score -= 10;
        if (patterns.onlyNumbers) score -= 20;
        if (patterns.onlyLetters) score -= 10;
        if (patterns.lowUniqueness) score -= 10;

        return Math.max(0, Math.min(100, score));
    }

    // --------------------------------------------------------------------------
    // 4. MULTI-TIER CRACK-TIME ESTIMATIONS
    // --------------------------------------------------------------------------
    function estimateCrackTimes(password, patterns) {
        const pool = getCharacterSetPool(password);
        if (!password || pool === 0) {
            return {
                online: "Instant",
                gpuFast: "Instant",
                slowHash: "Instant"
            };
        }

        if (patterns.commonPassword) {
            return {
                online: "Instant (Wordlist)",
                gpuFast: "Instant (<1 ms)",
                slowHash: "Instant (<1 sec)"
            };
        }

        let log10Combinations = password.length * Math.log10(pool);
        // Pattern reduction adjustments
        if (patterns.predictableWord) log10Combinations -= 3;
        if (patterns.numberSequence || patterns.reverseNumberSequence) log10Combinations -= 2.5;
        if (patterns.keyboardSequence) log10Combinations -= 3;
        if (patterns.repeatedCharacters) log10Combinations -= 2;
        if (patterns.lowUniqueness) log10Combinations -= 2;
        log10Combinations = Math.max(0, log10Combinations - Math.log10(2)); // average case

        // Rates:
        // Online Throttled (e.g. 100 guesses/sec = 10^2)
        const logSecondsOnline = log10Combinations - 2;
        // Offline Fast (e.g., 8x GPU rig cracking MD5/NTLM: 100 Billion/sec = 10^11)
        const logSecondsGPU = log10Combinations - 11;
        // Offline Slow (e.g., Bcrypt/Argon2: 10,000/sec = 10^4)
        const logSecondsSlow = log10Combinations - 4;

        return {
            online: formatSeconds(logSecondsOnline),
            gpuFast: formatSeconds(logSecondsGPU),
            slowHash: formatSeconds(logSecondsSlow)
        };
    }

    function formatSeconds(log10Sec) {
        if (!Number.isFinite(log10Sec) || log10Sec <= 0) return "Instant (< 1s)";
        const sec = Math.pow(10, Math.min(log10Sec, 15));

        if (sec < 60) return `${Math.round(sec)} seconds`;
        if (sec < 3600) return `${Math.round(sec / 60)} minutes`;
        if (sec < 86400) return `${Math.round(sec / 3600)} hours`;
        if (sec < 31536000) return `${Math.round(sec / 86400)} days`;

        const years = sec / 31536000;
        if (years < 1000) return `${Math.round(years)} years`;
        if (years < 1000000) return `${(years / 1000).toFixed(1)}k years`;
        if (years < 1000000000) return `${(years / 1000000).toFixed(1)}M years`;
        return `> ${Math.round(log10Sec - 7.5)} orders of magnitude years`;
    }

    // --------------------------------------------------------------------------
    // 5. SECURE GENERATOR (Web Crypto API)
    // --------------------------------------------------------------------------
    function generateSecurePassword(length = 18) {
        const lower = "abcdefghijkmnopqrstuvwxyz";
        const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        const nums = "23456789";
        const syms = "!@#$%^&*()-_=+[]{}";
        const all = lower + upper + nums + syms;

        const array = new Uint32Array(length);
        window.crypto.getRandomValues(array);

        const chars = [
            lower[array[0] % lower.length],
            upper[array[1] % upper.length],
            nums[array[2] % nums.length],
            syms[array[3] % syms.length]
        ];

        for (let i = 4; i < length; i++) {
            chars.push(all[array[i] % all.length]);
        }

        // Shuffle using Fisher-Yates with crypto random
        for (let i = chars.length - 1; i > 0; i--) {
            const j = array[i] % (i + 1);
            const temp = chars[i];
            chars[i] = chars[j];
            chars[j] = temp;
        }

        return chars.join("");
    }

    // --------------------------------------------------------------------------
    // 6. UI UPDATE PIPELINE
    // --------------------------------------------------------------------------
    function analyzePassword() {
        const pwd = passwordInput.value;
        const reqs = evaluateRequirements(pwd);
        const patterns = detectPatterns(pwd);
        const score = calculateStrengthScore(pwd, reqs, patterns);
        const entropy = calculateEntropy(pwd);
        const crackTimes = estimateCrackTimes(pwd, patterns);

        // Update requirements chips
        Object.entries(reqs).forEach(([k, passed]) => {
            const el = requirementElements[k];
            if (el) {
                el.className = `requirement-item ${passed ? "valid" : "invalid"}`;
                el.innerHTML = `
                    <span class="requirement-icon" aria-hidden="true">
                        <i class="fa-solid ${passed ? "fa-check" : "fa-xmark"}"></i>
                    </span>
                    <span>${REQUIREMENT_LABELS[k]}</span>
                `;
            }
        });

        // Update strength meter ring
        if (strengthPercent) strengthPercent.textContent = `${score}%`;
        let label = "Very Weak";
        let color = "var(--color-error)";

        if (score >= 80) { label = "Very Strong"; color = "var(--color-success-alt)"; }
        else if (score >= 60) { label = "Strong"; color = "var(--color-link)"; }
        else if (score >= 40) { label = "Moderate"; color = "#d97706"; }
        else if (score >= 20) { label = "Weak"; color = "var(--color-warning)"; }

        if (strengthText) {
            strengthText.textContent = label;
            strengthText.style.color = color;
        }

        if (meterBar) {
            const circumference = 377; // 2 * pi * 60
            const offset = circumference - (score / 100) * circumference;
            meterBar.style.strokeDashoffset = offset;
            meterBar.style.stroke = color;
        }

        // Update metrics cards
        if (resultContent) {
            resultContent.innerHTML = `
                <div class="analysis-results-grid">
                    <div class="metric-card">
                        <span class="metric-title">Entropy</span>
                        <span class="metric-value">${entropy} <small style="font-size:12px; font-weight:normal;">bits</small></span>
                        <span class="metric-caption">${entropy >= 60 ? "Cryptographically resilient" : "Low randomness pool"}</span>
                    </div>
                    <div class="metric-card">
                        <span class="metric-title">Offline Fast Hash (8x 4090)</span>
                        <span class="metric-value">${crackTimes.gpuFast}</span>
                        <span class="metric-caption">MD5 / NTLM fast hash attacks</span>
                    </div>
                    <div class="metric-card">
                        <span class="metric-title">Offline Slow Hash</span>
                        <span class="metric-value">${crackTimes.slowHash}</span>
                        <span class="metric-caption">Bcrypt / Argon2 hardened derivation</span>
                    </div>
                    <div class="metric-card">
                        <span class="metric-title">Online Throttled</span>
                        <span class="metric-value">${crackTimes.online}</span>
                        <span class="metric-caption">Rate-limited web login endpoints</span>
                    </div>
                </div>
            `;
        }

        // Update suggestions
        if (suggestionsContent) {
            const list = [];
            if (!reqs.length) list.push("Increase length to at least 12–16 characters.");
            if (!reqs.special) list.push("Add symbols such as !@#$%^&* to expand the character search space.");
            if (!reqs.upper || !reqs.lower) list.push("Combine mixed casing to avoid predictable character clusters.");
            if (!reqs.number) list.push("Include numbers non-sequentially.");
            if (patterns.predictableWord) list.push(`Avoid dictionary words like "${patterns.predictableWord}".`);
            if (patterns.numberSequence) list.push("Remove predictable numeric sequences like 1234 or 8765.");
            if (patterns.yearPattern) list.push("Avoid using 4-digit birth or calendar years.");
            if (patterns.repeatedCharacters) list.push("Avoid repeating identical characters consecutively.");

            if (list.length === 0 && pwd.length >= 14) {
                suggestionsContent.innerHTML = `
                    <div class="suggestion-item">
                        <i class="fa-solid fa-circle-check" style="color:var(--color-success-alt); margin-top:2px;" aria-hidden="true"></i>
                        <span>Excellent credential structure. High entropy and no predictable dictionary sequences detected.</span>
                    </div>
                `;
            } else {
                suggestionsContent.innerHTML = `
                    <ul class="suggestions-list">
                        ${list.map(s => `
                            <li class="suggestion-item">
                                <i class="fa-solid fa-triangle-exclamation suggestion-icon" aria-hidden="true"></i>
                                <span>${s}</span>
                            </li>
                        `).join("")}
                    </ul>
                `;
            }
        }
    }

    // --------------------------------------------------------------------------
    // 7. EVENT LISTENERS & INITIALIZATION
    // --------------------------------------------------------------------------
    document.addEventListener("DOMContentLoaded", () => {
        if (!passwordInput) return;

        passwordInput.addEventListener("input", analyzePassword);

        // Visibility Toggle
        if (togglePassword) {
            togglePassword.addEventListener("click", () => {
                const isPass = passwordInput.type === "password";
                passwordInput.type = isPass ? "text" : "password";
                const icon = togglePassword.querySelector("i");
                if (icon) {
                    icon.className = isPass ? "fa-regular fa-eye-slash" : "fa-regular fa-eye";
                }
                togglePassword.setAttribute("aria-label", isPass ? "Hide password" : "Show password");
            });
        }

        // Copy Password
        if (copyPassword) {
            copyPassword.addEventListener("click", async () => {
                if (!passwordInput.value) {
                    if (window.ThreatHawk) window.ThreatHawk.toast("No password to copy", "fa-triangle-exclamation");
                    return;
                }
                if (window.ThreatHawk) {
                    await window.ThreatHawk.copyToClipboard(passwordInput.value, "Password copied securely");
                }
            });
        }

        // Generate Password
        if (generatePassword) {
            generatePassword.addEventListener("click", () => {
                passwordInput.value = generateSecurePassword(selectedGeneratorLength);
                passwordInput.type = "text";
                if (togglePassword) {
                    const icon = togglePassword.querySelector("i");
                    if (icon) icon.className = "fa-regular fa-eye-slash";
                }
                analyzePassword();
                if (window.ThreatHawk) {
                    window.ThreatHawk.toast(`Generated ${selectedGeneratorLength}-character secure password`, "fa-wand-magic-sparkles");
                }
            });
        }

        // Length Pills
        document.querySelectorAll(".length-pill-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                document.querySelectorAll(".length-pill-btn").forEach(b => b.classList.remove("active"));
                btn.classList.add("active");
                selectedGeneratorLength = parseInt(btn.dataset.len, 10) || 18;
                passwordInput.value = generateSecurePassword(selectedGeneratorLength);
                analyzePassword();
            });
        });

        // Initialize state
        analyzePassword();
    });
})();
