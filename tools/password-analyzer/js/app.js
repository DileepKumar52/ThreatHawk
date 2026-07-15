"use strict";

/* =========================================================
   THREATHAWK PASSWORD INTELLIGENCE
   Complete JavaScript

   Features:
   - Automatic live analysis
   - Requirements validation
   - Strength score and meter
   - Entropy estimation
   - Offline crack-time estimation
   - Common-password detection
   - Pattern detection
   - Guaranteed secure password generator
   - Copy notification
   - Show/hide password
   - Persistent light/dark theme
========================================================= */


/* =========================================================
   1. DOM ELEMENTS
========================================================= */

const passwordInput =
    document.getElementById("passwordInput");

const togglePassword =
    document.getElementById("togglePassword");

const copyPassword =
    document.getElementById("copyPassword");

const generatePassword =
    document.getElementById("generatePassword");

const themeToggle =
    document.getElementById("themeToggle");

const strengthLevel =
    document.getElementById("strengthLevel");

const strengthPercent =
    document.getElementById("strengthPercent");

const strengthText =
    document.getElementById("strengthText");

const resultContent =
    document.getElementById("resultContent");

const suggestionsContent =
    document.getElementById("suggestionsContent");

const toast =
    document.getElementById("toast");

const toastMessage =
    document.getElementById("toastMessage");

const requirementElements = {
    length: document.getElementById("reqLength"),
    upper: document.getElementById("reqUpper"),
    lower: document.getElementById("reqLower"),
    number: document.getElementById("reqNumber"),
    special: document.getElementById("reqSpecial")
};


/* =========================================================
   2. CONFIGURATION
========================================================= */

const OFFLINE_GUESSES_PER_SECOND = 1_000_000_000;

const COMMON_PASSWORDS = new Set([
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "111111",
    "000000",
    "abc123",
    "admin",
    "admin123",
    "letmein",
    "login",
    "master",
    "password",
    "password1",
    "password12",
    "password123",
    "passw0rd",
    "qwerty",
    "qwerty123",
    "welcome",
    "welcome123",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "princess",
    "sunshine"
]);

const PREDICTABLE_WORDS = [
    "password",
    "admin",
    "qwerty",
    "welcome",
    "login",
    "letmein",
    "user",
    "guest"
];

const REQUIREMENT_LABELS = {
    length: "At least 8 characters",
    upper: "One uppercase letter",
    lower: "One lowercase letter",
    number: "One number",
    special: "One special character"
};

const STRENGTH_LEVELS = [
    {
        maximum: 19,
        label: "Very Weak",
        badgeClass: "very-weak",
        color: "#ef4444"
    },
    {
        maximum: 39,
        label: "Weak",
        badgeClass: "weak",
        color: "#f97316"
    },
    {
        maximum: 59,
        label: "Medium",
        badgeClass: "medium",
        color: "#eab308"
    },
    {
        maximum: 79,
        label: "Strong",
        badgeClass: "strong",
        color: "#3b82f6"
    },
    {
        maximum: 100,
        label: "Very Strong",
        badgeClass: "very-strong",
        color: "#22c55e"
    }
];

let currentScore = 0;
let toastTimer = null;


/* =========================================================
   3. REQUIREMENT CHECKS
========================================================= */

function evaluateRequirements(password) {
    return {
        length: password.length >= 8,
        upper: /[A-Z]/.test(password),
        lower: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        special: /[^A-Za-z0-9]/.test(password)
    };
}

function updateRequirementItem(element, passed, label) {
    if (!element) {
        return;
    }

    element.classList.remove("valid", "invalid");
    element.classList.add(
        "requirement-item",
        passed ? "valid" : "invalid"
    );

    element.innerHTML = `
        <span class="requirement-icon">
            <i class="fa-solid ${
                passed ? "fa-check" : "fa-xmark"
            }"></i>
        </span>

        <span>${label}</span>
    `;
}

function updateRequirements(requirements) {
    Object.entries(requirements).forEach(
        ([requirementName, passed]) => {
            updateRequirementItem(
                requirementElements[requirementName],
                passed,
                REQUIREMENT_LABELS[requirementName]
            );
        }
    );
}


/* =========================================================
   4. PASSWORD CHARACTER ANALYSIS
========================================================= */

function getCharacterSetSize(password) {
    let characterSetSize = 0;

    if (/[a-z]/.test(password)) {
        characterSetSize += 26;
    }

    if (/[A-Z]/.test(password)) {
        characterSetSize += 26;
    }

    if (/[0-9]/.test(password)) {
        characterSetSize += 10;
    }

    if (/[^A-Za-z0-9]/.test(password)) {
        characterSetSize += 33;
    }

    return characterSetSize;
}

function calculateEntropy(password) {
    const characterSetSize =
        getCharacterSetSize(password);

    if (
        password.length === 0 ||
        characterSetSize === 0
    ) {
        return 0;
    }

    return (
        password.length *
        Math.log2(characterSetSize)
    );
}

function detectPatterns(password) {
    const normalizedPassword =
        password.toLowerCase();

    const patterns = {
        commonPassword:
            COMMON_PASSWORDS.has(normalizedPassword),

        predictableWord:
            PREDICTABLE_WORDS.find(word =>
                normalizedPassword.includes(word)
            ) || null,

        numberSequence:
            /(?:0123|1234|2345|3456|4567|5678|6789|7890)/.test(
                normalizedPassword
            ),

        reverseNumberSequence:
            /(?:9876|8765|7654|6543|5432|4321|3210)/.test(
                normalizedPassword
            ),

        keyboardSequence:
            /(?:qwerty|asdf|zxcv|qazwsx)/.test(
                normalizedPassword
            ),

        repeatedCharacters:
            /(.)\1{2,}/.test(password),

        repeatedBlock:
            /(.{2,4})\1{1,}/i.test(password),

        onlyLetters:
            /^[a-z]+$/i.test(password),

        onlyNumbers:
            /^\d+$/.test(password),

        lowUniqueness: false
    };

    const uniqueCharacters =
        new Set(password).size;

    if (password.length >= 8) {
        patterns.lowUniqueness =
            uniqueCharacters / password.length < 0.5;
    }

    return patterns;
}


/* =========================================================
   5. STRENGTH SCORE
========================================================= */

function calculateStrengthScore(
    password,
    requirements,
    patterns
) {
    if (!password) {
        return 0;
    }

    if (patterns.commonPassword) {
        return 0;
    }

    let score = 0;

    /*
     * Length contribution: maximum 40 points.
     */
    if (password.length >= 8) {
        score += 12;
    }

    if (password.length >= 10) {
        score += 6;
    }

    if (password.length >= 12) {
        score += 8;
    }

    if (password.length >= 16) {
        score += 8;
    }

    if (password.length >= 20) {
        score += 6;
    }

    /*
     * Character diversity: maximum 40 points.
     */
    if (requirements.upper) {
        score += 10;
    }

    if (requirements.lower) {
        score += 10;
    }

    if (requirements.number) {
        score += 10;
    }

    if (requirements.special) {
        score += 10;
    }

    /*
     * Character uniqueness: maximum 20 points.
     */
    const uniqueCharacterCount =
        new Set(password).size;

    const uniquenessRatio =
        uniqueCharacterCount / password.length;

    score += Math.round(
        Math.min(uniquenessRatio, 1) * 20
    );

    /*
     * Pattern penalties.
     */
    if (patterns.predictableWord) {
        score -= 20;
    }

    if (
        patterns.numberSequence ||
        patterns.reverseNumberSequence
    ) {
        score -= 12;
    }

    if (patterns.keyboardSequence) {
        score -= 18;
    }

    if (patterns.repeatedCharacters) {
        score -= 15;
    }

    if (patterns.repeatedBlock) {
        score -= 10;
    }

    if (patterns.onlyLetters) {
        score -= 12;
    }

    if (patterns.onlyNumbers) {
        score -= 25;
    }

    if (patterns.lowUniqueness) {
        score -= 10;
    }

    return Math.max(
        0,
        Math.min(Math.round(score), 100)
    );
}

function getStrengthLevel(score) {
    return (
        STRENGTH_LEVELS.find(
            level => score <= level.maximum
        ) ||
        STRENGTH_LEVELS[
            STRENGTH_LEVELS.length - 1
        ]
    );
}


/* =========================================================
   6. CRACK-TIME ESTIMATION
========================================================= */

function calculateCrackTimeLogSeconds(
    password,
    patterns
) {
    const characterSetSize =
        getCharacterSetSize(password);

    if (
        password.length === 0 ||
        characterSetSize === 0
    ) {
        return Number.NEGATIVE_INFINITY;
    }

    /*
     * Work in logarithms to avoid JavaScript numeric overflow
     * with extremely large password combinations.
     */
    let log10Guesses =
        password.length *
        Math.log10(characterSetSize);

    /*
     * Assume an attacker finds the password halfway
     * through the search space on average.
     */
    log10Guesses -= Math.log10(2);

    /*
     * Reduce estimated resistance when predictable
     * patterns are detected.
     */
    if (patterns.commonPassword) {
        return Number.NEGATIVE_INFINITY;
    }

    if (patterns.predictableWord) {
        log10Guesses -= 5;
    }

    if (
        patterns.numberSequence ||
        patterns.reverseNumberSequence
    ) {
        log10Guesses -= 4;
    }

    if (patterns.keyboardSequence) {
        log10Guesses -= 5;
    }

    if (patterns.repeatedCharacters) {
        log10Guesses -= 4;
    }

    if (patterns.repeatedBlock) {
        log10Guesses -= 3;
    }

    if (patterns.lowUniqueness) {
        log10Guesses -= 2;
    }

    return (
        log10Guesses -
        Math.log10(OFFLINE_GUESSES_PER_SECOND)
    );
}

function formatLargeNumber(value) {
    if (value < 10) {
        return value.toFixed(1);
    }

    return Math.round(value).toLocaleString();
}

function formatCrackTimeFromLog(log10Seconds) {
    if (!Number.isFinite(log10Seconds)) {
        return "Instantly";
    }

    if (log10Seconds < 0) {
        return "Less than 1 second";
    }

    const timeUnits = [
        {
            label: "second",
            seconds: 1
        },
        {
            label: "minute",
            seconds: 60
        },
        {
            label: "hour",
            seconds: 60 * 60
        },
        {
            label: "day",
            seconds: 60 * 60 * 24
        },
        {
            label: "year",
            seconds: 60 * 60 * 24 * 365
        }
    ];

    /*
     * For manageable values, calculate normally.
     */
    if (log10Seconds < 15) {
        const seconds =
            10 ** log10Seconds;

        let selectedUnit =
            timeUnits[0];

        for (const unit of timeUnits) {
            if (seconds >= unit.seconds) {
                selectedUnit = unit;
            }
        }

        const amount =
            seconds / selectedUnit.seconds;

        const roundedAmount =
            formatLargeNumber(amount);

        return `${roundedAmount} ${
            Number(roundedAmount.replace(/,/g, "")) === 1
                ? selectedUnit.label
                : `${selectedUnit.label}s`
        }`;
    }

    /*
     * Extremely large values are represented as
     * powers of ten rather than overflowing.
     */
    const secondsPerYear =
        60 * 60 * 24 * 365;

    const log10Years =
        log10Seconds -
        Math.log10(secondsPerYear);

    if (log10Years < 3) {
        return `${Math.round(
            10 ** log10Years
        ).toLocaleString()} years`;
    }

    if (log10Years < 6) {
        return `${formatLargeNumber(
            10 ** (log10Years - 3)
        )} thousand years`;
    }

    if (log10Years < 9) {
        return `${formatLargeNumber(
            10 ** (log10Years - 6)
        )} million years`;
    }

    if (log10Years < 12) {
        return `${formatLargeNumber(
            10 ** (log10Years - 9)
        )} billion years`;
    }

    return `Approximately 10^${Math.floor(
        log10Years
    )} years`;
}


/* =========================================================
   7. SUGGESTIONS
========================================================= */

function buildSuggestions(
    password,
    requirements,
    patterns
) {
    const suggestions = [];

    if (!requirements.length) {
        suggestions.push(
            "Increase the password length to at least 8 characters. Twelve or more is preferable."
        );
    } else if (password.length < 12) {
        suggestions.push(
            "Increase the password to at least 12 characters for stronger resistance."
        );
    }

    if (!requirements.upper) {
        suggestions.push(
            "Add at least one uppercase letter."
        );
    }

    if (!requirements.lower) {
        suggestions.push(
            "Add at least one lowercase letter."
        );
    }

    if (!requirements.number) {
        suggestions.push(
            "Add at least one number."
        );
    }

    if (!requirements.special) {
        suggestions.push(
            "Add at least one special character."
        );
    }

    if (patterns.predictableWord) {
        suggestions.push(
            `Avoid predictable words such as "${patterns.predictableWord}".`
        );
    }

    if (
        patterns.numberSequence ||
        patterns.reverseNumberSequence
    ) {
        suggestions.push(
            "Avoid predictable numeric sequences such as 1234 or 4321."
        );
    }

    if (patterns.keyboardSequence) {
        suggestions.push(
            "Avoid keyboard patterns such as qwerty, asdf or zxcv."
        );
    }

    if (patterns.repeatedCharacters) {
        suggestions.push(
            "Avoid repeating the same character three or more times."
        );
    }

    if (patterns.repeatedBlock) {
        suggestions.push(
            "Avoid repeating the same group of characters."
        );
    }

    if (patterns.onlyLetters) {
        suggestions.push(
            "Do not rely only on letters. Add numbers and symbols."
        );
    }

    if (patterns.onlyNumbers) {
        suggestions.push(
            "Numeric-only passwords are highly predictable. Use mixed character types."
        );
    }

    if (patterns.lowUniqueness) {
        suggestions.push(
            "Use a wider variety of characters instead of repeatedly reusing the same ones."
        );
    }

    return [...new Set(suggestions)];
}


/* =========================================================
   8. METER
========================================================= */

function updateStrengthMeter(score) {
    const safeScore = Math.max(
        0,
        Math.min(score, 100)
    );

    currentScore = safeScore;

    const strength =
        getStrengthLevel(safeScore);

    const mobileHorizontalMeter =
        window.matchMedia(
            "(max-width: 860px)"
        ).matches;

    if (mobileHorizontalMeter) {
        strengthLevel.style.width =
            `${safeScore}%`;

        strengthLevel.style.height =
            "100%";
    } else {
        strengthLevel.style.height =
            `${safeScore}%`;

        strengthLevel.style.width =
            "100%";
    }

    strengthLevel.style.background =
        strength.color;

    strengthLevel.style.color =
        strength.color;

    strengthLevel.style.boxShadow =
        `0 0 20px ${strength.color}`;

    strengthPercent.textContent =
        `${safeScore}%`;

    strengthPercent.style.color =
        strength.color;

    strengthText.textContent =
        strength.label;

    strengthText.style.color =
        strength.color;

    strengthPercent.classList.remove(
        "updated"
    );

    void strengthPercent.offsetWidth;

    strengthPercent.classList.add(
        "updated"
    );
}


/* =========================================================
   9. RESULT RENDERING
========================================================= */

function renderResult({
    score,
    strength,
    entropy,
    crackTime,
    passedRequirements,
    patterns
}) {
    const commonPasswordWarning =
        patterns.commonPassword
            ? `
                <div class="common-password-alert">
                    <i class="fa-solid fa-triangle-exclamation"></i>

                    <span>
                        This value appears in common-password
                        lists and should not be used.
                    </span>
                </div>
            `
            : "";

    resultContent.className =
        "result-state";

    resultContent.innerHTML = `
        <div class="result-heading-line">
            <strong>Password assessment</strong>

            <span class="result-badge ${strength.badgeClass}">
                ${strength.label}
            </span>
        </div>

        <div class="result-grid">

            <div class="result-metric highlight">
                <span>Security score</span>
                <strong>${score} / 100</strong>
            </div>

            <div class="result-metric">
                <span>Requirements met</span>
                <strong>${passedRequirements} / 5</strong>
            </div>

            <div class="result-metric">
                <span>Estimated entropy</span>
                <strong>${entropy.toFixed(1)} bits</strong>
            </div>

            <div class="result-metric highlight">
                <span>Offline crack time</span>
                <strong>${crackTime}</strong>
            </div>

        </div>

        ${commonPasswordWarning}

        <div class="result-warning">
            <i class="fa-solid fa-circle-info"></i>

            <span>
                Crack time is a simplified estimate based on
                one billion offline guesses per second. Real
                results vary by hashing algorithm and attacker
                hardware.
            </span>
        </div>
    `;
}

function renderSuggestions(
    suggestions,
    patterns
) {
    if (patterns.commonPassword) {
        suggestionsContent.className =
            "suggestion-list";

        suggestionsContent.innerHTML = `
            <div class="suggestion-item">
                <i class="fa-solid fa-arrow-rotate-right"></i>

                <span>
                    Replace this password completely instead of
                    making minor changes to it.
                </span>
            </div>

            <div class="suggestion-item">
                <i class="fa-solid fa-ruler-horizontal"></i>

                <span>
                    Use at least 12 to 16 characters.
                </span>
            </div>

            <div class="suggestion-item">
                <i class="fa-solid fa-shuffle"></i>

                <span>
                    Use a unique password that is not reused on
                    another account.
                </span>
            </div>

            <div class="suggestion-item">
                <i class="fa-solid fa-wand-magic-sparkles"></i>

                <span>
                    Use the generator above to create a stronger
                    alternative.
                </span>
            </div>
        `;

        return;
    }

    if (suggestions.length === 0) {
        suggestionsContent.className =
            "suggestion-success";

        suggestionsContent.innerHTML = `
            <i class="fa-solid fa-circle-check"></i>

            <span>
                Excellent password structure. Keep it unique
                and store it in a trusted password manager.
            </span>
        `;

        return;
    }

    suggestionsContent.className =
        "suggestion-list";

    suggestionsContent.innerHTML =
        suggestions
            .map(
                suggestion => `
                    <div class="suggestion-item">
                        <i class="fa-solid fa-arrow-trend-up"></i>

                        <span>${suggestion}</span>
                    </div>
                `
            )
            .join("");
}


/* =========================================================
   10. EMPTY STATE
========================================================= */

function resetAnalysis() {
    const emptyRequirements = {
        length: false,
        upper: false,
        lower: false,
        number: false,
        special: false
    };

    updateRequirements(emptyRequirements);
    updateStrengthMeter(0);

    resultContent.className =
        "result-placeholder";

    resultContent.innerHTML = `
        <div class="placeholder-icon">
            <i class="fa-solid fa-key"></i>
        </div>

        <p>
            Enter a password to view its security score,
            entropy and estimated offline crack time.
        </p>
    `;

    suggestionsContent.className =
        "suggestions-placeholder";

    suggestionsContent.textContent =
        "Suggestions will appear after you enter a password.";
}


/* =========================================================
   11. LIVE ANALYSIS
========================================================= */

function analyzePassword() {
    const password =
        passwordInput.value;

    if (!password) {
        resetAnalysis();
        return;
    }

    const requirements =
        evaluateRequirements(password);

    const patterns =
        detectPatterns(password);

    const score =
        calculateStrengthScore(
            password,
            requirements,
            patterns
        );

    const strength =
        getStrengthLevel(score);

    const entropy =
        patterns.commonPassword
            ? 0
            : calculateEntropy(password);

    const log10Seconds =
        calculateCrackTimeLogSeconds(
            password,
            patterns
        );

    const crackTime =
        patterns.commonPassword
            ? "Instantly"
            : formatCrackTimeFromLog(
                log10Seconds
            );

    const suggestions =
        buildSuggestions(
            password,
            requirements,
            patterns
        );

    const passedRequirements =
        Object.values(requirements)
            .filter(Boolean)
            .length;

    updateRequirements(requirements);
    updateStrengthMeter(score);

    renderResult({
        score,
        strength,
        entropy,
        crackTime,
        passedRequirements,
        patterns
    });

    renderSuggestions(
        suggestions,
        patterns
    );
}


/* =========================================================
   12. SECURE RANDOM GENERATOR
========================================================= */

function getSecureRandomIndex(maximum) {
    if (
        !Number.isInteger(maximum) ||
        maximum <= 0
    ) {
        throw new Error(
            "Invalid random-index maximum."
        );
    }

    const randomValues =
        new Uint32Array(1);

    const maximumValidValue =
        Math.floor(
            0x100000000 / maximum
        ) * maximum;

    let randomValue;

    do {
        crypto.getRandomValues(
            randomValues
        );

        randomValue =
            randomValues[0];
    } while (
        randomValue >= maximumValidValue
    );

    return randomValue % maximum;
}

function getRandomCharacter(characters) {
    return characters[
        getSecureRandomIndex(
            characters.length
        )
    ];
}

function secureShuffle(values) {
    const shuffledValues =
        [...values];

    for (
        let index =
            shuffledValues.length - 1;
        index > 0;
        index--
    ) {
        const randomIndex =
            getSecureRandomIndex(index + 1);

        [
            shuffledValues[index],
            shuffledValues[randomIndex]
        ] = [
            shuffledValues[randomIndex],
            shuffledValues[index]
        ];
    }

    return shuffledValues;
}

function generateSecurePassword(
    passwordLength = 18
) {
    const uppercaseCharacters =
        "ABCDEFGHJKLMNPQRSTUVWXYZ";

    const lowercaseCharacters =
        "abcdefghijkmnopqrstuvwxyz";

    const numberCharacters =
        "23456789";

    const specialCharacters =
        "!@#$%^&*()-_=+[]{};:,.?";

    const allCharacters =
        uppercaseCharacters +
        lowercaseCharacters +
        numberCharacters +
        specialCharacters;

    /*
     * Guarantee every generated password contains
     * all required character categories.
     */
    const passwordCharacters = [
        getRandomCharacter(
            uppercaseCharacters
        ),
        getRandomCharacter(
            lowercaseCharacters
        ),
        getRandomCharacter(
            numberCharacters
        ),
        getRandomCharacter(
            specialCharacters
        )
    ];

    while (
        passwordCharacters.length <
        passwordLength
    ) {
        passwordCharacters.push(
            getRandomCharacter(
                allCharacters
            )
        );
    }

    return secureShuffle(
        passwordCharacters
    ).join("");
}


/* =========================================================
   13. CLIPBOARD AND TOAST
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

    const toastIcon =
        toast.querySelector("i");

    if (toastIcon) {
        toastIcon.className =
            `fa-solid ${iconClass}`;
    }

    toast.classList.add("show");

    window.clearTimeout(
        toastTimer
    );

    toastTimer =
        window.setTimeout(() => {
            toast.classList.remove(
                "show"
            );
        }, 2200);
}

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


/* =========================================================
   14. PASSWORD VISIBILITY
========================================================= */

function updateVisibilityButton(
    passwordIsVisible
) {
    const icon =
        togglePassword.querySelector("i");

    if (!icon) {
        return;
    }

    icon.className =
        passwordIsVisible
            ? "fa-regular fa-eye-slash"
            : "fa-regular fa-eye";

    togglePassword.setAttribute(
        "aria-label",
        passwordIsVisible
            ? "Hide password"
            : "Show password"
    );

    togglePassword.title =
        passwordIsVisible
            ? "Hide password"
            : "Show password";
}


/* =========================================================
   15. THEME
========================================================= */

function updateThemeButton(
    lightModeEnabled
) {
    const themeIcon =
        themeToggle.querySelector("i");

    const themeText =
        themeToggle.querySelector("span");

    if (themeIcon) {
        themeIcon.className =
            lightModeEnabled
                ? "fa-regular fa-moon"
                : "fa-regular fa-sun";
    }

    if (themeText) {
        themeText.textContent =
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
                "threathawk-password-theme"
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
   16. EVENT LISTENERS
========================================================= */

passwordInput.addEventListener(
    "input",
    analyzePassword
);

togglePassword.addEventListener(
    "click",
    () => {
        const showPassword =
            passwordInput.type ===
            "password";

        passwordInput.type =
            showPassword
                ? "text"
                : "password";

        updateVisibilityButton(
            showPassword
        );

        passwordInput.focus();
    }
);

copyPassword.addEventListener(
    "click",
    async () => {
        const password =
            passwordInput.value;

        if (!password) {
            showToast(
                "Enter or generate a password first",
                "fa-circle-exclamation"
            );

            passwordInput.focus();
            return;
        }

        try {
            await copyText(password);

            const copyIcon =
                copyPassword.querySelector(
                    "i"
                );

            if (copyIcon) {
                copyIcon.className =
                    "fa-solid fa-check";
            }

            showToast(
                "Password copied securely"
            );

            window.setTimeout(() => {
                if (copyIcon) {
                    copyIcon.className =
                        "fa-regular fa-copy";
                }
            }, 1400);
        } catch (error) {
            console.error(
                "Copy failed:",
                error
            );

            showToast(
                "Password could not be copied",
                "fa-xmark"
            );
        }
    }
);

generatePassword.addEventListener(
    "click",
    () => {
        try {
            passwordInput.value =
                generateSecurePassword(18);

            passwordInput.type =
                "text";

            updateVisibilityButton(true);
            analyzePassword();

            showToast(
                "Strong password generated",
                "fa-wand-magic-sparkles"
            );

            passwordInput.focus();
            passwordInput.select();
        } catch (error) {
            console.error(
                "Password generation failed:",
                error
            );

            showToast(
                "Password generation failed",
                "fa-xmark"
            );
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
                "threathawk-password-theme",
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

window.addEventListener(
    "resize",
    () => {
        updateStrengthMeter(
            currentScore
        );
    }
);


/* =========================================================
   17. INITIALIZATION
========================================================= */

function initializePasswordIntelligence() {
    applySavedTheme();
    updateVisibilityButton(false);
    resetAnalysis();
    passwordInput.focus();
}

initializePasswordIntelligence();