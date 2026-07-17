const urlInput = document.getElementById("urlInput");

const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");

const protocol = document.getElementById("protocol");
const hostname = document.getElementById("hostname");
const domain = document.getElementById("domain");
const tld = document.getElementById("tld");

const subdomain = document.getElementById("subdomain");
const port = document.getElementById("port");
const path = document.getElementById("path");
const query = document.getElementById("query");
const fragment = document.getElementById("fragment");
const length = document.getElementById("length");

const riskScore = document.getElementById("riskScore");
const riskLabel = document.getElementById("riskLabel");
const riskFill = document.getElementById("riskFill");
const findingsList = document.getElementById("findingsList");
const findingCount = document.getElementById("findingCount");

const riskScoreRing =
    document.querySelector(".risk-score-ring");

const themeToggle =
    document.getElementById("themeToggle");

const toast =
    document.getElementById("toast");

const toastMessage =
    document.getElementById("toastMessage");

let toastTimer = null;
let currentRiskScore = 0;

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
    let savedTheme = null;

    try {
        savedTheme =
            localStorage.getItem(
                "threathawk-url-theme"
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

    updateThemeButton(lightModeEnabled);

    try {
        localStorage.setItem(
            "threathawk-url-theme",
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

function resetResults() {
    protocol.textContent = "-";
    hostname.textContent = "-";
    domain.textContent = "-";
    tld.textContent = "-";

    subdomain.textContent = "-";
    port.textContent = "-";
    path.textContent = "-";
    query.textContent = "-";
    fragment.textContent = "-";
    length.textContent = "-";

    hostname.title = "-";
    domain.title = "-";
    path.title = "-";
    fragment.title = "-";

    updateRiskMeter(0, true);

    findingCount.textContent =
        "0 findings";

    findingsList.innerHTML = `
        <div class="findings-empty-state">

            <div class="empty-state-icon">
                <i class="fa-solid fa-shield"></i>
            </div>

            <strong>
                No URL analyzed
            </strong>

            <p class="empty-findings">
                Enter a website address and run the analyzer
                to view structural security findings.
            </p>

        </div>
    `;
}

function updateRiskMeter(
    score,
    forceNotAnalyzed = false
) {
    const safeScore =
        Math.max(
            0,
            Math.min(
                Math.round(score),
                100
            )
        );

    riskFill.classList.remove(
        "risk-low",
        "risk-medium",
        "risk-high",
        "risk-critical"
    );

    riskScoreRing.classList.remove(
        "risk-low-state",
        "risk-medium-state",
        "risk-high-state",
        "risk-critical-state"
    );

    let label;
    let fillClass;
    let ringClass;

    if (safeScore <= 24) {
        label = "Low Risk";
        fillClass = "risk-low";
        ringClass = "risk-low-state";
    } else if (safeScore <= 49) {
        label = "Medium Risk";
        fillClass = "risk-medium";
        ringClass = "risk-medium-state";
    } else if (safeScore <= 74) {
        label = "High Risk";
        fillClass = "risk-high";
        ringClass = "risk-high-state";
    } else {
        label = "Critical Risk";
        fillClass = "risk-critical";
        ringClass = "risk-critical-state";
    }

    riskFill.classList.add(fillClass);
    riskScoreRing.classList.add(ringClass);

    riskFill.style.width =
        `${safeScore}%`;

    if (forceNotAnalyzed) {
        riskLabel.textContent =
            "Not analyzed";

        riskScore.textContent = "0";
        currentRiskScore = 0;

        return;
    }

    riskLabel.textContent = label;

    const startScore =
        currentRiskScore;

    const difference =
        safeScore - startScore;

    const duration = 600;
    const startTime = performance.now();

    riskScore.classList.remove("updated");

    function animate(currentTime) {
        const elapsed =
            currentTime - startTime;

        const progress =
            Math.min(
                elapsed / duration,
                1
            );

        const eased =
            1 - Math.pow(1 - progress, 3);

        const displayedScore =
            Math.round(
                startScore +
                difference * eased
            );

        riskScore.textContent =
            displayedScore;

        if (progress < 1) {
            requestAnimationFrame(animate);
        } else {
            riskScore.textContent =
                safeScore;

            riskScore.classList.add(
                "updated"
            );
        }
    }

    requestAnimationFrame(animate);

    currentRiskScore = safeScore;
}

const suspiciousKeywords = [
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "password",
    "credential",
    "banking",
    "payment",
    "invoice",
    "wallet",
    "recover",
    "reset",
    "support",
    "authenticate",
    "unlock"
];

const urlShorteners = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc"
];

const trustedBrands = [
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "netflix",
    "facebook",
    "instagram",
    "whatsapp",
    "linkedin",
    "github",
    "dropbox",
    "adobe",
    "coinbase",
    "binance"
];

const redirectParameterNames = [
    "url",
    "uri",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "returnurl",
    "return_url",
    "next",
    "continue",
    "destination",
    "dest",
    "target",
    "to"
];

const suspiciousExtensions = [
    ".exe",
    ".msi",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".jar",
    ".ps1",
    ".vbs",
    ".js",
    ".apk",
    ".dmg",
    ".iso",
    ".zip",
    ".rar"
];

function isIPv4(hostname) {
    const ipv4Pattern =
        /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

    return ipv4Pattern.test(hostname);
}

function isIPv6(hostname) {
    const cleanHostname = hostname.replace(/^\[|\]$/g, "");

    return (
        cleanHostname.includes(":") &&
        /^[a-fA-F0-9:]+$/.test(cleanHostname)
    );
}

function addFinding(findings, points, title, description) {
    findings.push({
        points,
        title,
        description
    });
}

function levenshteinDistance(first, second) {
    first = first.toLowerCase();
    second = second.toLowerCase();

    const matrix = Array.from(
        { length: first.length + 1 },
        () => Array(second.length + 1).fill(0)
    );

    for (let row = 0; row <= first.length; row++) {
        matrix[row][0] = row;
    }

    for (let column = 0; column <= second.length; column++) {
        matrix[0][column] = column;
    }

    for (let row = 1; row <= first.length; row++) {
        for (let column = 1; column <= second.length; column++) {
            const cost =
                first[row - 1] === second[column - 1] ? 0 : 1;

            matrix[row][column] = Math.min(
                matrix[row - 1][column] + 1,
                matrix[row][column - 1] + 1,
                matrix[row - 1][column - 1] + cost
            );
        }
    }

    return matrix[first.length][second.length];
}

function calculateSimilarity(first, second) {
    const longestLength = Math.max(
        first.length,
        second.length
    );

    if (longestLength === 0) {
        return 100;
    }

    const distance = levenshteinDistance(first, second);

    return Math.round(
        (1 - distance / longestLength) * 100
    );
}

function normalizeLookalikes(value) {
    return value
        .toLowerCase()
        .replaceAll("0", "o")
        .replaceAll("1", "l")
        .replaceAll("3", "e")
        .replaceAll("5", "s")
        .replaceAll("7", "t")
        .replaceAll("@", "a");
}

function detectBrandImpersonation(hostname) {
    const lowerHostname = hostname
        .toLowerCase()
        .replace(/^www\./, "");

    const labels = lowerHostname.split(".");

    /*
     * This uses the label before the TLD as the main domain.
     * Example: micr0soft-support.net -> micr0soft-support
     */
    const domainLabel =
        labels.length >= 2
            ? labels[labels.length - 2]
            : labels[0];

    const normalizedDomain =
        normalizeLookalikes(domainLabel);

    const domainTokens = domainLabel
        .split(/[-_.]+/)
        .map(normalizeLookalikes)
        .filter(Boolean);

    let strongestMatch = null;

    for (const brand of trustedBrands) {
        const normalizedBrand =
            normalizeLookalikes(brand);

        /*
         * Do not report a genuine exact brand label.
         * microsoft.com -> no warning
         */
        if (normalizedDomain === normalizedBrand) {
            continue;
        }

        const candidates = [
            normalizedDomain,
            ...domainTokens
        ];

        for (const candidate of candidates) {
            const similarity = calculateSimilarity(
                candidate,
                normalizedBrand
            );

            const containsBrand =
                normalizedDomain.includes(normalizedBrand);

            if (
                similarity >= 75 ||
                containsBrand
            ) {
                if (
                    !strongestMatch ||
                    similarity > strongestMatch.similarity
                ) {
                    strongestMatch = {
                        brand,
                        similarity
                    };
                }
            }
        }
    }

    return strongestMatch;
}

function analyzeURLRisk(parsed, originalURL) {
    const findings = [];

    const hostname = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname.toLowerCase();
    const completeURL = originalURL.toLowerCase();

    /*
     * 1. Insecure protocol
     */
    if (parsed.protocol === "http:") {
        addFinding(
            findings,
            20,
            "Insecure HTTP connection",
            "The URL does not use HTTPS encryption."
        );
    } else if (
        parsed.protocol !== "https:" &&
        parsed.protocol !== "http:"
    ) {
        addFinding(
            findings,
            12,
            "Unusual URL protocol",
            `The URL uses the ${parsed.protocol.replace(":", "").toUpperCase()} protocol.`
        );
    }

    /*
     * 2. IP address instead of domain name
     */
    if (isIPv4(hostname) || isIPv6(hostname)) {
        addFinding(
            findings,
            25,
            "IP address used as hostname",
            "The URL uses an IP address instead of a recognizable domain."
        );
    }

    /*
     * 3. Embedded username/password or @ abuse
     */
    if (
        parsed.username ||
        parsed.password ||
        originalURL.includes("@")
    ) {
        addFinding(
            findings,
            25,
            "User-information or @ symbol detected",
            "The URL may hide its actual destination using user-information syntax."
        );
    }

    /*
     * 4. Punycode
     */
    if (hostname.includes("xn--")) {
        addFinding(
            findings,
            25,
            "Punycode domain detected",
            "The domain uses an internationalized representation that may imitate another domain."
        );
    }

    /*
     * 5. Known URL-shortening service
     */
    if (
        urlShorteners.some(shortener =>
            hostname === shortener ||
            hostname.endsWith(`.${shortener}`)
        )
    ) {
        addFinding(
            findings,
            18,
            "URL-shortening service detected",
            "The final destination is hidden behind a shortened URL."
        );
    }

    /*
     * 6. Suspicious words
     */
    const matchedKeywords = suspiciousKeywords.filter(keyword =>
        completeURL.includes(keyword)
    );

    if (matchedKeywords.length > 0) {
        const uniqueKeywords = [...new Set(matchedKeywords)];

        const keywordScore = Math.min(
            6 + uniqueKeywords.length * 3,
            18
        );

        addFinding(
            findings,
            keywordScore,
            "Suspicious keywords detected",
            `Matched: ${uniqueKeywords.join(", ")}.`
        );
    }

    /*
     * 7. Percent-encoded characters
     */
    const encodedMatches =
        originalURL.match(/%[a-fA-F0-9]{2}/g) || [];

    if (encodedMatches.length >= 3) {
        addFinding(
            findings,
            12,
            "Heavy URL encoding detected",
            `${encodedMatches.length} encoded sequences were found.`
        );
    } else if (encodedMatches.length > 0) {
        addFinding(
            findings,
            5,
            "Encoded characters detected",
            `${encodedMatches.length} encoded sequence(s) were found.`
        );
    }

    /*
     * 8. Excessive subdomains
     *
     * This is a heuristic. Accurate registrable-domain handling
     * will later use the Public Suffix List.
     */
    const hostnameParts = hostname
        .split(".")
        .filter(Boolean);

    const estimatedSubdomainCount = Math.max(
        hostnameParts.length - 2,
        0
    );

    if (estimatedSubdomainCount >= 4) {
        addFinding(
            findings,
            15,
            "Excessive subdomains",
            `${estimatedSubdomainCount} possible subdomain levels were detected.`
        );
    } else if (estimatedSubdomainCount >= 2) {
        addFinding(
            findings,
            7,
            "Multiple subdomains",
            `${estimatedSubdomainCount} possible subdomain levels were detected.`
        );
    }

    /*
     * 9. Unusual port
     */
    if (
        parsed.port &&
        !["80", "443", "21", "22"].includes(parsed.port)
    ) {
        addFinding(
            findings,
            10,
            "Unusual port detected",
            `The URL explicitly uses port ${parsed.port}.`
        );
    }

    /*
     * 10. Suspicious downloadable file
     */
    const matchedExtension = suspiciousExtensions.find(extension =>
        pathname.endsWith(extension)
    );

    if (matchedExtension) {
        addFinding(
            findings,
            20,
            "Potentially dangerous file extension",
            `The path ends with ${matchedExtension}.`
        );
    }

    /*
     * 11. Redirect or nested URL parameter
     */
    for (const [parameterName, parameterValue] of parsed.searchParams) {
        const normalizedName = parameterName.toLowerCase();
        const normalizedValue = parameterValue.toLowerCase();

        const isRedirectParameter =
            redirectParameterNames.includes(normalizedName);

        const containsNestedURL =
            /^https?:\/\//i.test(parameterValue) ||
            normalizedValue.includes("http%3a") ||
            normalizedValue.includes("https%3a");

        if (isRedirectParameter || containsNestedURL) {
            addFinding(
                findings,
                18,
                "Redirect or nested URL detected",
                `The "${parameterName}" parameter may redirect to another destination.`
            );

            break;
        }
    }

    /*
     * 12. Excessive URL length
     */
    if (originalURL.length > 200) {
        addFinding(
            findings,
            15,
            "Very long URL",
            `The URL contains ${originalURL.length} characters.`
        );
    } else if (originalURL.length > 100) {
        addFinding(
            findings,
            7,
            "Long URL",
            `The URL contains ${originalURL.length} characters.`
        );
    }

    /*
     * 13. Domain contains many digits
     */
    const digitCount =
        (hostname.match(/\d/g) || []).length;

    if (digitCount >= 6) {
        addFinding(
            findings,
            10,
            "Many digits in hostname",
            `${digitCount} numeric characters were found in the hostname.`
        );
    }

    /*
     * 14. Excessive hyphens
     */
    const hyphenCount =
        (hostname.match(/-/g) || []).length;

    if (hyphenCount >= 4) {
        addFinding(
            findings,
            8,
            "Excessive hyphens in hostname",
            `${hyphenCount} hyphens were found in the hostname.`
        );
    }

    const brandMatch =
    detectBrandImpersonation(hostname);

    if (brandMatch) {
        const brandName =
            brandMatch.brand.charAt(0).toUpperCase() +
            brandMatch.brand.slice(1);

        addFinding(
            findings,
            25,
            "Possible brand impersonation",
            `The hostname resembles ${brandName}. Similarity: ${brandMatch.similarity}%.`
        );
    }

    const rawScore = findings.reduce(
        (total, finding) => total + finding.points,
        0
    );

    return {
        score: Math.min(rawScore, 100),
        findings
    };
}

function escapeHTML(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function getFindingSeverity(points) {
    if (points <= 0) {
        return {
            className: "finding-low",
            label: "Info",
            icon: "fa-circle-info"
        };
    }

    if (points <= 7) {
        return {
            className: "finding-low",
            label: "Low",
            icon: "fa-shield-check"
        };
    }

    if (points <= 15) {
        return {
            className: "finding-medium",
            label: "Medium",
            icon: "fa-triangle-exclamation"
        };
    }

    if (points <= 24) {
        return {
            className: "finding-high",
            label: "High",
            icon: "fa-circle-exclamation"
        };
    }

    return {
        className: "finding-critical",
        label: "Critical",
        icon: "fa-skull-crossbones"
    };
}

function renderFindings(findings) {
    findingCount.textContent =
        `${findings.length} ${
            findings.length === 1
                ? "finding"
                : "findings"
        }`;

    if (findings.length === 0) {
        findingsList.innerHTML = `
            <div class="finding-card finding-safe">

                <div class="finding-icon">
                    <i class="fa-solid fa-shield-check"></i>
                </div>

                <div class="finding-content">

                    <div class="finding-title-row">

                        <h3>
                            No obvious structural risks detected
                        </h3>

                        <span>Low</span>

                    </div>

                    <p>
                        The URL passed the current heuristic
                        and reputation checks. This does not
                        guarantee that the destination is safe.
                    </p>

                </div>

            </div>
        `;

        return;
    }

    findingsList.innerHTML =
        findings
            .map(finding => {
                const severity =
                    getFindingSeverity(
                        finding.points
                    );

                return `
                    <div class="finding-card ${severity.className}">

                        <div class="finding-icon">
                            <i class="fa-solid ${severity.icon}"></i>
                        </div>

                        <div class="finding-content">

                            <div class="finding-title-row">

                                <h3>
                                    ${escapeHTML(finding.title)}
                                </h3>

                                <span>
                                    ${
                                        finding.points > 0
                                            ? `+${finding.points}`
                                            : severity.label
                                    }
                                </span>

                            </div>

                            <p>
                                ${escapeHTML(finding.description)}
                            </p>

                        </div>

                    </div>
                `;
            })
            .join("");
}

async function checkSafeBrowsing(url) {
    const response = await fetch("/api/safe-browsing", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ url })
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(
            data.error || "Safe Browsing request failed."
        );
    }

    return data;
}

async function analyzeURL() {

    let input = urlInput.value.trim();

    if (!input) {
        showToast(
            "Please enter a URL first",
            "fa-circle-exclamation"
        );

        urlInput.focus();
        return;
    }

    if (!/^https?:\/\//i.test(input) &&
        !/^ftp:\/\//i.test(input)) {

        input = "https://" + input;
    }

    try {

        const parsed = new URL(input);

        protocol.textContent =
            parsed.protocol.replace(":", "").toUpperCase();

        hostname.textContent = parsed.hostname;
        hostname.title = parsed.hostname;

        const parts = parsed.hostname.split(".");

        if (parts.length >= 2) {

            domain.textContent = parts[parts.length - 2];
            domain.title = domain.textContent;

            tld.textContent =
                "." + parts[parts.length - 1];

            if (parts.length > 2) {

                subdomain.textContent =
                    parts.slice(0, -2).join(".");

            }
            else {

                subdomain.textContent = "None";

            }

        }
        else {

            domain.textContent = parsed.hostname;
            tld.textContent = "Unknown";
            subdomain.textContent = "None";

        }

        port.textContent =
            parsed.port ||
            (
                parsed.protocol === "https:"
                    ? "443 (Default)"
                    : parsed.protocol === "http:"
                        ? "80 (Default)"
                        : "Default"
            );

        path.textContent =
            parsed.pathname || "/";

        path.title = path.textContent;

        query.textContent =
            parsed.search
                ? new URLSearchParams(parsed.search).size
                : "0";

        fragment.textContent =
            parsed.hash
                ? parsed.hash.substring(1)
                : "None";
        fragment.title =
            fragment.textContent;
            
        length.textContent =
            input.length + " Characters";

        
            const riskAnalysis = analyzeURLRisk(
                parsed,
                input
            );

            let finalScore = riskAnalysis.score;
            const finalFindings = [...riskAnalysis.findings];

            analyzeBtn.disabled = true;

            analyzeBtn.innerHTML = `
                <i class="fa-solid fa-spinner fa-spin"></i>
                Checking Reputation...
            `;

            document
                .querySelector(".analyzer-workspace")
                ?.classList.add("is-loading");

            try {
                const reputationResult =
                await checkSafeBrowsing(input);

                if (
                    reputationResult.checked &&
                    reputationResult.safe === false
                ) {
                    const threatNames =
                    reputationResult.threats
                    ?.map(item => item.threatType)
                    .filter(Boolean) || [];

                    const uniqueThreats =
                    [...new Set(threatNames)];

                    addFinding(
                        finalFindings,
                        100,
                        "Google Safe Browsing threat detected",
                        uniqueThreats.length
                        ? `Google classified this URL as: ${uniqueThreats.join(", ")}.`
                        : "Google Safe Browsing identified this URL as unsafe."
                    );

                    finalScore = 100;
                }
            } catch (error) {
                console.error(
                        "Safe Browsing check failed:",
                    error
                );

                addFinding(
                    finalFindings,
                    0,
                        "Reputation check unavailable",
                        "The local analysis completed, but Google Safe Browsing could not be reached."
                );
            } finally {

                document
                    .querySelector(".analyzer-workspace")
                    ?.classList.remove("is-loading");
                
                analyzeBtn.disabled = false;

                analyzeBtn.innerHTML = `
                    <i class="fa-solid fa-magnifying-glass-chart"></i>
                    Analyze URL
                `;
            }

            updateRiskMeter(finalScore);
            renderFindings(finalFindings);

            showToast(
                "URL analysis completed",
                "fa-shield-halved"
            );

        }

    catch (error) {
        console.error(
            "URL analysis failed:",
            error
        );

        showToast(
            "Please enter a valid URL",
            "fa-xmark"
        );

        resetResults();
        urlInput.focus();
    }

}

analyzeBtn.addEventListener("click", analyzeURL);

clearBtn.addEventListener(
    "click",
    () => {
        urlInput.value = "";

        resetResults();

        showToast(
            "URL Analyzer cleared",
            "fa-rotate-left"
        );

        urlInput.focus();
    }
);

urlInput.addEventListener("keydown", event => {

    if (event.key === "Enter" && !event.shiftKey) {

        event.preventDefault();

        analyzeURL();

    }

});

themeToggle.addEventListener(
    "click",
    toggleTheme
);

function initializeURLAnalyzer() {
    applySavedTheme();
    resetResults();
}

initializeURLAnalyzer();