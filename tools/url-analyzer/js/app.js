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

    updateRiskMeter(0);
    riskLabel.textContent = "Not analyzed";
    findingCount.textContent = "0 findings";

    findingsList.innerHTML = `
        <p class="empty-findings">
            Analyze a URL to view security findings.
        </p>
    `;

}

function updateRiskMeter(score) {
    const safeScore = Math.max(0, Math.min(score, 100));

    riskScore.textContent = safeScore;
    riskFill.style.width = `${safeScore}%`;

    riskFill.classList.remove(
        "risk-low",
        "risk-medium",
        "risk-high",
        "risk-critical"
    );

    if (safeScore <= 24) {
        riskLabel.textContent = "Low Risk";
        riskFill.classList.add("risk-low");
    } else if (safeScore <= 49) {
        riskLabel.textContent = "Medium Risk";
        riskFill.classList.add("risk-medium");
    } else if (safeScore <= 74) {
        riskLabel.textContent = "High Risk";
        riskFill.classList.add("risk-high");
    } else {
        riskLabel.textContent = "Critical Risk";
        riskFill.classList.add("risk-critical");
    }
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

function renderFindings(findings) {
    findingCount.textContent =
        `${findings.length} ${
            findings.length === 1 ? "finding" : "findings"
        }`;

    if (findings.length === 0) {
        findingsList.innerHTML = `
            <div class="finding-item finding-safe">
                <div class="finding-icon">✓</div>

                <div>
                    <h3>No obvious structural risks detected</h3>
                    <p>
                        The URL passed the current local heuristic checks.
                        This does not guarantee that the destination is safe.
                    </p>
                </div>
            </div>
        `;

        return;
    }

    findingsList.innerHTML = findings
        .map(finding => {
            return `
                <div class="finding-item">
                    <div class="finding-icon">!</div>

                    <div class="finding-content">
                        <div class="finding-title-row">
                            <h3>${finding.title}</h3>
                            <span>+${finding.points}</span>
                        </div>

                        <p>${finding.description}</p>
                    </div>
                </div>
            `;
        })
        .join("");
}

function analyzeURL() {

    let input = urlInput.value.trim();

    if (!input) {
        alert("Please enter a URL.");
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

        const parts = parsed.hostname.split(".");

        if (parts.length >= 2) {

            domain.textContent = parts[parts.length - 2];

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

        query.textContent =
            parsed.search
                ? new URLSearchParams(parsed.search).size
                : "0";

        fragment.textContent =
            parsed.hash
                ? parsed.hash.substring(1)
                : "None";

        length.textContent =
            input.length + " Characters";

        
            const riskAnalysis = analyzeURLRisk(
                parsed,
                input
            );

            updateRiskMeter(riskAnalysis.score);
            renderFindings(riskAnalysis.findings);

    }

    catch {

        alert("Invalid URL.");

        resetResults();

    }

}

analyzeBtn.addEventListener("click", analyzeURL);

clearBtn.addEventListener("click", () => {

    urlInput.value = "";

    resetResults();

});

urlInput.addEventListener("keydown", event => {

    if (event.key === "Enter" && !event.shiftKey) {

        event.preventDefault();

        analyzeURL();

    }

});