export default async function handler(req, res) {
    res.setHeader(
        "Access-Control-Allow-Origin",
        "*"
    );

    res.setHeader(
        "Access-Control-Allow-Methods",
        "POST, OPTIONS"
    );

    res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type"
    );

    if (req.method === "OPTIONS") {
        return res.status(204).end();
    }

    if (req.method !== "POST") {
        return res.status(405).json({
            error: "Method not allowed. Use POST."
        });
    }

    try {
        const submittedURL =
            req.body?.url?.trim();

        if (!submittedURL) {
            return res.status(400).json({
                error: "A URL is required."
            });
        }

        try {
            new URL(submittedURL);
        } catch {
            return res.status(400).json({
                error: "The submitted URL is invalid."
            });
        }

        const apiKey =
            process.env.SAFE_BROWSING_API_KEY;

        if (!apiKey) {
            console.error(
                "SAFE_BROWSING_API_KEY is missing."
            );

            return res.status(500).json({
                error:
                    "Safe Browsing is not configured."
            });
        }

        const googleResponse = await fetch(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    client: {
                        clientId: "threathawk",
                        clientVersion: "1.0.0"
                    },

                    threatInfo: {
                        threatTypes: [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"
                        ],

                        platformTypes: [
                            "ANY_PLATFORM"
                        ],

                        threatEntryTypes: [
                            "URL"
                        ],

                        threatEntries: [
                            {
                                url: submittedURL
                            }
                        ]
                    }
                })
            }
        );

        if (!googleResponse.ok) {
            const googleError =
                await googleResponse.text();

            console.error(
                "Google Safe Browsing error:",
                googleError
            );

            return res.status(502).json({
                error:
                    "The reputation service returned an error."
            });
        }

        const googleData =
            await googleResponse.json();

        const matches =
            googleData.matches || [];

        return res.status(200).json({
            checked: true,
            safe: matches.length === 0,
            matchCount: matches.length,

            threats: matches.map(match => ({
                threatType:
                    match.threatType,

                platformType:
                    match.platformType,

                threatEntryType:
                    match.threatEntryType,

                url:
                    match.threat?.url ||
                    submittedURL
            }))
        });
    } catch (error) {
        console.error(
            "Safe Browsing function error:",
            error
        );

        return res.status(500).json({
            error:
                "The URL reputation check failed."
        });
    }
}