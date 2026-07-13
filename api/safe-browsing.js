const allowedOrigins = [
    "https://threathawk.xyz",
    "https://www.threathawk.xyz"
];

function getCorsOrigin(request) {
    const origin = request.headers.get("origin");

    /*
     * Allow any origin temporarily while testing locally.
     * We will restrict this after deployment works.
     */
    if (!origin || origin === "null") {
        return "*";
    }

    return allowedOrigins.includes(origin)
        ? origin
        : "*";
}

function createJSONResponse(request, data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": getCorsOrigin(request),
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type"
        }
    });
}

export default async function handler(request) {
    if (request.method === "OPTIONS") {
        return createJSONResponse(request, {}, 204);
    }

    if (request.method !== "POST") {
        return createJSONResponse(
            request,
            {
                error: "Method not allowed. Use POST."
            },
            405
        );
    }

    try {
        const requestBody = await request.json();
        const submittedURL = requestBody.url?.trim();

        if (!submittedURL) {
            return createJSONResponse(
                request,
                {
                    error: "A URL is required."
                },
                400
            );
        }

        try {
            new URL(submittedURL);
        } catch {
            return createJSONResponse(
                request,
                {
                    error: "The submitted URL is invalid."
                },
                400
            );
        }

        const apiKey =
            process.env.SAFE_BROWSING_API_KEY;

        if (!apiKey) {
            console.error(
                "SAFE_BROWSING_API_KEY is missing."
            );

            return createJSONResponse(
                request,
                {
                    error:
                        "Safe Browsing is not configured."
                },
                500
            );
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

            return createJSONResponse(
                request,
                {
                    error:
                        "The reputation service returned an error."
                },
                502
            );
        }

        const googleData =
            await googleResponse.json();

        const matches = googleData.matches || [];

        return createJSONResponse(request, {
            checked: true,
            safe: matches.length === 0,
            matchCount: matches.length,

            threats: matches.map(match => ({
                threatType: match.threatType,
                platformType: match.platformType,
                threatEntryType:
                    match.threatEntryType,
                url: match.threat?.url || submittedURL
            }))
        });
    } catch (error) {
        console.error(
            "Safe Browsing function error:",
            error
        );

        return createJSONResponse(
            request,
            {
                error:
                    "The URL reputation check failed."
            },
            500
        );
    }
}