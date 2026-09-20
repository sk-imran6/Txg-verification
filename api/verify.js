const crypto = require("crypto");
const { neon } = require("@neondatabase/serverless");

/*
========================================================
TXG MULTI-BOT AUTO DEVICE VERIFICATION
Telegram Mini App + Normal Website

IMPORTANT:
- Bot tokens stay server-side.
- Telegram initData is validated server-side.
- Device identifiers are hashed before database storage.
- No password / OTP / manual login.
- Normal website mode verifies the browser profile.
- Telegram mode verifies Telegram initData + browser profile.
========================================================
*/

/*
--------------------------------------------------------
BOT CONFIG
--------------------------------------------------------

Add every supported bot here.

Example:

const BOT_CONFIG = {
    "123456789": {
        name: "My Bot",
        continueUrl: "https://t.me/MyBot"
    },

    "987654321": {
        name: "Second Bot",
        continueUrl: "https://t.me/SecondBot"
    }
};

--------------------------------------------------------
*/

const BOT_CONFIG = {
    /*
    "123456789": {
        name: "YOUR BOT",
        continueUrl: "https://t.me/YOUR_BOT"
    }
    */
};


/*
--------------------------------------------------------
RESPONSE HELPER
--------------------------------------------------------
*/

function send(res, statusCode, data) {
    res.statusCode = statusCode;

    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");

    res.setHeader(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    );

    res.end(JSON.stringify(data));
}


/*
--------------------------------------------------------
SAFE STRING
--------------------------------------------------------
*/

function safeString(value, maxLength) {
    if (typeof value !== "string") {
        return null;
    }

    if (!value.length || value.length > maxLength) {
        return null;
    }

    return value;
}


/*
--------------------------------------------------------
CONSTANT-TIME HEX COMPARISON
--------------------------------------------------------
*/

function safeHexEqual(a, b) {
    if (
        typeof a !== "string" ||
        typeof b !== "string" ||
        a.length !== b.length
    ) {
        return false;
    }

    try {
        const aa = Buffer.from(a, "hex");
        const bb = Buffer.from(b, "hex");

        if (aa.length !== bb.length || aa.length === 0) {
            return false;
        }

        return crypto.timingSafeEqual(aa, bb);
    } catch (e) {
        return false;
    }
}


/*
--------------------------------------------------------
BOT TOKEN
--------------------------------------------------------
*/

function getBotToken(botId) {
    if (
        typeof botId !== "string" ||
        !/^[0-9]{1,30}$/.test(botId)
    ) {
        return null;
    }

    const envName = "BOT_TOKEN_" + botId;
    const token = process.env[envName];

    if (!token || typeof token !== "string") {
        return null;
    }

    if (token.length < 20 || token.length > 300) {
        return null;
    }

    return token;
}


/*
--------------------------------------------------------
BOT CONFIG
--------------------------------------------------------
*/

function getBotConfig(botId) {
    if (!Object.prototype.hasOwnProperty.call(BOT_CONFIG, botId)) {
        return null;
    }

    const config = BOT_CONFIG[botId];

    if (!config || typeof config !== "object") {
        return null;
    }

    return config;
}


/*
--------------------------------------------------------
TELEGRAM INIT DATA VALIDATION
--------------------------------------------------------

Telegram Web App data is authenticated using:

secret_key = HMAC_SHA256(
    key = "WebAppData",
    data = bot_token
)

hash = HMAC_SHA256(
    key = secret_key,
    data = data_check_string
)

--------------------------------------------------------
*/

function validateTelegramInitData(initData, botToken) {
    if (
        typeof initData !== "string" ||
        initData.length < 10 ||
        initData.length > 10000
    ) {
        return {
            valid: false,
            reason: "invalid_init_data"
        };
    }

    if (!botToken) {
        return {
            valid: false,
            reason: "missing_bot_token"
        };
    }

    let params;

    try {
        params = new URLSearchParams(initData);
    } catch (e) {
        return {
            valid: false,
            reason: "invalid_init_data_format"
        };
    }

    const receivedHash = params.get("hash");
    const authDateString = params.get("auth_date");

    if (
        !receivedHash ||
        !/^[a-f0-9]{64}$/i.test(receivedHash)
    ) {
        return {
            valid: false,
            reason: "invalid_hash"
        };
    }

    if (!authDateString || !/^[0-9]+$/.test(authDateString)) {
        return {
            valid: false,
            reason: "invalid_auth_date"
        };
    }

    const authDate = Number(authDateString);

    if (!Number.isSafeInteger(authDate)) {
        return {
            valid: false,
            reason: "invalid_auth_date"
        };
    }

    /*
    Telegram authentication data should be fresh.
    5 minutes maximum age.
    30 seconds future clock tolerance.
    */

    const now = Math.floor(Date.now() / 1000);

    if (authDate > now + 30) {
        return {
            valid: false,
            reason: "future_auth_date"
        };
    }

    if (now - authDate > 300) {
        return {
            valid: false,
            reason: "expired_auth_data"
        };
    }

    const dataCheckArray = [];

    for (const [key, value] of params.entries()) {
        if (key === "hash") {
            continue;
        }

        dataCheckArray.push(key + "=" + value);
    }

    dataCheckArray.sort();

    const dataCheckString = dataCheckArray.join("\n");

    const secretKey = crypto
        .createHmac("sha256", "WebAppData")
        .update(botToken)
        .digest();

    const calculatedHash = crypto
        .createHmac("sha256", secretKey)
        .update(dataCheckString)
        .digest("hex");

    if (!safeHexEqual(calculatedHash, receivedHash)) {
        return {
            valid: false,
            reason: "telegram_signature_invalid"
        };
    }

    const userJson = params.get("user");

    if (!userJson) {
        return {
            valid: false,
            reason: "telegram_user_missing"
        };
    }

    let telegramUser;

    try {
        telegramUser = JSON.parse(userJson);
    } catch (e) {
        return {
            valid: false,
            reason: "telegram_user_invalid"
        };
    }

    if (
        !telegramUser ||
        telegramUser.id === undefined ||
        telegramUser.id === null
    ) {
        return {
            valid: false,
            reason: "telegram_user_id_missing"
        };
    }

    const userId = String(telegramUser.id);

    if (!/^[0-9]{1,30}$/.test(userId)) {
        return {
            valid: false,
            reason: "telegram_user_id_invalid"
        };
    }

    return {
        valid: true,
        userId: userId,
        authDate: authDate
    };
}


/*
--------------------------------------------------------
DEVICE ID VALIDATION
--------------------------------------------------------

The frontend generates a random device ID.

We do NOT trust it as proof of physical hardware.

It identifies a browser profile only.

--------------------------------------------------------
*/

function validDeviceId(deviceId) {
    if (
        typeof deviceId !== "string" ||
        deviceId.length < 32 ||
        deviceId.length > 256
    ) {
        return false;
    }

    return /^[A-Za-z0-9._~-]+$/.test(deviceId);
}


/*
--------------------------------------------------------
HASH DEVICE ID
--------------------------------------------------------
*/

function hashDevice(deviceId) {
    const pepper = process.env.DEVICE_PEPPER;

    if (
        typeof pepper !== "string" ||
        pepper.length < 32
    ) {
        throw new Error("DEVICE_PEPPER is not configured correctly");
    }

    return crypto
        .createHash("sha256")
        .update(pepper + ":" + deviceId)
        .digest("hex");
}


/*
--------------------------------------------------------
DATABASE SETUP
--------------------------------------------------------
*/

async function setupDatabase(sql) {
    await sql`
        CREATE TABLE IF NOT EXISTS txg_devices (
            device_hash TEXT PRIMARY KEY,
            first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `;

    await sql`
        CREATE TABLE IF NOT EXISTS txg_device_users (
            device_hash TEXT NOT NULL,
            user_id TEXT NOT NULL,
            first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (device_hash, user_id)
        )
    `;

    await sql`
        CREATE TABLE IF NOT EXISTS txg_device_bots (
            device_hash TEXT NOT NULL,
            bot_id TEXT NOT NULL,
            first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (device_hash, bot_id)
        )
    `;
}


/*
--------------------------------------------------------
REQUEST RATE LIMIT
--------------------------------------------------------

This is a lightweight per-instance protection.

For stronger distributed rate limiting, use
an external rate-limit store in production.
--------------------------------------------------------
*/

const requestTracker = new Map();

function checkRateLimit(key) {
    const now = Date.now();

    const existing = requestTracker.get(key);

    if (!existing) {
        requestTracker.set(key, {
            count: 1,
            started: now
        });

        return true;
    }

    /*
    60 requests per 60 seconds per temporary key.
    */

    if (now - existing.started > 60000) {
        requestTracker.set(key, {
            count: 1,
            started: now
        });

        return true;
    }

    existing.count += 1;

    if (existing.count > 60) {
        return false;
    }

    return true;
}


/*
--------------------------------------------------------
REQUEST BODY
--------------------------------------------------------
*/

async function readBody(req) {
    return new Promise((resolve, reject) => {
        let body = "";
        let size = 0;

        req.on("data", chunk => {
            size += chunk.length;

            /*
            Maximum request body: 64 KB
            */

            if (size > 65536) {
                reject(new Error("request_too_large"));

                try {
                    req.destroy();
                } catch (e) {}

                return;
            }

            body += chunk.toString();
        });

        req.on("end", () => {
            try {
                if (!body) {
                    resolve({});
                    return;
                }

                resolve(JSON.parse(body));
            } catch (e) {
                reject(new Error("invalid_json"));
            }
        });

        req.on("error", () => {
            reject(new Error("request_error"));
        });
    });
}


/*
--------------------------------------------------------
MAIN HANDLER
--------------------------------------------------------
*/

module.exports = async function handler(req, res) {

    /*
    Only POST requests.
    */

    if (req.method !== "POST") {
        return send(res, 405, {
            success: false,
            error: "method_not_allowed"
        });
    }


    /*
    Read request.
    */

    let body;

    try {
        body = await readBody(req);
    } catch (e) {
        return send(res, 400, {
            success: false,
            error: "invalid_request"
        });
    }


    /*
    ----------------------------------------------------
    REQUIRED FIELDS
    ----------------------------------------------------
    */

    const mode =
        typeof body.mode === "string"
            ? body.mode
            : "website";

    const botId =
        typeof body.botId === "string"
            ? body.botId
            : "";

    const deviceId =
        typeof body.deviceId === "string"
            ? body.deviceId
            : "";


    /*
    Mode must be either:

    telegram
    website
    */

    if (mode !== "telegram" && mode !== "website") {
        return send(res, 400, {
            success: false,
            error: "invalid_mode"
        });
    }


    /*
    ----------------------------------------------------
    BOT VALIDATION
    ----------------------------------------------------
    */

    const botConfig = getBotConfig(botId);

    if (!botConfig) {
        return send(res, 400, {
            success: false,
            error: "unsupported_bot"
        });
    }


    /*
    ----------------------------------------------------
    DEVICE VALIDATION
    ----------------------------------------------------
    */

    if (!validDeviceId(deviceId)) {
        return send(res, 400, {
            success: false,
            error: "invalid_device"
        });
    }


    /*
    ----------------------------------------------------
    RATE LIMIT
    ----------------------------------------------------
    */

    const rateKey =
        mode + ":" + botId + ":" + deviceId.slice(0, 64);

    if (!checkRateLimit(rateKey)) {
        return send(res, 429, {
            success: false,
            error: "rate_limited"
        });
    }


    /*
    ----------------------------------------------------
    TELEGRAM MODE
    ----------------------------------------------------
    */

    let telegramUserId = null;

    if (mode === "telegram") {

        const initData =
            typeof body.initData === "string"
                ? body.initData
                : "";

        if (!initData) {
            return send(res, 401, {
                success: false,
                error: "telegram_init_data_required"
            });
        }


        /*
        Get the token ONLY on the server.
        */

        const botToken = getBotToken(botId);

        if (!botToken) {
            return send(res, 500, {
                success: false,
                error: "bot_token_not_configured"
            });
        }


        /*
        Validate Telegram cryptographic signature.
        */

        const telegramResult =
            validateTelegramInitData(
                initData,
                botToken
            );

        if (!telegramResult.valid) {
            return send(res, 401, {
                success: false,
                error: "telegram_verification_failed"
            });
        }

        telegramUserId = telegramResult.userId;
    }


    /*
    ----------------------------------------------------
    DATABASE
    ----------------------------------------------------
    */

    const databaseUrl =
        process.env.DATABASE_URL;

    if (
        typeof databaseUrl !== "string" ||
        databaseUrl.length < 10
    ) {
        return send(res, 500, {
            success: false,
            error: "database_not_configured"
        });
    }


    let sql;

    try {
        sql = neon(databaseUrl);
    } catch (e) {
        return send(res, 500, {
            success: false,
            error: "database_connection_failed"
        });
    }


    try {

        /*
        Create tables if they do not exist.
        */

        await setupDatabase(sql);


        /*
        Hash browser device identifier.

        Raw device ID is never stored.
        */

        const deviceHash =
            hashDevice(deviceId);


        /*
        ------------------------------------------------
        CHECK EXISTING DEVICE + BOT
        ------------------------------------------------
        */

        const existingBot =
            await sql`
                SELECT
                    device_hash,
                    bot_id
                FROM txg_device_bots
                WHERE device_hash = ${deviceHash}
                  AND bot_id = ${botId}
                LIMIT 1
            `;


        const alreadyVerified =
            existingBot.length > 0;


        /*
        ------------------------------------------------
        CREATE / UPDATE DEVICE
        ------------------------------------------------
        */

        await sql`
            INSERT INTO txg_devices (
                device_hash,
                first_seen_at,
                last_seen_at
            )
            VALUES (
                ${deviceHash},
                NOW(),
                NOW()
            )
            ON CONFLICT (device_hash)
            DO UPDATE SET
                last_seen_at = NOW()
        `;


        /*
        ------------------------------------------------
        TELEGRAM USER ASSOCIATION
        ------------------------------------------------
        */

        if (telegramUserId) {

            await sql`
                INSERT INTO txg_device_users (
                    device_hash,
                    user_id,
                    first_seen_at,
                    last_seen_at
                )
                VALUES (
                    ${deviceHash},
                    ${telegramUserId},
                    NOW(),
                    NOW()
                )
                ON CONFLICT (
                    device_hash,
                    user_id
                )
                DO UPDATE SET
                    last_seen_at = NOW()
            `;
        }


        /*
        ------------------------------------------------
        BOT ASSOCIATION
        ------------------------------------------------
        */

        await sql`
            INSERT INTO txg_device_bots (
                device_hash,
                bot_id,
                first_seen_at,
                last_seen_at
            )
            VALUES (
                ${deviceHash},
                ${botId},
                NOW(),
                NOW()
            )
            ON CONFLICT (
                device_hash,
                bot_id
            )
            DO UPDATE SET
                last_seen_at = NOW()
        `;


        /*
        ------------------------------------------------
        FINAL RESULT
        ------------------------------------------------
        */

        if (alreadyVerified) {

            return send(res, 200, {
                success: true,
                status: "same_device",
                title: "SAME DEVICE",
                subtitle: "This device is already verified.",
                mode: mode,
                bot_id: botId,
                continue_url:
                    typeof botConfig.continueUrl === "string"
                        ? botConfig.continueUrl
                        : null
            });
        }


        /*
        FIRST VERIFICATION
        */

        return send(res, 200, {
            success: true,
            status: "verified",
            title: "VERIFIED",
            subtitle: "Device verification is complete.",
            mode: mode,
            bot_id: botId,
            continue_url:
                typeof botConfig.continueUrl === "string"
                    ? botConfig.continueUrl
                    : null
        });

    } catch (error) {

        /*
        Do not expose database errors,
        SQL details or secrets to the client.
        */

        return send(res, 500, {
            success: false,
            error: "verification_service_error"
        });
    }
};

Important

For Telegram, frontend must send:

mode: "telegram"
initData: Telegram.WebApp.initData

For a normal website, frontend sends:

mode: "website"

with the generated "deviceId".

And in Vercel you still need:

DATABASE_URL
DEVICE_PEPPER
BOT_TOKEN_<BOT_ID>

The normal website mode is automatic verification, not login. It can recognize the same browser profile, but it cannot honestly guarantee that two different browsers are the same physical phone.
