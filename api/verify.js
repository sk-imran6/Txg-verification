const crypto = require("crypto");
const { neon } = require("@neondatabase/serverless");

const sql = neon(process.env.DATABASE_URL);

const BOT_CONFIG = {
  // Add your bots here:
  // "123456789": {
  //   name: "My Bot",
  //   continueUrl: "https://t.me/MyBot"
  // }
};

const RATE_LIMIT = new Map();

function json(res, status, data) {
  res.status(status).json(data);
}

function validBotId(id) {
  return /^[0-9]{5,20}$/.test(String(id || ""));
}

function validDeviceId(id) {
  return (
    typeof id === "string" &&
    /^[a-f0-9]{64}$/i.test(id)
  );
}

function hashDevice(deviceId) {
  return crypto
    .createHmac(
      "sha256",
      process.env.DEVICE_PEPPER
    )
    .update(deviceId)
    .digest("hex");
}

function checkRate(ip) {
  const now = Date.now();
  const old = RATE_LIMIT.get(ip);

  if (!old || now - old.time > 60000) {
    RATE_LIMIT.set(ip, {
      time: now,
      count: 1
    });
    return true;
  }

  if (old.count >= 30) {
    return false;
  }

  old.count++;
  return true;
}

function validateTelegramInitData(
  initData,
  botToken
) {
  if (!initData || !botToken) {
    return null;
  }

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");

  if (!receivedHash) {
    return null;
  }

  params.delete("hash");

  const authDate = Number(
    params.get("auth_date") || 0
  );

  if (!authDate) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);

  if (authDate > now + 30) {
    return null;
  }

  if (now - authDate > 300) {
    return null;
  }

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => key + "=" + value)
    .join("\n");

  const secretKey = crypto
    .createHmac(
      "sha256",
      "WebAppData"
    )
    .update(botToken)
    .digest();

  const calculatedHash = crypto
    .createHmac(
      "sha256",
      secretKey
    )
    .update(dataCheckString)
    .digest("hex");

  if (
    receivedHash.length !== calculatedHash.length
  ) {
    return null;
  }

  if (
    !crypto.timingSafeEqual(
      Buffer.from(receivedHash),
      Buffer.from(calculatedHash)
    )
  ) {
    return null;
  }

  let user = null;

  try {
    user = JSON.parse(
      params.get("user") || "null"
    );
  } catch (e) {
    return null;
  }

  if (
    !user ||
    !user.id
  ) {
    return null;
  }

  return user;
}

async function createTables() {
  await sql`
    CREATE TABLE IF NOT EXISTS txg_devices (
      device_hash TEXT PRIMARY KEY,
      first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS txg_device_users (
      device_hash TEXT NOT NULL,
      bot_id TEXT NOT NULL,
      telegram_user_id TEXT NOT NULL,
      first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (
        device_hash,
        bot_id,
        telegram_user_id
      )
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS txg_device_bots (
      device_hash TEXT NOT NULL,
      bot_id TEXT NOT NULL,
      first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (
        device_hash,
        bot_id
      )
    )
  `;
}

module.exports = async function handler(req, res) {
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate"
  );

  if (req.method !== "POST") {
    return json(res, 405, {
      ok: false,
      error: "METHOD_NOT_ALLOWED"
    });
  }

  const ip =
    req.headers["x-forwarded-for"] ||
    req.socket?.remoteAddress ||
    "unknown";

  if (!checkRate(String(ip))) {
    return json(res, 429, {
      ok: false,
      error: "TOO_MANY_REQUESTS"
    });
  }

  try {
    const body =
      typeof req.body === "string"
        ? JSON.parse(req.body)
        : req.body || {};

    const botId = String(
      body.botId || ""
    ).trim();

    const deviceId = String(
      body.deviceId || ""
    ).trim();

    const initData = String(
      body.initData || ""
    );

    if (!validBotId(botId)) {
      return json(res, 400, {
        ok: false,
        error: "INVALID_BOT"
      });
    }

    if (!validDeviceId(deviceId)) {
      return json(res, 400, {
        ok: false,
        error: "INVALID_DEVICE"
      });
    }

    const config = BOT_CONFIG[botId];

    if (!config) {
      return json(res, 404, {
        ok: false,
        error: "BOT_NOT_CONFIGURED"
      });
    }

    const botToken =
      process.env["BOT_TOKEN_" + botId];

    if (!botToken) {
      return json(res, 500, {
        ok: false,
        error: "BOT_NOT_CONFIGURED"
      });
    }

    let telegramUser = null;

    /*
      Telegram Mini App verification
    */
    if (initData) {
      telegramUser =
        validateTelegramInitData(
          initData,
          botToken
        );

      if (!telegramUser) {
        return json(res, 401, {
          ok: false,
          error: "INVALID_TELEGRAM_DATA"
        });
      }
    }

    await createTables();

    const deviceHash =
      hashDevice(deviceId);

    const existingDevice =
      await sql`
        SELECT device_hash
        FROM txg_devices
        WHERE device_hash = ${deviceHash}
        LIMIT 1
      `;

    const alreadyVerified =
      existingDevice.length > 0;

    if (!alreadyVerified) {
      await sql`
        INSERT INTO txg_devices (
          device_hash
        )
        VALUES (
          ${deviceHash}
        )
        ON CONFLICT (device_hash)
        DO UPDATE SET
          last_seen = NOW()
      `;
    } else {
      await sql`
        UPDATE txg_devices
        SET last_seen = NOW()
        WHERE device_hash = ${deviceHash}
      `;
    }

    /*
      Save bot-device relationship
    */
    const existingBot =
      await sql`
        SELECT bot_id
        FROM txg_device_bots
        WHERE device_hash = ${deviceHash}
          AND bot_id = ${botId}
        LIMIT 1
      `;

    if (existingBot.length === 0) {
      await sql`
        INSERT INTO txg_device_bots (
          device_hash,
          bot_id
        )
        VALUES (
          ${deviceHash},
          ${botId}
        )
      `;
    } else {
      await sql`
        UPDATE txg_device_bots
        SET last_seen = NOW()
        WHERE device_hash = ${deviceHash}
          AND bot_id = ${botId}
      `;
    }

    /*
      Save Telegram user only when
      Telegram initData is available.
    */
    if (telegramUser) {
      const telegramUserId =
        String(telegramUser.id);

      const existingUser =
        await sql`
          SELECT telegram_user_id
          FROM txg_device_users
          WHERE device_hash = ${deviceHash}
            AND bot_id = ${botId}
            AND telegram_user_id =
              ${telegramUserId}
          LIMIT 1
        `;

      if (existingUser.length === 0) {
        await sql`
          INSERT INTO txg_device_users (
            device_hash,
            bot_id,
            telegram_user_id
          )
          VALUES (
            ${deviceHash},
            ${botId},
            ${telegramUserId}
          )
        `;
      } else {
        await sql`
          UPDATE txg_device_users
          SET last_seen = NOW()
          WHERE device_hash = ${deviceHash}
            AND bot_id = ${botId}
            AND telegram_user_id =
              ${telegramUserId}
        `;
      }
    }

    return json(res, 200, {
      ok: true,
      status: alreadyVerified
        ? "same_device"
        : "verified",
      bot_id: botId,
      continue_url:
        config.continueUrl || null
    });

  } catch (error) {
    return json(res, 500, {
      ok: false,
      error: "VERIFICATION_FAILED"
    });
  }
};

Important: "BOT_CONFIG" me sirf bot ID + continue URL rahega; actual token ".env" me "BOT_TOKEN_<BOT_ID>" ke naam se rahega. Token URL ya frontend me nahi jayega.
