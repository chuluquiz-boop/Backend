// firebaseAdmin.js
import admin from "firebase-admin";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

/**
 * Prefer FIREBASE_SERVICE_ACCOUNT_JSON (Render env var).
 * Fallback to FIREBASE_SERVICE_ACCOUNT_PATH, then local serviceAccount.json for local dev.
 */

function loadServiceAccount() {
  // ✅ 1) Render / Production: JSON in env
  const rawEnv = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (rawEnv && rawEnv.trim()) {
    try {
      return JSON.parse(rawEnv);
    } catch (e) {
      throw new Error(
        "Invalid FIREBASE_SERVICE_ACCOUNT_JSON (not valid JSON). " +
          (e?.message || "")
      );
    }
  }

  // ✅ 2) Optional: explicit path in env
  const filePathEnv = process.env.FIREBASE_SERVICE_ACCOUNT_PATH;
  if (filePathEnv && filePathEnv.trim()) {
    if (!fs.existsSync(filePathEnv)) {
      throw new Error(`FIREBASE_SERVICE_ACCOUNT_PATH not found: ${filePathEnv}`);
    }
    const raw = fs.readFileSync(filePathEnv, "utf8");
    return JSON.parse(raw);
  }

  // ✅ 3) Local dev fallback: serviceAccount.json next to this file
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const localPath = path.join(__dirname, "serviceAccount.json");

  if (!fs.existsSync(localPath)) {
    throw new Error(
      "No Firebase service account provided.\n" +
        "- Set FIREBASE_SERVICE_ACCOUNT_JSON in env (recommended)\n" +
        "- OR set FIREBASE_SERVICE_ACCOUNT_PATH\n" +
        "- OR place serviceAccount.json next to firebaseAdmin.js (local only)"
    );
  }

  const raw = fs.readFileSync(localPath, "utf8");
  return JSON.parse(raw);
}

const serviceAccount = loadServiceAccount();

// ✅ Validate required fields early (clear errors)
if (
  !serviceAccount?.project_id ||
  !serviceAccount?.client_email ||
  !serviceAccount?.private_key
) {
  throw new Error(
    "Invalid Firebase service account: missing project_id / client_email / private_key"
  );
}

// ✅ Ensure private_key newlines are correct (sometimes env loses \n)
serviceAccount.private_key = String(serviceAccount.private_key).replace(/\\n/g, "\n");

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

export const fcm = admin.messaging();