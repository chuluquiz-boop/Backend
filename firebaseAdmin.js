// firebaseAdmin.js
import admin from "firebase-admin";
import fs from "fs";
import path from "path";

const filePath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH
  ? process.env.FIREBASE_SERVICE_ACCOUNT_PATH
  : path.join(process.cwd(), "serviceAccount.json");

const raw = fs.readFileSync(filePath, "utf8");
const serviceAccount = JSON.parse(raw);

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

export const fcm = admin.messaging();