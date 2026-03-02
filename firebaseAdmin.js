// firebaseAdmin.js
import admin from "firebase-admin";

const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
if (!raw) throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON missing");

const serviceAccount = JSON.parse(raw);

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

// ✅ هذا هو المهم: export باسم fcm
export const fcm = admin.messaging();