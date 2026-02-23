import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { supabaseAdmin } from "./supabaseAdmin.js";

dotenv.config();

const app = express();
app.use(
  cors({
    origin: [
      "https://chuluquiz.onrender.com", // رابط الفرونت الحقيقي
      "http://localhost:5173",          // للـ dev
    ],
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

// ✅ Register بدون Auth (Hash في السيرفر)
app.post("/api/register", async (req, res) => {
  try {
    const { username, phone, password } = req.body || {};

    if (!username || username.trim().length < 2) {
      return res.status(400).json({ ok: false, message: "اسم المستخدم غير صالح" });
    }

    const phoneDigits = String(phone || "").replace(/\D/g, "");
    if (phoneDigits.length !== 10) {
      return res.status(400).json({ ok: false, message: "رقم الهاتف يجب أن يكون 10 أرقام" });
    }

    if (!password || String(password).length < 6) {
      return res.status(400).json({ ok: false, message: "كلمة السر يجب أن تكون 6 أحرف على الأقل" });
    }

    // تأكد من عدم وجود نفس الهاتف
    const { data: existing, error: exErr } = await supabaseAdmin
      .from("users")
      .select("id")
      .eq("phone", phoneDigits)
      .maybeSingle();

    if (exErr) throw exErr;
    if (existing) {
      return res.status(409).json({ ok: false, message: "رقم الهاتف مسجل مسبقاً" });
    }

    // (اختياري) تأكد من عدم وجود نفس username
    const { data: existingUser, error: exErr2 } = await supabaseAdmin
      .from("users")
      .select("id")
      .eq("username", username.trim())
      .maybeSingle();

    if (exErr2) throw exErr2;
    if (existingUser) {
      return res.status(409).json({ ok: false, message: "اسم المستخدم مستعمل مسبقاً" });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const { error: insErr } = await supabaseAdmin.from("users").insert({
      username: username.trim(),
      phone: phoneDigits,
      password_hash: passwordHash,
      role: "user",
      state: 0, // 👈 طلب قيد المراجعة
    });

    if (insErr) throw insErr;

    // رسالة احترافية مثل ما طلبت
    return res.json({
      ok: true,
      message: "تم تقديم طلب تسجيلك بنجاح ✅\nيرجى الانتظار حتى تتم الموافقة عليه.\nشكرًا لك.",
    });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// ✅ Login: لازم username + password صحيحين + state = 1
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (!username || username.trim().length < 2) {
      return res.status(400).json({ ok: false, message: "اسم المستخدم غير صالح" });
    }

    if (!password || String(password).length < 6) {
      return res.status(400).json({ ok: false, message: "كلمة السر غير صالحة" });
    }

    const { data: user, error } = await supabaseAdmin
      .from("users")
      .select("id, username, password_hash, role, state")
      .eq("username", username.trim())
      .maybeSingle();

    if (error || !user) {
      return res.status(401).json({ ok: false, message: "اسم المستخدم أو كلمة السر غير صحيحة." });
    }

    // شرط الموافقة
    if (Number(user.state) !== 1) {
      return res.status(403).json({
        ok: false,
        message: "تم تقديم طلبك، يرجى الانتظار حتى تتم الموافقة من الإدارة.",
      });
    }

    const okPass = await bcrypt.compare(password, user.password_hash);
    if (!okPass) {
      return res.status(401).json({ ok: false, message: "اسم المستخدم أو كلمة السر غير صحيحة." });
    }

    // JWT token
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      return res.status(500).json({ ok: false, message: "JWT_SECRET غير موجود في .env" });
    }

    const token = jwt.sign(
      { uid: user.id, username: user.username, role: user.role },
      secret,
      { expiresIn: "7d" }
    );

    // ✅ إنشاء session_token في Supabase (user_sessions)
    const { data: sessionRow, error: sessErr } = await supabaseAdmin
      .from("user_sessions")
      .insert({ user_id: user.id })
      .select("token")
      .single();

    if (sessErr || !sessionRow?.token) {
      return res.status(500).json({ ok: false, message: "فشل إنشاء جلسة المشاركة" });
    }

    return res.json({
      ok: true,
      message: "تم تسجيل الدخول بنجاح ✅",
      token, // JWT كما كان
      session_token: sessionRow.token, // ✅ هذا اللي سنستعمله لحفظ النتائج
      user_id: user.id,
      username: user.username,
    });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});
// ✅ Admin Login: لازم role = admin و state = 1
app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (!username || username.trim().length < 2) {
      return res.status(400).json({ ok: false, message: "اسم المستخدم غير صالح" });
    }
    if (!password || String(password).length < 6) {
      return res.status(400).json({ ok: false, message: "كلمة السر غير صالحة" });
    }

    const { data: user, error } = await supabaseAdmin
      .from("users")
      .select("id, username, password_hash, role, state")
      .eq("username", username.trim())
      .maybeSingle();

    if (error || !user) {
      return res.status(401).json({ ok: false, message: "اسم المستخدم أو كلمة السر غير صحيحة." });
    }

    if (Number(user.state) !== 1) {
      return res.status(403).json({ ok: false, message: "الحساب غير مفعل." });
    }

    if (String(user.role) !== "admin") {
      return res.status(403).json({ ok: false, message: "غير مصرح لك بالدخول كأدمن." });
    }

    const okPass = await bcrypt.compare(password, user.password_hash);
    if (!okPass) {
      return res.status(401).json({ ok: false, message: "اسم المستخدم أو كلمة السر غير صحيحة." });
    }

    const secret = process.env.JWT_SECRET;
    if (!secret) return res.status(500).json({ ok: false, message: "JWT_SECRET غير موجود في .env" });

    const token = jwt.sign(
      { uid: user.id, username: user.username, role: user.role },
      secret,
      { expiresIn: "7d" }
    );

    return res.json({
      ok: true,
      message: "تم تسجيل دخول الأدمن ✅",
      token,
      user_id: user.id,
      username: user.username,
      role: user.role,
    });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});
// ✅ (TEST ONLY) Get all users — NO AUTH
app.get("/api/admin/users", async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("users")
      .select("id, username, phone, role, state, created_at")
      .order("created_at", { ascending: false });

    if (error) return res.status(400).json({ ok: false, message: error.message });
    return res.json({ ok: true, users: data || [] });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// ✅ (TEST ONLY) Update user state — NO AUTH
app.patch("/api/admin/users/:id/state", async (req, res) => {
  try {
    const { id } = req.params;
    const { state } = req.body || {};
    const s = Number(state);

    if (![0, 1, 2, 3].includes(s)) {
      return res.status(400).json({ ok: false, message: "Invalid state. Use 0/1/2/3" });
    }

    const { error } = await supabaseAdmin
      .from("users")
      .update({ state: s })
      .eq("id", id);

    if (error) return res.status(400).json({ ok: false, message: error.message });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// ✅ (TEST ONLY) Promote to admin — NO AUTH
app.patch("/api/admin/users/:id/promote", async (req, res) => {
  try {
    const { id } = req.params;

    const { error } = await supabaseAdmin
      .from("users")
      .update({ role: "admin", state: 1 })
      .eq("id", id);

    if (error) return res.status(400).json({ ok: false, message: error.message });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// ✅ (TEST ONLY) Demote admin -> user — NO AUTH
app.patch("/api/admin/users/:id/demote", async (req, res) => {
  try {
    const { id } = req.params;

    const { error } = await supabaseAdmin
      .from("users")
      .update({ role: "user" })
      .eq("id", id);

    if (error) return res.status(400).json({ ok: false, message: error.message });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// ✅ (TEST ONLY) Delete user — NO AUTH
app.delete("/api/admin/users/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const { error } = await supabaseAdmin
      .from("users")
      .delete()
      .eq("id", id);

    if (error) return res.status(400).json({ ok: false, message: error.message });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// =============================
// ✅ App State (StateGate) — TEST ONLY / NO AUTH
// =============================

// Get all keys
app.get("/api/admin/app-state", async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("app_state")
      .select("key, state, updated_at")
      .order("key", { ascending: true });

    if (error) return res.status(400).json({ ok: false, message: error.message });
    return res.json({ ok: true, rows: data || [] });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// Upsert (create if missing) + set state
app.patch("/api/admin/app-state/:key", async (req, res) => {
  try {
    const { key } = req.params;
    const { state } = req.body || {};
    const s = Number(state);

    if (![0, 1].includes(s)) {
      return res.status(400).json({ ok: false, message: "Invalid state. Use 0/1" });
    }

    const safeKey = String(key || "").trim();
    if (!safeKey) return res.status(400).json({ ok: false, message: "Missing key" });

    const { error } = await supabaseAdmin
      .from("app_state")
      .upsert(
        { key: safeKey, state: s, updated_at: new Date().toISOString() },
        { onConflict: "key" }
      );

    if (error) return res.status(400).json({ ok: false, message: error.message });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// =============================
// ✅ Admin: Leaderboard + Live Stats — TEST ONLY / NO AUTH
// =============================

// List quizzes
app.get("/api/admin/quizzes", async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("quizzes")
      .select("id, title, status, created_at")
      .order("created_at", { ascending: false });

    if (error) return res.status(400).json({ ok: false, message: error.message });
    return res.json({ ok: true, quizzes: data || [] });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// Leaderboard for a quiz
app.get("/api/admin/leaderboard", async (req, res) => {
  try {
    const quizId = String(req.query.quiz_id || "").trim();
    if (!quizId) return res.status(400).json({ ok: false, message: "Missing quiz_id" });

    const { data, error } = await supabaseAdmin
      .from("quiz_scores")
      .select("user_id, score, updated_at, users:users(id, username, phone)")
      .eq("quiz_id", quizId)
      .order("score", { ascending: false })
      .order("updated_at", { ascending: true })
      .limit(500);

    if (error) return res.status(400).json({ ok: false, message: error.message });

    const rows = (data || []).map((r, i) => ({
      rank: i + 1,
      user_id: r.user_id,
      username: r?.users?.username || "—",
      phone: r?.users?.phone || "—",
      score: r.score ?? 0,
      updated_at: r.updated_at,
    }));

    return res.json({ ok: true, rows });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// Answers of a user in a quiz (with points)
app.get("/api/admin/user-answers", async (req, res) => {
  try {
    const quizId = String(req.query.quiz_id || "").trim();
    const userIdRaw = String(req.query.user_id || "").trim();
    const userId = Number(userIdRaw);

    if (!quizId) return res.status(400).json({ ok: false, message: "Missing quiz_id" });
    if (!userIdRaw || Number.isNaN(userId)) {
      return res.status(400).json({ ok: false, message: "Missing/invalid user_id" });
    }

    const { data: answers, error: aErr } = await supabaseAdmin
      .from("quiz_answers")
      .select(
        "question_id, choice_id, is_correct, points_awarded, answered_at, questions:questions(question_text, level_id), choices:choices(label, choice_text)"
      )
      .eq("quiz_id", quizId)
      .eq("user_id", userId)
      .order("answered_at", { ascending: true })
      .limit(500);

    if (aErr) return res.status(400).json({ ok: false, message: aErr.message });

    const qIds = Array.from(new Set((answers || []).map((x) => x.question_id).filter(Boolean)));

    let correctMap = {};
    if (qIds.length) {
      const { data: correctChoices, error: cErr } = await supabaseAdmin
        .from("choices")
        .select("id, question_id, label, choice_text")
        .in("question_id", qIds)
        .eq("is_correct", true);

      if (cErr) return res.status(400).json({ ok: false, message: cErr.message });

      correctMap = (correctChoices || []).reduce((acc, c) => {
        acc[c.question_id] = c;
        return acc;
      }, {});
    }

    const { data: user, error: uErr } = await supabaseAdmin
      .from("users")
      .select("id, username, phone")
      .eq("id", userId)
      .maybeSingle();
    if (uErr) return res.status(400).json({ ok: false, message: uErr.message });

    const { data: scoreRow, error: sErr } = await supabaseAdmin
      .from("quiz_scores")
      .select("score")
      .eq("quiz_id", quizId)
      .eq("user_id", userId)
      .maybeSingle();
    if (sErr) return res.status(400).json({ ok: false, message: sErr.message });

    const rows = (answers || []).map((a, idx) => {
      const corr = correctMap[a.question_id];
      return {
        index: idx + 1,
        question_id: a.question_id,
        question_text: a?.questions?.question_text || "—",
        level_id: a?.questions?.level_id ?? null,
        chosen: {
          id: a.choice_id,
          label: a?.choices?.label || "—",
          text: a?.choices?.choice_text || "—",
        },
        correct: corr ? { id: corr.id, label: corr.label, text: corr.choice_text } : null,
        is_correct: !!a.is_correct,
        points_awarded: a.points_awarded ?? 0,
        answered_at: a.answered_at,
      };
    });

    return res.json({
      ok: true,
      user: user || { id: userId, username: "—", phone: "—" },
      score: scoreRow?.score ?? 0,
      rows,
    });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// Live stats
app.get("/api/admin/live-stats", async (req, res) => {
  try {
    let quizId = String(req.query.quiz_id || "").trim();

    if (!quizId) {
      const { data: ctrl, error: cErr } = await supabaseAdmin
        .from("quiz_control")
        .select("status, starts_at, active_quiz_id, updated_at")
        .eq("id", 1)
        .maybeSingle();
      if (cErr) return res.status(400).json({ ok: false, message: cErr.message });
      quizId = ctrl?.active_quiz_id || "";
      if (!quizId) return res.json({ ok: true, quiz_id: "", control: ctrl || null, stats: null });
    }

    const [{ data: quiz, error: qErr }, { data: control, error: ctrlErr }] = await Promise.all([
      supabaseAdmin.from("quizzes").select("id, title, status").eq("id", quizId).maybeSingle(),
      supabaseAdmin.from("quiz_control").select("status, starts_at, active_quiz_id, updated_at").eq("id", 1).maybeSingle(),
    ]);

    if (qErr) return res.status(400).json({ ok: false, message: qErr.message });
    if (ctrlErr) return res.status(400).json({ ok: false, message: ctrlErr.message });

    const [playersRes, answersRes, scoresRes, questionsRes] = await Promise.all([
      supabaseAdmin.from("quiz_players").select("id", { count: "exact", head: true }).eq("quiz_id", quizId),
      supabaseAdmin.from("quiz_answers").select("id, question_id, is_correct", { count: "exact" }).eq("quiz_id", quizId),
      supabaseAdmin
        .from("quiz_scores")
        .select("user_id, score, users:users(username)")
        .eq("quiz_id", quizId)
        .order("score", { ascending: false })
        .limit(10),
      supabaseAdmin.from("questions").select("id, level_id, question_text, created_at").eq("quiz_id", quizId).order("created_at", { ascending: true }),
    ]);

    if (playersRes.error) return res.status(400).json({ ok: false, message: playersRes.error.message });
    if (answersRes.error) return res.status(400).json({ ok: false, message: answersRes.error.message });
    if (scoresRes.error) return res.status(400).json({ ok: false, message: scoresRes.error.message });
    if (questionsRes.error) return res.status(400).json({ ok: false, message: questionsRes.error.message });

    const playersCount = playersRes.count || 0;
    const allAnswers = answersRes.data || [];
    const answersCount = answersRes.count || allAnswers.length || 0;

    const perQ = new Map();
    for (const a of allAnswers) {
      const qid = a.question_id;
      if (!qid) continue;
      const cur = perQ.get(qid) || { answered: 0, correct: 0 };
      cur.answered += 1;
      if (a.is_correct) cur.correct += 1;
      perQ.set(qid, cur);
    }

    const questions = questionsRes.data || [];
    const questionStats = questions.map((q, idx) => {
      const agg = perQ.get(q.id) || { answered: 0, correct: 0 };
      const answeredPlayers = playersCount > 0 ? Math.min(playersCount, agg.answered) : agg.answered;
      const progress = playersCount > 0 ? answeredPlayers / playersCount : 0;
      const correctRate = agg.answered > 0 ? agg.correct / agg.answered : 0;
      return {
        index: idx + 1,
        question_id: q.id,
        level_id: q.level_id,
        question_text: q.question_text,
        answered: agg.answered,
        correct: agg.correct,
        progress,
        correct_rate: correctRate,
      };
    });

    const top = (scoresRes.data || []).map((r, i) => ({
      rank: i + 1,
      user_id: r.user_id,
      username: r?.users?.username || "—",
      score: r.score ?? 0,
    }));

    return res.json({
      ok: true,
      quiz_id: quizId,
      quiz: quiz || null,
      control: control || null,
      stats: {
        players_count: playersCount,
        answers_count: answersCount,
        questions_count: questions.length,
        top,
        question_stats: questionStats,
      },
    });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// =============================
// ✅ Admin: Create Quiz (NO AUTH - مثل باقي صفحات TEST ONLY)
// =============================
app.post("/api/admin/create-quiz", async (req, res) => {
  let createdQuizId = null;

  try {
    const { title, description, questions } = req.body || {};

    const t = String(title || "").trim();
    if (t.length < 2) {
      return res.status(400).json({ ok: false, message: "Quiz title غير صالح" });
    }

    if (!Array.isArray(questions) || questions.length < 1) {
      return res.status(400).json({ ok: false, message: "لازم سؤال واحد على الأقل" });
    }

    // 1) create quiz
    const { data: quizRow, error: qErr } = await supabaseAdmin
      .from("quizzes")
      .insert({
        title: t,
        description: String(description || "").trim() || null,
        status: "draft",
      })
      .select("id")
      .single();

    if (qErr) throw qErr;
    createdQuizId = quizRow?.id;
    if (!createdQuizId) throw new Error("لم يتم استرجاع quiz_id");

    // 2) insert questions + choices
    for (let i = 0; i < questions.length; i++) {
      const q = questions[i] || {};
      const level_id = Number(q.level_id);
      const question_text = String(q.question_text || "").trim();
      const hint = String(q.hint || "").trim() || null;

      if (!level_id || Number.isNaN(level_id)) {
        throw new Error(`Q${i + 1}: level_id غير صالح`);
      }
      if (!question_text) {
        throw new Error(`Q${i + 1}: نص السؤال فارغ`);
      }

      const choices = Array.isArray(q.choices) ? q.choices : [];
      const filled = choices
        .map((c) => ({
          label: String(c?.label || "").trim().toUpperCase(),
          choice_text: String(c?.choice_text || "").trim(),
          is_correct: !!c?.is_correct,
        }))
        .filter((c) => c.label && c.choice_text);

      if (filled.length < 2) {
        throw new Error(`Q${i + 1}: لازم على الأقل اقتراحين`);
      }

      const correctCount = filled.filter((c) => c.is_correct).length;
      if (correctCount !== 1) {
        throw new Error(`Q${i + 1}: لازم جواب صحيح واحد فقط`);
      }

      // insert question
      const { data: insertedQ, error: insQErr } = await supabaseAdmin
        .from("questions")
        .insert({
          quiz_id: createdQuizId,
          level_id,
          question_text,
          hint,
        })
        .select("id")
        .single();

      if (insQErr) throw insQErr;

      const questionId = insertedQ?.id;
      if (!questionId) throw new Error(`Q${i + 1}: لم يتم استرجاع question_id`);

      // insert choices
      const payloadChoices = filled.map((c) => ({
        question_id: questionId,
        label: c.label,
        choice_text: c.choice_text,
        is_correct: c.is_correct,
      }));

      const { error: chErr } = await supabaseAdmin.from("choices").insert(payloadChoices);
      if (chErr) throw chErr;
    }

    return res.json({ ok: true, quiz_id: createdQuizId });
  } catch (err) {
    // cleanup: إذا فشلنا بعد إنشاء quiz نحذفو (cascade يحذف questions/choices)
    if (createdQuizId) {
      await supabaseAdmin.from("quizzes").delete().eq("id", createdQuizId);
    }
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// =============================
// ✅ Admin: Manage Quiz (NO AUTH - TEST ONLY)
// =============================

// Get full quiz (meta + questions + choices)
app.get("/api/admin/quizzes/:id/full", async (req, res) => {
  try {
    const quizId = String(req.params.id || "").trim();
    if (!quizId) return res.status(400).json({ ok: false, message: "Missing quiz id" });

    const [{ data: quiz, error: qErr }, { data: settings, error: sErr }, { data: qs, error: qsErr }] =
      await Promise.all([
        supabaseAdmin
          .from("quizzes")
          .select("id,title,description,status,created_at")
          .eq("id", quizId)
          .maybeSingle(),

        supabaseAdmin
          .from("quiz_settings")
          .select("quiz_id, seconds_per_question, updated_at")
          .eq("quiz_id", quizId)
          .maybeSingle(),

        supabaseAdmin
          .from("questions")
          .select("id,quiz_id,level_id,question_text,hint,created_at,choices(id,label,choice_text,is_correct)")
          .eq("quiz_id", quizId)
          .order("created_at", { ascending: true }),
      ]);

    if (qErr) return res.status(400).json({ ok: false, message: qErr.message });
    if (sErr) return res.status(400).json({ ok: false, message: sErr.message });
    if (qsErr) return res.status(400).json({ ok: false, message: qsErr.message });
    if (!quiz) return res.status(404).json({ ok: false, message: "Quiz not found" });

    // لو settings غير موجودة، أنشئها تلقائياً (اختياري)
    let sec = settings?.seconds_per_question;
    if (sec == null) {
      const { data: ins, error: insErr } = await supabaseAdmin
        .from("quiz_settings")
        .insert({ quiz_id: quizId, seconds_per_question: 3 })
        .select("seconds_per_question")
        .single();
      if (insErr) return res.status(400).json({ ok: false, message: insErr.message });
      sec = ins?.seconds_per_question ?? 3;
    }

    return res.json({
      ok: true,
      quiz,
      settings: { seconds_per_question: sec },
      questions: qs || [],
    });
  } catch (e) {
    return res.status(500).json({ ok: false, message: e?.message || "Server error" });
  }
});

// Update quiz meta (title/description/seconds_per_question)

app.patch("/api/admin/quizzes/:id", async (req, res) => {
  try {
    const quizId = String(req.params.id || "").trim();
    const { title, description, seconds_per_question } = req.body || {};
    if (!quizId) return res.status(400).json({ ok: false, message: "Missing quiz id" });

    // 1) update quizzes (title/description)
    const patchQuiz = {};
    if (title !== undefined) {
      const t = String(title || "").trim();
      if (t.length < 2) return res.status(400).json({ ok: false, message: "Title غير صالح" });
      patchQuiz.title = t;
    }
    if (description !== undefined) {
      const d = String(description || "").trim();
      patchQuiz.description = d ? d : null;
    }

    if (Object.keys(patchQuiz).length) {
      const { error } = await supabaseAdmin.from("quizzes").update(patchQuiz).eq("id", quizId);
      if (error) return res.status(400).json({ ok: false, message: error.message });
    }

    // 2) update quiz_settings (seconds_per_question)
    if (seconds_per_question !== undefined) {
      const s = Number(seconds_per_question);
      if (!Number.isFinite(s) || s < 1 || s > 300) {
        return res.status(400).json({ ok: false, message: "seconds_per_question لازم بين 1 و 300" });
      }

      // upsert على quiz_id
      const { error: upErr } = await supabaseAdmin
        .from("quiz_settings")
        .upsert({ quiz_id: quizId, seconds_per_question: Math.floor(s) }, { onConflict: "quiz_id" });

      if (upErr) return res.status(400).json({ ok: false, message: upErr.message });
    }

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, message: e?.message || "Server error" });
  }
});
// Add question to quiz (with choices)
app.post("/api/admin/quizzes/:id/questions", async (req, res) => {
  try {
    const quizId = String(req.params.id || "").trim();
    const { level_id, question_text, hint, choices } = req.body || {};

    if (!quizId) return res.status(400).json({ ok: false, message: "Missing quiz id" });

    const lv = Number(level_id);
    if (!lv || Number.isNaN(lv)) return res.status(400).json({ ok: false, message: "level_id غير صالح" });

    const qt = String(question_text || "").trim();
    if (!qt) return res.status(400).json({ ok: false, message: "question_text فارغ" });

    const ch = Array.isArray(choices) ? choices : [];
    const filled = ch
      .map((c) => ({
        label: String(c?.label || "").trim().toUpperCase(),
        choice_text: String(c?.choice_text || "").trim(),
        is_correct: !!c?.is_correct,
      }))
      .filter((c) => c.label && c.choice_text);

    if (filled.length < 2) return res.status(400).json({ ok: false, message: "لازم على الأقل اقتراحين" });

    const correctCount = filled.filter((c) => c.is_correct).length;
    if (correctCount !== 1) return res.status(400).json({ ok: false, message: "لازم جواب صحيح واحد فقط" });

    const { data: insertedQ, error: insQErr } = await supabaseAdmin
      .from("questions")
      .insert({
        quiz_id: quizId,
        level_id: lv,
        question_text: qt,
        hint: String(hint || "").trim() || null,
      })
      .select("id")
      .single();

    if (insQErr) return res.status(400).json({ ok: false, message: insQErr.message });

    const qid = insertedQ?.id;
    const payloadChoices = filled.map((c) => ({
      question_id: qid,
      label: c.label,
      choice_text: c.choice_text,
      is_correct: c.is_correct,
    }));

    const { error: insCErr } = await supabaseAdmin.from("choices").insert(payloadChoices);
    if (insCErr) return res.status(400).json({ ok: false, message: insCErr.message });

    return res.json({ ok: true, question_id: qid });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// Update question (text/hint/level)
app.patch("/api/admin/questions/:id", async (req, res) => {
  try {
    const qid = String(req.params.id || "").trim();
    const { level_id, question_text, hint } = req.body || {};
    if (!qid) return res.status(400).json({ ok: false, message: "Missing question id" });

    const patch = {};

    if (level_id !== undefined) {
      const lv = Number(level_id);
      if (!lv || Number.isNaN(lv)) return res.status(400).json({ ok: false, message: "level_id غير صالح" });
      patch.level_id = lv;
    }

    if (question_text !== undefined) {
      const qt = String(question_text || "").trim();
      if (!qt) return res.status(400).json({ ok: false, message: "question_text فارغ" });
      patch.question_text = qt;
    }

    if (hint !== undefined) {
      patch.hint = String(hint || "").trim() || null;
    }

    if (!Object.keys(patch).length) return res.json({ ok: true });

    const { error } = await supabaseAdmin.from("questions").update(patch).eq("id", qid);
    if (error) return res.status(400).json({ ok: false, message: error.message });

    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// Replace choices for a question
app.put("/api/admin/questions/:id/choices", async (req, res) => {
  try {
    const qid = String(req.params.id || "").trim();
    const { choices } = req.body || {};
    if (!qid) return res.status(400).json({ ok: false, message: "Missing question id" });

    const incoming = Array.isArray(choices) ? choices : [];

    // ننظف الداتا لكن بدون حذف السجلات من DB
    const normalized = incoming
      .map((c) => ({
        id: c?.id || null,
        label: String(c?.label || "").trim().toUpperCase(),
        choice_text: String(c?.choice_text || "").trim(),
        is_correct: !!c?.is_correct,
      }))
      .filter((c) => c.label); // label لازم موجود

    const nonEmpty = normalized.filter((c) => c.choice_text);
    if (nonEmpty.length < 2) {
      return res.status(400).json({ ok: false, message: "لازم على الأقل اقتراحين مكتوبين" });
    }
    const correctCount = nonEmpty.filter((c) => c.is_correct).length;
    if (correctCount !== 1) {
      return res.status(400).json({ ok: false, message: "لازم جواب صحيح واحد فقط (ضمن الاقتراحات المكتوبة)" });
    }

    // choices الحالية
    const { data: existing, error: exErr } = await supabaseAdmin
      .from("choices")
      .select("id,label")
      .eq("question_id", qid);

    if (exErr) return res.status(400).json({ ok: false, message: exErr.message });

    const byLabel = new Map((existing || []).map((x) => [String(x.label || "").toUpperCase(), x]));

    // ✅ نحدّث الموجودين فقط (بدون delete)
    // نقدر نعمل تحديثات متسلسلة باش تكون بسيطة ومضمونة
    for (const c of normalized) {
      const row = byLabel.get(c.label);
      if (row) {
        const { error: upErr } = await supabaseAdmin
          .from("choices")
          .update({
            choice_text: c.choice_text || null,
            is_correct: !!c.is_correct,
          })
          .eq("id", row.id);

        if (upErr) return res.status(400).json({ ok: false, message: upErr.message });
      } else {
        // label جديد (اختياري): نديرو insert
        // لكن فقط إذا النص مكتوب
        if (c.choice_text) {
          const { error: insErr } = await supabaseAdmin.from("choices").insert({
            question_id: qid,
            label: c.label,
            choice_text: c.choice_text,
            is_correct: !!c.is_correct,
          });
          if (insErr) return res.status(400).json({ ok: false, message: insErr.message });
        }
      }
    }

    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// Delete question (choices cascade by FK)
app.delete("/api/admin/questions/:id", async (req, res) => {
  try {
    const qid = String(req.params.id || "").trim();
    if (!qid) return res.status(400).json({ ok: false, message: "Missing question id" });

    const { error } = await supabaseAdmin.from("questions").delete().eq("id", qid);
    if (error) return res.status(400).json({ ok: false, message: error.message });

    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

// Move question to another quiz
app.patch("/api/admin/questions/:id/move", async (req, res) => {
  try {
    const qid = String(req.params.id || "").trim();
    const { to_quiz_id } = req.body || {};
    const to = String(to_quiz_id || "").trim();

    if (!qid) return res.status(400).json({ ok: false, message: "Missing question id" });
    if (!to) return res.status(400).json({ ok: false, message: "Missing to_quiz_id" });

    const { error } = await supabaseAdmin.from("questions").update({ quiz_id: to }).eq("id", qid);
    if (error) return res.status(400).json({ ok: false, message: error.message });

    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, message: err?.message || "Server error" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));