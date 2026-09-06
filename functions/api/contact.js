/**
 * お問い合わせの受け口（Cloudflare Pages Functions）— プロテインスキマー図鑑
 *
 * ■ 設計（Gin-DB と同方式・2026-09-06）
 *   ブラウザが話す相手は このサイトの /api/contact だけ。
 *   受け取った内容は Googleスプレッドシートに1行追記し、控えを Cloudflare D1 に残す。
 *   メール送信も転送もしないので、**宛先メールアドレスがシステムのどこにも存在しない**。
 *   HTML にも JS にもリポジトリにも、送信先は一切書かれていない。
 *
 * ■ Cloudflare 側の設定（社長作業。詳細は 社長室/問い合わせの受け取り方.md）
 *   D1 バインディング  DB                … 控え（任意だが推奨。回数制限にも使う）
 *   シークレット       SHEETS_ID         … スプレッドシートのID
 *   シークレット       SHEETS_TAB        … タブ名（例：スキマー図鑑）
 *   シークレット       GOOGLE_SA_EMAIL   … サービスアカウントのメール
 *   シークレット       GOOGLE_SA_KEY     … サービスアカウントの秘密鍵（PEM）
 *   シークレット       TURNSTILE_SECRET  … 任意。未設定なら検証しない
 *
 *   保存先が1つも無いうちは「受付を準備中」と正直に返す（黙って捨てない）。
 */

const MAX = { name: 100, email: 200, url: 500, message: 4000, kind: 40 };
const KINDS = [
  "掲載している仕様・出典の誤り",
  "機種の追加・販売終了のご連絡",
  "メーカー・権利者の方からのご依頼",
  "その他",
];

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex",
    },
  });
}

function clean(v, max) {
  if (typeof v !== "string") return "";
  // 制御文字を落とす。改行(10)とタブ(9)は本文に必要なので残す
  let out = "";
  for (const ch of v) {
    const c = ch.codePointAt(0);
    if (c === 9 || c === 10) { out += ch; continue; }
    if (c < 32 || c === 127) continue;
    out += ch;
  }
  return out.trim().slice(0, max);
}

async function verifyTurnstile(secret, token, ip) {
  if (!secret) return true;          // 未設定なら検証しない
  if (!token) return false;
  const form = new FormData();
  form.append("secret", secret);
  form.append("response", token);
  if (ip) form.append("remoteip", ip);
  try {
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify",
      { method: "POST", body: form });
    const d = await r.json();
    return !!d.success;
  } catch (e) {
    return false;
  }
}

/* ---- Googleスプレッドシートへの追記 ----------------------------------------
 * サービスアカウントのJWTでアクセストークンを取り、対象タブに1行 append する。
 * 鍵は Cloudflare の暗号化シークレットにだけ置き、コードにもHTMLにも書かない。
 */
function b64urlFromBytes(buf) {
  let s = "";
  const a = new Uint8Array(buf);
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlFromString(str) {
  return b64urlFromBytes(new TextEncoder().encode(str));
}

/** PEM(PKCS#8) を Web Crypto の鍵に読み込む */
async function importKey(pem) {
  const body = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const raw = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "pkcs8", raw.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false, ["sign"]
  );
}

async function serviceAccountToken(email, pem) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64urlFromString(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = b64urlFromString(JSON.stringify({
    iss: email,
    scope: "https://www.googleapis.com/auth/spreadsheets",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  }));
  const key = await importKey(pem);
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(header + "." + claim));
  const jwt = header + "." + claim + "." + b64urlFromBytes(sig);

  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });
  if (!r.ok) return null;
  return (await r.json()).access_token || null;
}

async function appendToSheet(env, row) {
  const id = env.SHEETS_ID;
  const tab = env.SHEETS_TAB;
  if (!id || !tab || !env.GOOGLE_SA_EMAIL || !env.GOOGLE_SA_KEY) return false;
  try {
    const token = await serviceAccountToken(env.GOOGLE_SA_EMAIL, env.GOOGLE_SA_KEY);
    if (!token) return false;
    const url = "https://sheets.googleapis.com/v4/spreadsheets/" + encodeURIComponent(id)
      + "/values/" + encodeURIComponent(tab) + "!A1:H1:append"
      + "?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS";
    const r = await fetch(url, {
      method: "POST",
      headers: { authorization: "Bearer " + token, "content-type": "application/json" },
      body: JSON.stringify({ values: [row] }),
    });
    return r.ok;
  } catch (e) {
    return false;
  }
}

/* ---- スパム対策 ------------------------------------------------------------
 * 弾いたことは相手に教えない（200 / ok:true を返す）。
 * 同一IPの上限は、携帯キャリアや会社が多数の利用者で同じIPを共有する（CGNAT）ため
 * 広めに取る。このサイトは嘘ゼロが命なので、読者からの誤記の指摘が届かないほうが痛い。
 */
const LIMIT = { hour: 8, day: 30 };

function looksLikeSpam(message, name, url) {
  const text = [message, name, url].filter(Boolean).join(" ");
  const links = (text.match(/https?:\/\//gi) || []).length;
  if (links >= 3) return "links";

  const hasJa = /[ぁ-んァ-ヶ一-龥]/.test(message);
  if (!hasJa && links >= 1) return "no_ja_with_link";

  const NG = [
    "seo", "backlink", "被リンク", "上位表示", "格安", "副業", "稼げ",
    "投資", "仮想通貨", "ビットコイン", "出会い", "アダルト", "融資",
    "viagra", "casino", "loan", "crypto", "porn", "escort",
  ];
  const low = text.toLowerCase();
  let hits = 0;
  for (const w of NG) if (low.includes(w)) hits++;
  if (hits >= 2) return "keywords";

  if (/(.)\1{20,}/.test(message)) return "repeat";
  return null;
}

/* IPは生で残さずハッシュにする */
async function ipHash(ip) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("skimmer:" + ip));
  const a = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < 16; i++) s += a[i].toString(16).padStart(2, "0");
  return s;
}

async function tooManyFrom(env, iph) {
  if (!env.DB || !iph) return false;
  try {
    await env.DB.prepare(
      "CREATE TABLE IF NOT EXISTS submits (iph TEXT, at INTEGER)").run();
    const now = Date.now();
    await env.DB.prepare("DELETE FROM submits WHERE at < ?1")
      .bind(now - 86400000).run();
    const h = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM submits WHERE iph = ?1 AND at > ?2")
      .bind(iph, now - 3600000).first();
    const d = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM submits WHERE iph = ?1 AND at > ?2")
      .bind(iph, now - 86400000).first();
    if ((h && h.n >= LIMIT.hour) || (d && d.n >= LIMIT.day)) return true;
    await env.DB.prepare("INSERT INTO submits (iph, at) VALUES (?1, ?2)")
      .bind(iph, now).run();
    return false;
  } catch (e) {
    return false;   // 数えられないときは通す。正当な問い合わせを落とさない
  }
}

async function recordBlocked(env, reason, body, country) {
  if (!env.DB) return;
  try {
    await env.DB.prepare(
      "CREATE TABLE IF NOT EXISTS blocked (at TEXT, reason TEXT, country TEXT, " +
      "name TEXT, email TEXT, url TEXT, message TEXT)").run();
    await env.DB.prepare(
      "INSERT INTO blocked (at, reason, country, name, email, url, message) " +
      "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    ).bind(new Date().toISOString(), reason, country || "",
           clean(body.name, 100), clean(body.email, 200),
           clean(body.url, 500), clean(body.message, 1000)).run();
  } catch (e) {
    // 記録に失敗しても本処理は止めない
  }
}


export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json(400, { ok: false, error: "bad_request", message: "送信内容を読み取れませんでした。" });
  }

  // ① ハニーポット。人には見えない項目に入力があったら弾く（ボットには成功に見せる）
  if (clean(body.hp, 50) || clean(body.ct_ref2, 50)) {
    return json(200, { ok: true });
  }

  // ② フォーム表示から3秒未満の送信は機械とみなす
  const elapsed = Number(body.elapsed);
  if (Number.isFinite(elapsed) && elapsed >= 0 && elapsed < 3000) {
    return json(200, { ok: true });
  }

  // ③ Turnstile（設定されている場合のみ）
  const ip = request.headers.get("cf-connecting-ip") || "";
  if (!(await verifyTurnstile(env.TURNSTILE_SECRET, body.token, ip))) {
    return json(400, { ok: false, error: "captcha", message: "確認に失敗しました。時間をおいてお試しください。" });
  }

  const country = request.headers.get("cf-ipcountry") || "";

  // ④ 同一IPからの回数制限
  const iph = ip ? await ipHash(ip) : "";
  if (await tooManyFrom(env, iph)) {
    await recordBlocked(env, "rate", body, country);
    return json(200, { ok: true });   // 弾いたことは教えない
  }

  // ⑤ 本文の判定。語の一致による推測なので**捨てずに**「スパム判定」の状態でシートへ回す
  const spam = looksLikeSpam(clean(body.message, MAX.message),
                             clean(body.name, MAX.name),
                             clean(body.url, MAX.url));
  let flagged = "";
  if (spam) {
    await recordBlocked(env, spam, body, country);
    flagged = "スパム判定（" + spam + "）";
  }

  const kind = clean(body.kind, MAX.kind);
  const name = clean(body.name, MAX.name);
  const email = clean(body.email, MAX.email);
  const url = clean(body.url, MAX.url);
  const message = clean(body.message, MAX.message);

  if (!message || message.length < 10) {
    return json(422, { ok: false, error: "too_short", message: "お問い合わせ内容を10文字以上でご記入ください。" });
  }
  if (!KINDS.includes(kind)) {
    return json(422, { ok: false, error: "bad_kind", message: "お問い合わせの種類をお選びください。" });
  }
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json(422, { ok: false, error: "bad_email", message: "メールアドレスの形式をご確認ください。" });
  }

  const at = new Date().toISOString();
  let stored = false;

  // 控え（D1）
  if (env.DB) {
    try {
      await env.DB.prepare(
        "CREATE TABLE IF NOT EXISTS messages (at TEXT, kind TEXT, name TEXT, email TEXT, " +
        "url TEXT, country TEXT, message TEXT, status TEXT)").run();
      await env.DB.prepare(
        "INSERT INTO messages (at, kind, name, email, url, country, message, status) " +
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
      ).bind(at, kind, name, email, url, country, message, flagged || "new").run();
      stored = true;
    } catch (e) {
      // 例外の中身は返さない
    }
  }

  // 本命：スプレッドシートへ1行追記
  const sheetRow = [
    at.replace("T", " ").slice(0, 19),
    kind, name, email, url, country, message,
    flagged || "未対応",
  ];
  if (await appendToSheet(env, sheetRow)) stored = true;

  if (!stored) {
    // 黙って捨てず、送れなかったことを正直に返す
    return json(503, {
      ok: false, error: "not_configured",
      message: "申し訳ありません。ただいま受付の設定作業中で送信できません。時間をおいてお試しください。",
    });
  }

  return json(200, { ok: true });
}

// onRequestPost だけを export する（onRequest を併記すると POST が奪われる）。
