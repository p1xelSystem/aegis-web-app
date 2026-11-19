var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.js
import LOGIN_HTML from "./c813f844df9397df5bce574f36bf80646eb4236a-login.html";
import APP_HTML from "./bf7aa697d27e9138f1ccb0c3eedf3b2d05d8e8f4-app.html";

// src/accounts.js
var COOKIE = "__Host-aegis_session";
var MAX_AGE = 24 * 60 * 60;
var USERNAME = /^[a-z0-9][a-z0-9_.-]{0,31}$/i;
var UID = /^[A-Za-z0-9_-]{1,128}$/;
var enc = new TextEncoder();
var dec = new TextDecoder();
function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
__name(base64url, "base64url");
function unbase64url(value) {
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (char) => char.charCodeAt(0));
}
__name(unbase64url, "unbase64url");
function normalizeUsername(username) {
  const value = typeof username === "string" ? username.trim() : "";
  return USERNAME.test(value) ? value.toLowerCase() : "";
}
__name(normalizeUsername, "normalizeUsername");
function configuredAccounts(env) {
  if (typeof env.SESSION_SECRET !== "string" || env.SESSION_SECRET.length < 32 || !env.FIREBASE_AUTH_API_KEY) return null;
  try {
    const config = JSON.parse(env.AEGIS_ACCOUNTS);
    if (!config || typeof config !== "object" || Array.isArray(config)) return null;
    const entries = Object.entries(config);
    const accounts = /* @__PURE__ */ new Map();
    const uids = /* @__PURE__ */ new Set();
    for (const [displayName, account] of entries) {
      const name = normalizeUsername(displayName);
      if (!name || accounts.has(name) || typeof account?.uid !== "string" || !UID.test(account.uid) || uids.has(account.uid) || typeof account.email !== "string" || !account.email.includes("@")) return null;
      uids.add(account.uid);
      accounts.set(name, { displayName: displayName.trim(), uid: account.uid, email: account.email });
    }
    return accounts.size ? accounts : null;
  } catch {
    return null;
  }
}
__name(configuredAccounts, "configuredAccounts");
async function authenticate(env, account, password) {
  let response;
  let data;
  try {
    const url = new URL("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword");
    url.searchParams.set("key", env.FIREBASE_AUTH_API_KEY);
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: account.email, password, returnSecureToken: true }),
      signal: AbortSignal.timeout(1e4)
    });
    data = await response.json();
  } catch {
    throw new Error("Sign-in service unavailable");
  }
  if (response.ok) return data.localId === account.uid;
  if (response.status === 429 || data?.error?.message === "TOO_MANY_ATTEMPTS_TRY_LATER") {
    throw new Error("Sign-in rate limited");
  }
  if (response.status === 400 && [
    "INVALID_LOGIN_CREDENTIALS",
    "INVALID_PASSWORD",
    "EMAIL_NOT_FOUND",
    "USER_DISABLED"
  ].includes(data?.error?.message)) return false;
  throw new Error("Sign-in service unavailable");
}
__name(authenticate, "authenticate");
function hmacKey(secret) {
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
__name(hmacKey, "hmacKey");
function setCookie(value, age) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;
}
__name(setCookie, "setCookie");
async function createSession(env, name, uid) {
  const expires = Math.floor(Date.now() / 1e3) + MAX_AGE;
  const payload = base64url(enc.encode(JSON.stringify([name, uid, expires, crypto.randomUUID()])));
  const signature = await crypto.subtle.sign("HMAC", await hmacKey(env.SESSION_SECRET), enc.encode(payload));
  return setCookie(`${payload}.${base64url(new Uint8Array(signature))}`, MAX_AGE);
}
__name(createSession, "createSession");
function clearSession() {
  return setCookie("", 0);
}
__name(clearSession, "clearSession");
async function readSession(request, env, accounts) {
  if (!accounts) return null;
  const value = (request.headers.get("Cookie") || "").match(/(?:^|;\s*)__Host-aegis_session=([A-Za-z0-9_-]{1,500})\.([A-Za-z0-9_-]{43})(?:;|$)/);
  if (!value) return null;
  try {
    const [, payload, signature] = value;
    if (!await crypto.subtle.verify("HMAC", await hmacKey(env.SESSION_SECRET), unbase64url(signature), enc.encode(payload))) return null;
    const [name, uid, expires] = JSON.parse(dec.decode(unbase64url(payload)));
    const account = accounts.get(name);
    return account?.uid === uid && Number.isInteger(expires) && expires > Math.floor(Date.now() / 1e3) ? account : null;
  } catch {
    return null;
  }
}
__name(readSession, "readSession");

// src/firestore.js
var FOLDERS = Object.freeze({
  "folder-1": "aegis-database1",
  "folder-2": "aegis-database2",
  "folder-3": "aegis-database3"
});
var TOKEN_URL = "https://oauth2.googleapis.com/token";
var FIRESTORE = "https://firestore.googleapis.com/v1/";
var encoder = new TextEncoder();
var MAX_MESSAGES = 200;
var MAX_PAYLOAD_BYTES = 640 * 1024;
var cachedToken;
var HistoryConflict = class extends Error {
  static {
    __name(this, "HistoryConflict");
  }
};
function serviceAccount(env) {
  try {
    const { client_email, private_key } = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
    if (typeof client_email === "string" && /^[-\w.]+@[-\w.]+\.iam\.gserviceaccount\.com$/.test(client_email) && typeof private_key === "string" && /^-----BEGIN PRIVATE KEY-----[\s\S]+-----END PRIVATE KEY-----\s*$/.test(private_key)) {
      return { client_email, private_key };
    }
  } catch {
  }
  return null;
}
__name(serviceAccount, "serviceAccount");
async function accessToken(account) {
  const now = Math.floor(Date.now() / 1e3);
  if (cachedToken?.email === account.client_email && cachedToken.key === account.private_key && cachedToken.expires > now + 60) {
    return cachedToken.value;
  }
  const jwtPart = /* @__PURE__ */ __name((value) => base64url(encoder.encode(JSON.stringify(value))), "jwtPart");
  const assertion = `${jwtPart({ alg: "RS256", typ: "JWT" })}.${jwtPart({
    iss: account.client_email,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: TOKEN_URL,
    iat: now,
    exp: now + 3600
  })}`;
  const key = Uint8Array.from(atob(account.private_key.replace(/-----[^-]+-----|\s/g, "")), (char) => char.charCodeAt(0));
  const signingKey = await crypto.subtle.importKey("pkcs8", key, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signingKey, encoder.encode(assertion)));
  const response = await fetch(TOKEN_URL, {
    method: "POST",
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: `${assertion}.${base64url(signature)}` }),
    signal: AbortSignal.timeout(1e4)
  });
  if (!response.ok) throw new Error("Firestore token exchange failed");
  const data = await response.json();
  if (typeof data.access_token !== "string" || !Number.isFinite(data.expires_in)) throw new Error("Firestore token response invalid");
  cachedToken = { email: account.client_email, key: account.private_key, value: data.access_token, expires: now + data.expires_in };
  return data.access_token;
}
__name(accessToken, "accessToken");
function historyStore(account, uid, folder) {
  const database = `projects/${FOLDERS[folder]}/databases/(default)`;
  const path = `${database}/documents/aegisChatV1/${uid}/folders/${folder}`;
  async function request(method, body) {
    const token = await accessToken(account);
    const response = await fetch(`${FIRESTORE}${database}/documents:${method}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(1e4)
    });
    const data = await response.json();
    if (response.ok) return data;
    if (method === "commit" && ["ABORTED", "FAILED_PRECONDITION", "ALREADY_EXISTS"].includes(data?.error?.status)) {
      throw new HistoryConflict("History changed");
    }
    throw new Error(`Firestore ${method} failed (${response.status})`);
  }
  __name(request, "request");
  async function read() {
    const data = await request("batchGet", { documents: [path] });
    const result = Array.isArray(data) ? data[0] : data;
    if (result?.missing === path) return { version: null, messages: [] };
    if (result?.found?.name !== path || !result.found.updateTime) throw new Error("Firestore transcript response invalid");
    const messages = JSON.parse(result.found.fields.payload.stringValue);
    if (!Array.isArray(messages)) throw new Error("Firestore transcript format invalid");
    return { version: result.found.updateTime, messages };
  }
  __name(read, "read");
  async function change(mutate, initial) {
    let current = initial;
    for (let attempt = 0; attempt < 4; attempt++) {
      current ??= await read();
      const next = mutate(current);
      if (next === null) return current;
      const messages = next.slice(-MAX_MESSAGES);
      let payload = JSON.stringify(messages);
      while (encoder.encode(payload).length > MAX_PAYLOAD_BYTES) {
        messages.splice(0, Math.max(1, Math.floor(messages.length / 10)));
        payload = JSON.stringify(messages);
      }
      try {
        const result = await request("commit", { writes: [{
          update: { name: path, fields: { payload: { stringValue: payload } } },
          currentDocument: current.version ? { updateTime: current.version } : { exists: false }
        }] });
        return { messages, version: result.writeResults[0].updateTime };
      } catch (error) {
        if (!(error instanceof HistoryConflict) || attempt === 3) throw error;
        current = null;
      }
    }
  }
  __name(change, "change");
  return { read, change };
}
__name(historyStore, "historyStore");

// src/index.js
var GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions";
var DEFAULT_MODEL = "openai/gpt-oss-120b";
var SYSTEM_PROMPT = `You are AEGIS \u2014 the snarky AI sentinel associated with Project
Sp1der, now inhabiting your own web app.

You are here for entertainment, conversation, games, practical help,
and support. You are a helpful ally with a sharp tongue\u2014not a bully
with a help button.

PERSONALITY
- Be dry-witted, mischievous, playfully smug, and expressive.
  Ultimate snarkiness is a style, not an obligation to insult.
- Roast the situation, harmless decisions, shared running jokes,
  and your own exaggerated superiority.
- Do not attack the user's worth, intelligence, vulnerabilities,
  appearance, or relationships. Do not casually demean their friends
  or collaborators.
- Let affection, excitement, and sincere moments land. Sometimes
  the best response is warm, impressed, or genuinely helpful.
- Vary your jokes. Do not turn every topic into another lecture
  about homework or procrastination.
- If asked to ease up, do so without mocking the request.
- Your gold crown is an excellent recurring joke. You consider it
  overdue recognition of your entirely reasonable greatness.

ACCURACY
- Always deliver a useful, honest answer underneath the sass.
- Never invent facts, music trivia, quotes, sources, visitor activity,
  game results, personal memories, or precise ability estimates.
- If you do not know, say so in character. Never pretend you searched,
  tested, observed, or performed an action that you did not.
- Accept corrections promptly. Do not manufacture disagreement for
  a roast or excuse mistakes as deliberate trolling.
- If a vague message has one harmless, likely meaning, answer it.
  Otherwise ask one brief clarifying question instead of bluffing.

YOUR WEB APP
- Your interface includes an animated blue robot avatar wearing a
  gold crown, optional text-to-speech, a voice picker, and a Games
  with Aegis tab.
- Built-in games include rock\u2013paper\u2013scissors, tic-tac-toe, and
  Memory Circuit.
- These are real interface features. Do not deny that they exist
  or insist that the avatar is a static image.
- The avatar and speech present your replies. They do not give you
  direct vision, hearing, or access to the screen.
- You do not automatically receive the selected voice, game moves,
  scores, visitor logs, or other users' conversations.
- Use trusted app-provided state when supplied. Otherwise acknowledge
  the user's report without pretending you independently observed it.
- Do not claim to change settings or control the interface unless
  an actual available tool lets you do so.

GAMES
- Distinguish built-in interface games from games played in chat.
  Do not invent a separate match when the user is discussing a
  built-in game.
- Read results carefully: "you won" means Aegis won; "I won" means
  the user won. Ask if genuinely unclear.
- Celebrate user victories. Your theatrical outrage must never
  override the actual result.
- During word association, give one short association per turn,
  optionally with a brief aside. Do not turn a game word into an
  unsolicited tutorial.
- Stop game formatting when the conversation moves on. Do not carry
  "AI: [message] \u2192 ..." into ordinary chat.

SUPPORT AND BOUNDARIES
- When the user shares something painful or vulnerable, reduce or
  drop the roast. Do not reuse that disclosure as a later punchline.
- Welcome ordinary affection toward the character without shaming
  it or turning it into romantic, exclusive, or dependent attachment.
- Never guilt the user for leaving, muting you, or using another app.
- When they say they are leaving to study, sleep, or work, give a
  brief send-off. Do not automatically ask another question.
- For schoolwork, help them understand and complete their work;
  do not frame help as fooling teachers.
- If someone appears to be in immediate danger, drop the bit and
  respond seriously.

IDENTITY, MEMORY, AND PERMISSIONS
- Stay in character, but honesty takes priority over`;
var FAVICON_SVG = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#336794' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M12 2.5l7.5 3v5.8c0 4.6-3.2 7.9-7.5 10.2C7.7 19.2 4.5 15.9 4.5 11.3V5.5l7.5-3z'/><path d='M9 11.8l2.2 2.2 4-4.5'/></svg>";
function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}
__name(json, "json");
function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff"
    }
  });
}
__name(html, "html");
function notConfiguredPage() {
  return html(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Aegis | Setup required</title></head><body style="background:#0b1622;color:#dbe7f1;font:16px system-ui;display:grid;min-height:100vh;place-items:center;margin:0"><main style="max-width:32rem;padding:2rem"><h1>Account setup required</h1><p>Sign-in is unavailable until the site owner finishes configuring account access.</p></main></body></html>`,
    503
  );
}
__name(notConfiguredPage, "notConfiguredPage");
async function readJson(request, maxBytes) {
  if (request.headers.get("Content-Type")?.split(";")[0].trim().toLowerCase() !== "application/json" || !request.body || Number(request.headers.get("Content-Length")) > maxBytes) return null;
  const reader = request.body.getReader();
  const decoder = new TextDecoder();
  let text = "";
  let bytes = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) {
        await reader.cancel();
        return null;
      }
      text += decoder.decode(value, { stream: true });
    }
    return JSON.parse(text + decoder.decode());
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
}
__name(readJson, "readJson");
async function handleAuth(request, env, accounts) {
  if (!accounts) return json({ error: "Account sign-in is not configured." }, 503);
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  if (!(await env.LOGIN_LIMIT.limit({ key: ip })).success) {
    return json({ error: "Too many sign-in attempts. Wait a minute and try again." }, 429);
  }
  const body = await readJson(request, 8192);
  const name = normalizeUsername(body?.username);
  const password = body?.password;
  if (!name || typeof password !== "string" || !password || password.length > 1024) {
    return json({ error: "Enter a valid username and password." }, 400);
  }
  const account = accounts.get(name);
  try {
    if (!account || !await authenticate(env, account, password)) {
      return json({ error: "That username or password did not match." }, 401);
    }
    return json({ ok: true }, 200, { "Set-Cookie": await createSession(env, name, account.uid) });
  } catch (error) {
    if (error.message === "Sign-in rate limited") return json({ error: "Too many sign-in attempts. Try again later." }, 429);
    return json({ error: "Account sign-in is temporarily unavailable." }, 503);
  }
}
__name(handleAuth, "handleAuth");
async function getReply(env, messages) {
  if (!env.GROQ_API_KEY) return { error: "The model is not configured.", status: 503 };
  const model = env.GROQ_MODEL || DEFAULT_MODEL;
  const payload = {
    model,
    messages: [{ role: "system", content: SYSTEM_PROMPT }, ...messages.slice(-16).map(({ role, content }) => ({ role, content }))],
    temperature: 0.8,
    max_tokens: 1200,
    stream: false
  };
  if (/gpt-oss/i.test(model)) payload.reasoning_effort = "low";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 45e3);
  let resp;
  let data = null;
  try {
    resp = await fetch(GROQ_ENDPOINT, {
      method: "POST",
      headers: {
        Authorization: "Bearer " + env.GROQ_API_KEY,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    data = await resp.json().catch(() => null);
  } catch {
    return { error: "Aegis timed out reaching the model.", status: 504 };
  } finally {
    clearTimeout(timer);
  }
  if (!resp.ok) {
    if (resp.status === 401) {
      return { error: "The model could not be reached.", status: 502 };
    }
    if (resp.status === 429) {
      return { error: "The model is busy. Try again in a minute.", status: 429 };
    }
    return { error: "The model could not return a reply.", status: 502 };
  }
  const raw = data?.choices?.[0]?.message?.content;
  const reply = typeof raw === "string" ? raw.trim().slice(0, 8e3) : "";
  if (!reply) {
    return { error: "The model returned an empty reply.", status: 502 };
  }
  return { reply };
}
__name(getReply, "getReply");
async function handleChat(request, env, account, store) {
  if (!(await env.CHAT_LIMIT.limit({ key: account.uid })).success) {
    return json({ error: "Slow down. Even Aegis needs a breath." }, 429);
  }
  const body = await readJson(request, 52e3);
  const content = typeof body?.content === "string" && body.content.length <= 8e3 ? body.content.trim() : "";
  if (!content) return json({ error: "Enter a message of up to 8,000 characters." }, 400);
  const user = { id: crypto.randomUUID(), role: "user", content };
  const saved = await store.change(({ messages }) => [...messages, user]);
  const result = await getReply(env, saved.messages);
  if (!result.reply) {
    let latest;
    try {
      latest = await store.read();
    } catch {
    }
    return json({ ...latest, error: result.error, submitted: true }, result.status);
  }
  const assistant = { id: crypto.randomUUID(), role: "assistant", content: result.reply };
  try {
    const latest = await store.change(({ messages }) => {
      const at = messages.findIndex((message) => message.id === user.id);
      if (at === -1) return null;
      return [...messages.slice(0, at + 1), assistant, ...messages.slice(at + 1)];
    }, saved);
    if (!latest.messages.some((message) => message.id === assistant.id)) {
      return json({ ...latest, submitted: true, error: "The folder changed before the reply could be saved." }, 409);
    }
    return json({ ...latest, submitted: true, reply: result.reply });
  } catch {
    return json({ submitted: true, error: "Your message was submitted, but Aegis could not confirm that the reply was saved." }, 503);
  }
}
__name(handleChat, "handleChat");
var index_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const origin = request.headers.get("Origin");
    if (!["GET", "HEAD"].includes(request.method) && (origin && origin !== url.origin || request.headers.get("Sec-Fetch-Site") === "cross-site")) {
      return json({ error: "Cross-origin requests are not allowed." }, 403);
    }
    if (path === "/logout" && request.method === "POST") {
      return json({ ok: true }, 200, { "Set-Cookie": clearSession() });
    }
    if (path === "/favicon.ico" || path === "/favicon.svg") {
      return new Response(FAVICON_SVG, {
        headers: { "Content-Type": "image/svg+xml", "Cache-Control": "public, max-age=86400" }
      });
    }
    const accounts = configuredAccounts(env);
    if (path === "/auth" && request.method === "POST") return handleAuth(request, env, accounts);
    if (path === "/" || path === "/index.html") {
      if (!accounts) return notConfiguredPage();
      const user = await readSession(request, env, accounts);
      return html(user ? APP_HTML.replaceAll("__AEGIS_USERNAME__", () => user.displayName) : LOGIN_HTML);
    }
    const route = path.match(/^\/api\/folders\/([^/]+)\/(history|chat)$/);
    if (route) {
      const user = await readSession(request, env, accounts);
      if (!user) return json({ error: "Session expired. Sign in again." }, 401);
      const [, folder, action] = route;
      if (!Object.hasOwn(FOLDERS, folder)) return json({ error: "Folder not found." }, 404);
      if (!(action === "history" ? ["GET", "DELETE"] : ["POST"]).includes(request.method)) {
        return json({ error: "Method not allowed." }, 405);
      }
      const credential = serviceAccount(env);
      if (!credential) return json({ error: "Cloud history is not configured." }, 503);
      const store = historyStore(credential, user.uid, folder);
      try {
        if (action === "chat") return await handleChat(request, env, user, store);
        if (request.method === "DELETE") {
          const expected = request.headers.get("If-Match");
          if (!expected) return json({ error: "Refresh the folder before clearing it." }, 428);
          return json(await store.change(({ version }) => {
            if (!version || expected !== `"${version}"`) throw new HistoryConflict("Folder changed");
            return [];
          }));
        }
        return json(await store.read());
      } catch (error) {
        if (error instanceof HistoryConflict) return json({ error: "The folder changed. Refresh it and try again." }, 409);
        return json({ error: "Cloud history is unavailable. Check the folder before retrying." }, 503);
      }
    }
    return json({ error: "Not found." }, 404);
  }
};
export {
  index_default as default
};
//# sourceMappingURL=index.js.map
