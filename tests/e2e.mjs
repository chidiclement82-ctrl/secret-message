// End-to-end test: serves the site locally and drives it in Chromium.
// The Supabase database is replaced by an in-memory stand-in that follows
// the same rules as supabase/schema.sql, so no network or account is needed.
// Run with `npm test`.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { extname, join, normalize } from "node:path";
import assert from "node:assert/strict";
import { chromium } from "playwright";

const root = new URL("..", import.meta.url).pathname;
const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".webmanifest": "application/manifest+json" };
const server = createServer(async (req, res) => {
  const path = normalize(decodeURIComponent(new URL(req.url, "http://x").pathname)).replace(/^\/+/, "") || "index.html";
  try {
    const body = await readFile(join(root, path));
    res.writeHead(200, { "content-type": types[extname(path)] || "application/octet-stream" }).end(body);
  } catch {
    res.writeHead(404).end();
  }
}).listen(0);
const base = `http://localhost:${server.address().port}/`;
const supabaseUrl = (await readFile(join(root, "config.js"), "utf8")).match(/supabaseUrl:\s*"([^"]+)"/)[1];

// ---- fake database (mirrors supabase/schema.sql) --------------------------
const SETUP_CODE = "TEST-CODE-1234-ABCD";
const sha256hex = (buf) => createHash("sha256").update(buf).digest("hex");
const db = { inbox: { setup_code_hash: sha256hex(SETUP_CODE) }, messages: [], nextId: 1 };
const fail = (code, message, status = 400) => ({ status, body: { code, message } });
const ownerOk = (token) => db.inbox.auth_hash && /^[0-9a-f]{64}$/.test(token || "") && sha256hex(Buffer.from(token, "hex")) === db.inbox.auth_hash;
const rpc = {
  get_inbox: () => ({ public_key: db.inbox.public_key || null, salt: db.inbox.salt || null }),
  setup_inbox: (a) => {
    if (db.inbox.public_key || sha256hex(a.setup_code) !== db.inbox.setup_code_hash) return fail("28000", "invalid setup code");
    Object.assign(db.inbox, { public_key: a.public_key, salt: a.salt, auth_hash: a.auth_hash, wrapped_key: a.wrapped_key, setup_code_hash: null });
    return null;
  },
  send_message: (a) => {
    if (!db.inbox.public_key) return fail("P0001", "inbox not set up");
    if (!/^[A-Za-z0-9_-]+$/.test(a.blob) || a.blob.length < 100 || a.blob.length > 16000) return fail("22023", "bad message");
    db.messages.push({ id: db.nextId++, created_at: new Date().toISOString(), blob: a.blob });
    return null;
  },
  open_inbox: (a) => ownerOk(a.token)
    ? { wrapped_key: db.inbox.wrapped_key, messages: [...db.messages].reverse() }
    : fail("28000", "wrong passphrase"),
  delete_message: (a) => {
    if (!ownerOk(a.token)) return fail("28000", "wrong passphrase");
    db.messages = db.messages.filter((m) => m.id !== a.message_id);
    return null;
  },
  change_passphrase: (a) => {
    if (!ownerOk(a.token)) return fail("28000", "wrong passphrase");
    Object.assign(db.inbox, { salt: a.salt, auth_hash: a.auth_hash, wrapped_key: a.wrapped_key });
    return null;
  },
};
const apiCalls = [];

// ---- browser -------------------------------------------------------------
const browser = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
await ctx.route(`${supabaseUrl}/**`, async (route) => {
  const fn = new URL(route.request().url()).pathname.replace("/rest/v1/rpc/", "");
  const args = JSON.parse(route.request().postData() || "{}");
  apiCalls.push({ fn, args });
  const out = rpc[fn] ? rpc[fn](args) : fail("PGRST202", "not found", 404);
  if (out && out.status) return route.fulfill({ status: out.status, json: out.body });
  return out === null ? route.fulfill({ status: 204, body: "" }) : route.fulfill({ status: 200, json: out });
});
// The tests make their own inbox key, so serve config.js with the pinned key
// swapped for whatever `pinned` is (none by default).
let pinned = "";
const configJs = await readFile(join(root, "config.js"), "utf8");
await ctx.route(`${base}config.js`, (route) => route.fulfill({
  contentType: "text/javascript",
  body: configJs.replace(/pinnedPublicKey:\s*"[^"]*"/, `pinnedPublicKey: "${pinned}"`),
}));
const errors = [];
const hosts = new Set();
ctx.on("page", (p) => {
  p.on("pageerror", (e) => errors.push(e.message));
  // Expected: the browser logs the 400s from wrong-code/passphrase attempts.
  p.on("console", (m) => m.type() === "error" && !/status of 400/.test(m.text()) && errors.push(m.text()));
  p.on("request", (r) => hosts.add(new URL(r.url()).host));
  p.on("dialog", (d) => d.accept());
});

let passed = 0;
async function test(name, fn) {
  await fn();
  passed++;
  console.log("✓", name);
}

const PASS = "purple tractor seven lagoon";
const sender = await ctx.newPage();
const owner = await ctx.newPage();

async function send(text, from) {
  await sender.goto(base);
  await sender.waitForSelector("#compose:not([hidden])");
  await sender.fill("#message", text);
  if (from) await sender.fill("#from", from);
  await sender.click("#send");
  await sender.waitForSelector("#sent:not([hidden])");
}
async function unlock(pass) {
  await owner.goto(base + "inbox.html");
  await owner.waitForSelector("#unlock:not([hidden])");
  await owner.fill("#pass", pass);
  await owner.click("#unlock-btn");
}

await test("send page says the inbox is closed before setup", async () => {
  await sender.goto(base);
  await sender.waitForSelector("#closed:not([hidden])");
  assert.ok(await sender.locator("#compose").isHidden());
});

await test("setup rejects a short passphrase and a wrong code", async () => {
  await owner.goto(base + "inbox.html");
  await owner.waitForSelector("#setup:not([hidden])");
  await owner.fill("#setup-code", "WRONG");
  await owner.fill("#setup-pass", "short");
  await owner.fill("#setup-pass2", "short");
  await owner.click("#setup-btn");
  assert.match(await owner.textContent("#setup-error"), /12 characters/);
  await owner.fill("#setup-pass", PASS);
  await owner.fill("#setup-pass2", PASS);
  await owner.click("#setup-btn");
  await owner.waitForFunction(() => /setup code/.test(document.getElementById("setup-error").textContent));
  assert.equal(db.inbox.public_key, undefined);
});

await test("setup with the right code creates the inbox and opens it", async () => {
  // As a phone might type it: smart dashes, spaces, lower case.
  await owner.fill("#setup-code", " " + SETUP_CODE.toLowerCase().replace(/-/g, " – ") + " ");
  await owner.click("#setup-btn");
  await owner.waitForSelector("#inbox:not([hidden])");
  assert.equal(await owner.textContent("#summary"), "No messages yet.");
  assert.ok(db.inbox.public_key && db.inbox.wrapped_key);
  assert.ok(!JSON.stringify(apiCalls).includes(PASS), "passphrase never sent");
});

const secret = "Meet at 7 ✓ <b>not html</b>\nline two 🔐";
await test("visitors can send, anonymously or with a name", async () => {
  await send(secret);
  await send("second message", "Ada, 0803 000 0000");
  assert.equal(db.messages.length, 2);
  for (const m of db.messages) {
    assert.ok(!m.blob.includes("Meet") && !m.blob.includes("Ada"), "database holds only ciphertext");
  }
  assert.equal(db.messages[0].blob.length, db.messages[1].blob.length, "padding hides length");
});

await test("wrong passphrase doesn't open the inbox", async () => {
  await unlock("not the passphrase");
  await owner.waitForSelector("#unlock-error:not([hidden])");
  assert.match(await owner.textContent("#unlock-error"), /Wrong passphrase/);
});

await test("owner reads messages, newest first, as plain text", async () => {
  await unlock(PASS);
  await owner.waitForSelector("#inbox:not([hidden])");
  assert.equal(await owner.textContent("#summary"), "2 messages");
  assert.deepEqual(await owner.locator("#messages .plain").allTextContents(), ["second message", secret]);
  assert.deepEqual(await owner.locator("#messages .from").allTextContents(), ["From: Ada, 0803 000 0000", "Anonymous"]);
  assert.equal(await owner.locator("#messages b").count(), 0, "shown as text, not HTML");
});

await test("a tampered message shows as unreadable, not as altered text", async () => {
  const b = db.messages[0].blob;
  db.messages[0].blob = b.slice(0, 120) + (b[120] === "A" ? "B" : "A") + b.slice(121);
  await owner.click("#refresh");
  await owner.waitForSelector("#messages .plain.broken");
  db.messages[0].blob = b;
  await owner.click("#refresh");
  await owner.waitForFunction(() => !document.querySelector("#messages .plain.broken"));
});

await test("owner can delete a message", async () => {
  await owner.locator("#messages .delete").first().click();
  await owner.waitForFunction(() => document.getElementById("summary").textContent === "1 message");
  assert.deepEqual(db.messages.map((m) => m.id), [1]);
});

await test("owner can change the passphrase", async () => {
  const NEW = "new passphrase for the inbox";
  await owner.locator("#inbox details summary").click();
  await owner.fill("#new-pass", NEW);
  await owner.fill("#new-pass2", NEW);
  await owner.click("#change-btn");
  await owner.waitForSelector("#change-msg:not([hidden])");
  await unlock(PASS);
  await owner.waitForSelector("#unlock-error:not([hidden])");
  await unlock(NEW);
  await owner.waitForSelector("#inbox:not([hidden])");
  assert.deepEqual(await owner.locator("#messages .plain").allTextContents(), [secret]);
});

await test("pinned key: matches are used, a swapped key is refused", async () => {
  pinned = db.inbox.public_key;
  await send("with the right pinned key");
  assert.equal(db.messages.length, 2);
  const real = db.inbox.public_key;
  db.inbox.public_key = (await readFile(join(root, "config.js"), "utf8")).match(/pinnedPublicKey:\s*"([^"]+)"/)[1];
  await sender.goto(base);
  await sender.fill("#message", "should not be sent");
  await sender.click("#send");
  await sender.waitForSelector("#send-error:not([hidden])");
  assert.match(await sender.textContent("#send-error"), /key/);
  assert.equal(db.messages.length, 2);
  db.inbox.public_key = real;
  pinned = "";
});

await test("pages only talk to their own site and the inbox database", async () => {
  assert.deepEqual([...hosts].sort(), [new URL(base).host, new URL(supabaseUrl).host].sort());
});

await test("no console or page errors", async () => {
  assert.deepEqual(errors, []);
});

await browser.close();
server.close();
console.log(`\n${passed} passed`);
