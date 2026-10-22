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
const configJs = await readFile(join(root, "config.js"), "utf8");
const supabaseUrl = configJs.match(/supabaseUrl:\s*"([^"]+)"/)[1];

// ---- fake database (mirrors supabase/schema.sql) --------------------------
const SETUP_CODE = "TEST-CODE-1234-ABCD";
const sha256hex = (buf) => createHash("sha256").update(buf).digest("hex");
const db = { inbox: { setup_code_hash: sha256hex(SETUP_CODE) }, threads: new Map(), messages: [], subs: [], nextId: 1 };
// Any valid P-256 public key will do as the server's push (VAPID) key.
const PUSH_KEY = "BDQHMQixFxiZus647DCubqwmoA5sK4Q0MIALfuTPPn2pZKpnxMzXlHNXfGShE7oeqHk-IpniTlXT38dwvrr78BE";
const fail = (code, message, status = 400) => ({ status, body: { code, message } });
const isHex64 = (s) => /^[0-9a-f]{64}$/.test(s || "");
const isB64 = (s) => /^[A-Za-z0-9_-]+$/.test(s || "");
const ownerOk = (token) => db.inbox.auth_hash && isHex64(token) && sha256hex(Buffer.from(token, "hex")) === db.inbox.auth_hash;
const now = () => new Date(Date.now() + db.nextId).toISOString(); // strictly increasing
const rowsOf = (tid) => db.messages.filter((m) => m.thread_id === tid)
  .map(({ id, from_owner, created_at, blob }) => ({ id, from_owner, created_at, blob }));
const rpc = {
  get_inbox: () => ({ public_key: db.inbox.public_key || null, salt: db.inbox.salt || null }),
  setup_inbox: (a) => {
    if (db.inbox.public_key || sha256hex(a.setup_code) !== db.inbox.setup_code_hash) return fail("28000", "invalid setup code", 403);
    Object.assign(db.inbox, { public_key: a.public_key, salt: a.salt, auth_hash: a.auth_hash, wrapped_key: a.wrapped_key, setup_code_hash: null });
    return null;
  },
  send_to_thread: (a) => {
    if (!db.inbox.public_key) return fail("P0001", "inbox not set up");
    if (!isHex64(a.thread_token) || !isB64(a.blob)) return fail("22023", "bad message");
    const tid = sha256hex(Buffer.from(a.thread_token, "hex"));
    if (!db.threads.has(tid)) {
      if (!isB64(a.envelope)) return fail("22023", "bad message");
      db.threads.set(tid, { id: tid, envelope: a.envelope, created_at: now(), last_at: now(), last_from_owner: false });
    }
    const t = db.threads.get(tid);
    db.messages.push({ id: db.nextId++, thread_id: tid, from_owner: false, created_at: now(), blob: a.blob });
    Object.assign(t, { last_at: now(), last_from_owner: false });
    return null;
  },
  get_thread: (a) => isHex64(a.thread_token) ? rowsOf(sha256hex(Buffer.from(a.thread_token, "hex"))) : fail("22023", "bad token"),
  open_inbox: (a) => ownerOk(a.token)
    ? { wrapped_key: db.inbox.wrapped_key,
        threads: [...db.threads.values()].sort((x, y) => (x.last_at < y.last_at ? 1 : -1)).map((t) => ({ ...t, messages: rowsOf(t.id) })) }
    : fail("28000", "wrong passphrase", 403),
  reply_to_thread: (a) => {
    if (!ownerOk(a.token)) return fail("28000", "wrong passphrase", 403);
    const t = db.threads.get(a.thread_id);
    if (!t || !isB64(a.blob)) return fail("22023", "bad message");
    db.messages.push({ id: db.nextId++, thread_id: t.id, from_owner: true, created_at: now(), blob: a.blob });
    Object.assign(t, { last_at: now(), last_from_owner: true });
    return null;
  },
  delete_thread: (a) => {
    if (!ownerOk(a.token)) return fail("28000", "wrong passphrase", 403);
    db.threads.delete(a.thread_id);
    db.messages = db.messages.filter((m) => m.thread_id !== a.thread_id);
    return null;
  },
  get_push_key: () => PUSH_KEY,
  subscribe_owner: (a) => {
    if (!ownerOk(a.token)) return fail("28000", "wrong passphrase", 403);
    db.subs.push({ target: "owner", endpoint: a.endpoint, p256dh: a.p256dh, auth: a.auth });
    return null;
  },
  subscribe_thread: (a) => {
    const tid = isHex64(a.thread_token) && sha256hex(Buffer.from(a.thread_token, "hex"));
    if (!tid || !db.threads.has(tid)) return fail("22023", "no such conversation");
    db.subs.push({ target: tid, endpoint: a.endpoint, p256dh: a.p256dh, auth: a.auth });
    return null;
  },
  change_passphrase: (a) => {
    if (!ownerOk(a.token)) return fail("28000", "wrong passphrase", 403);
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
await ctx.route(`${base}config.js`, (route) => route.fulfill({
  contentType: "text/javascript",
  body: configJs.replace(/pinnedPublicKey:\s*"[^"]*"/, `pinnedPublicKey: "${pinned}"`),
}));
// Headless Chromium has no push service, so stand in for the browser's
// subscribe step (permission prompt + push service). Everything around it,
// including the real service worker registration, runs for real.
await ctx.addInitScript(() => {
  let n = 0;
  Object.defineProperty(Notification, "permission", { get: () => "granted" });
  Notification.requestPermission = async () => "granted";
  PushManager.prototype.getSubscription = async () => null;
  PushManager.prototype.subscribe = async function (opts) {
    const id = ++n;
    return {
      options: opts,
      toJSON: () => ({
        endpoint: `https://fcm.googleapis.com/fcm/send/test-${location.pathname}-${id}`,
        keys: { p256dh: "B" + "x".repeat(86), auth: "a".repeat(22) },
      }),
    };
  };
});
const errors = [];
const hosts = new Set();
ctx.on("page", (p) => {
  p.on("pageerror", (e) => errors.push(e.message));
  // Expected: the browser logs the 4xx from wrong-code/passphrase attempts.
  p.on("console", (m) => m.type() === "error" && !/status of 40[03]/.test(m.text()) && errors.push(m.text()));
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
const visitor = await ctx.newPage();
const owner = await ctx.newPage();

// Start a conversation; returns the visitor's private link.
async function startConversation(text) {
  await visitor.goto(base);
  await visitor.waitForSelector("#compose:not([hidden])");
  await visitor.fill("#message", text);
  await visitor.click("#send");
  await visitor.waitForSelector("#sent:not([hidden])");
  return visitor.inputValue("#chat-link");
}
async function unlock(pass) {
  await owner.goto(base + "inbox.html");
  await owner.waitForSelector("#unlock:not([hidden])");
  await owner.fill("#pass", pass);
  await owner.click("#unlock-btn");
}
const threadTexts = (page, scope) => page.locator(`${scope} .bubble .plain`).allTextContents();

await test("send page says the inbox is closed before setup", async () => {
  await visitor.goto(base);
  await visitor.waitForSelector("#closed:not([hidden])");
  assert.ok(await visitor.locator("#compose").isHidden());
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

await test("setup with the right code (typed like a phone would) opens the inbox", async () => {
  await owner.fill("#setup-code", " " + SETUP_CODE.toLowerCase().replace(/-/g, " – ") + " ");
  await owner.click("#setup-btn");
  await owner.waitForSelector("#inbox:not([hidden])");
  assert.equal(await owner.textContent("#summary"), "No messages yet.");
  assert.ok(!JSON.stringify(apiCalls).includes(PASS), "passphrase never sent");
});

const secret = "Meet at 7 ✓ <b>not html</b>\nline two 🔐";
let linkA, linkB;
await test("the form is anonymous: no name or phone fields", async () => {
  await visitor.goto(base);
  await visitor.waitForSelector("#compose:not([hidden])");
  assert.equal(await visitor.locator("#compose input").count(), 0);
});

await test("visitors send complaints and get a private link", async () => {
  linkA = await startConversation(secret);
  linkB = await startConversation("hello from B");
  assert.match(linkA, /\/chat\.html#[A-Za-z0-9_-]{43}$/);
  assert.equal(db.threads.size, 2);
  const stored = JSON.stringify([...db.threads.values(), ...db.messages]);
  for (const plain of ["Meet", "hello", linkA.split("#")[1], linkB.split("#")[1]]) {
    assert.ok(!stored.includes(plain), `database never sees "${plain}"`);
  }
  assert.ok(!JSON.stringify(apiCalls).includes(linkA.split("#")[1]), "the link secret is never sent");
  assert.equal(db.messages[0].blob.length, db.messages[1].blob.length, "padding hides length");
});

await test("the send page lists conversations started on this device", async () => {
  await visitor.goto(base);
  await visitor.waitForSelector("#saved:not([hidden])");
  assert.deepEqual(await visitor.locator("#saved-list a").allTextContents(), ["hello from B", secret.trim().slice(0, 60)]);
});

await test("wrong passphrase doesn't open the inbox", async () => {
  await unlock("not the passphrase");
  await owner.waitForSelector("#unlock-error:not([hidden])");
  assert.match(await owner.textContent("#unlock-error"), /Wrong passphrase/);
});

await test("owner sees conversations, newest first, as plain text", async () => {
  await unlock(PASS);
  await owner.waitForSelector("#inbox:not([hidden])");
  assert.equal(await owner.textContent("#summary"), "2 conversations · 2 waiting for a reply");
  assert.deepEqual(await owner.locator("#threads .convo .from").allTextContents(), ["Anonymous", "Anonymous"]);
  assert.deepEqual(await threadTexts(owner, "#threads .convo:nth-child(2)"), [secret]);
  assert.equal(await owner.locator("#threads b").count(), 0, "shown as text, not HTML");
});

await test("owner replies; only that visitor can read it", async () => {
  const convo = owner.locator("#threads .convo", { hasText: secret.split("\n")[0] });
  await convo.locator("textarea").fill("Thanks! See you at 7.");
  await convo.locator(".reply").click();
  await owner.waitForFunction(() => /1 waiting/.test(document.getElementById("summary").textContent));
  assert.ok(!JSON.stringify(db.messages).includes("Thanks"), "reply stored encrypted");

  await visitor.goto(linkA);
  await visitor.waitForSelector("#chat:not([hidden])");
  assert.deepEqual(await threadTexts(visitor, "#thread"), [secret, "Thanks! See you at 7."]);
  assert.equal(await visitor.locator("#thread .bubble.theirs").count(), 1);
  assert.ok(await visitor.locator("#waiting").isHidden());

  await visitor.goto(linkB);
  await visitor.waitForSelector("#chat:not([hidden])");
  assert.deepEqual(await threadTexts(visitor, "#thread"), ["hello from B"], "other conversation untouched");
  assert.ok(await visitor.locator("#waiting").isVisible());
});

await test("visitor follows up; owner sees it in the same conversation", async () => {
  await visitor.goto(linkA);
  await visitor.waitForSelector("#chat:not([hidden])");
  await visitor.fill("#message", "Great, thanks!");
  await visitor.click("#send");
  await visitor.waitForFunction(() => document.querySelectorAll("#thread .bubble").length === 3);
  await owner.click("#refresh");
  await owner.waitForFunction(() => /2 waiting/.test(document.getElementById("summary").textContent));
  const first = owner.locator("#threads .convo").first();
  assert.deepEqual(await threadTexts(owner, "#threads .convo:first-child"), [secret, "Thanks! See you at 7.", "Great, thanks!"]);
  assert.ok(await first.locator(".badge").isVisible());
});

await test("owner turns on notifications for new messages", async () => {
  await owner.waitForSelector("#notify:not([hidden])");
  await owner.click("#notify");
  await owner.waitForFunction(() => document.getElementById("notify").textContent.includes("on"));
  assert.equal(db.subs.filter((x) => x.target === "owner").length, 1);
  assert.ok(await owner.evaluate(() => navigator.serviceWorker.getRegistration().then((r) => !!r)), "service worker registered");
});

await test("visitor turns on reply notifications for their conversation", async () => {
  await visitor.goto(linkA);
  await visitor.waitForSelector("#notify:not([hidden])");
  await visitor.click("#notify");
  await visitor.waitForFunction(() => document.getElementById("notify").textContent.includes("on"));
  const tid = [...db.threads.keys()].find((id) => db.messages.some((m) => m.thread_id === id && m.from_owner));
  assert.deepEqual(db.subs.filter((x) => x.target !== "owner").map((x) => x.target), [tid]);
  assert.ok(!JSON.stringify(db.subs).includes(linkA.split("#")[1]), "the link secret is never sent");
});

await test("tapping a reply notification opens the right conversation", async () => {
  const tid = db.subs.find((x) => x.target !== "owner").target;
  await visitor.goto(base + "?open=" + tid);
  await visitor.waitForURL((u) => u.hash === new URL(linkA).hash);
  await visitor.waitForSelector("#chat:not([hidden])");
  assert.equal((await threadTexts(visitor, "#thread"))[0], secret);
});

await test("a broken or wrong link is refused", async () => {
  await visitor.goto(base + "chat.html#nope");
  await visitor.waitForSelector("#load-error:not([hidden])");
  await visitor.goto(base + "chat.html#" + "A".repeat(43));
  await visitor.waitForFunction(() => /no conversation/.test(document.getElementById("load-error").textContent));
});

await test("tampering is caught: changed text, or a message flipped to look like a reply", async () => {
  const m = db.messages.find((x) => x.from_owner === false && x.thread_id === [...db.threads.keys()][0]);
  const orig = m.blob;
  m.blob = orig.slice(0, 30) + (orig[30] === "A" ? "B" : "A") + orig.slice(31);
  await visitor.goto(linkA);
  await visitor.waitForSelector("#thread .plain.broken");
  m.blob = orig;
  m.from_owner = true;
  await visitor.reload();
  await visitor.waitForSelector("#thread .plain.broken");
  m.from_owner = false;
});

await test("owner can delete a conversation", async () => {
  await owner.click("#refresh");
  await owner.locator("#threads .convo", { hasText: "hello from B" }).locator(".delete").click();
  await owner.waitForFunction(() => /^1 conversation/.test(document.getElementById("summary").textContent));
  assert.equal(db.threads.size, 1);
  await visitor.goto(linkB);
  await visitor.waitForFunction(() => /no conversation/.test(document.getElementById("load-error").textContent));
});

await test("owner can change the passphrase", async () => {
  const NEW = "new passphrase for the inbox";
  await owner.locator("#inbox > details summary").click();
  await owner.fill("#new-pass", NEW);
  await owner.fill("#new-pass2", NEW);
  await owner.click("#change-btn");
  await owner.waitForSelector("#change-msg:not([hidden])");
  await unlock(PASS);
  await owner.waitForSelector("#unlock-error:not([hidden])");
  await unlock(NEW);
  await owner.waitForSelector("#inbox:not([hidden])");
  assert.equal(await owner.locator("#threads .convo").count(), 1);
});

await test("pinned key: matches are used, a swapped key is refused", async () => {
  pinned = db.inbox.public_key;
  await startConversation("with the right pinned key");
  assert.equal(db.threads.size, 2);
  const real = db.inbox.public_key;
  db.inbox.public_key = configJs.match(/pinnedPublicKey:\s*"([^"]+)"/)[1];
  await visitor.goto(base);
  await visitor.fill("#message", "should not be sent");
  await visitor.click("#send");
  await visitor.waitForSelector("#send-error:not([hidden])");
  assert.match(await visitor.textContent("#send-error"), /key/);
  assert.equal(db.threads.size, 2);
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
