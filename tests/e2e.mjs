// End-to-end test: serves the site locally and drives it in Chromium.
// Run with `npm test`.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
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

const browser = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
const errors = [];
const hosts = new Set();
ctx.on("page", (p) => {
  p.on("pageerror", (e) => errors.push(e.message));
  p.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  p.on("request", (r) => hosts.add(new URL(r.url()).host));
});

const message = "Meet at 7 ✓ <b>not html</b>\nline two 🔐";
const sender = await ctx.newPage();
async function makeLink(password) {
  await sender.goto(base);
  await sender.fill("#message", message);
  if (password) await sender.fill("#password", password);
  await sender.click("#encrypt");
  await sender.waitForSelector("#result:not([hidden])");
  assert.equal(await sender.inputValue("#message"), "", "plaintext cleared after encrypting");
  return sender.inputValue("#link");
}
const reader = await ctx.newPage();
async function open(link) {
  await reader.goto("about:blank");
  await reader.goto(link);
}

let passed = 0;
async function test(name, fn) {
  await fn();
  passed++;
  console.log("✓", name);
}

await test("link-only message round-trips", async () => {
  const link = await makeLink("");
  assert.ok(!link.includes("Meet"), "no plaintext in link");
  await open(link);
  assert.equal(new URL(reader.url()).hash, "", "secret removed from address bar");
  await reader.click("#decrypt");
  await reader.waitForSelector("#plain-wrap:not([hidden])");
  assert.equal(await reader.textContent("#plain"), message);
  assert.equal(await reader.locator("#plain b").count(), 0, "shown as text, not HTML");
});

await test("password message needs the right password", async () => {
  const link = await makeLink("hunter2");
  assert.equal(link.split("#")[1].split(".").length, 2, "no key in a password link");
  await open(link);
  await reader.fill("#unlock-password", "wrong");
  await reader.click("#decrypt");
  await reader.waitForSelector("#reveal-error:not([hidden])");
  await reader.fill("#unlock-password", "hunter2");
  await reader.click("#decrypt");
  await reader.waitForSelector("#plain-wrap:not([hidden])");
  assert.equal(await reader.textContent("#plain"), message);
});

await test("tampered link is rejected", async () => {
  const [url, frag] = (await makeLink("")).split("#");
  const parts = frag.split(".");
  const c = parts[1].split("");
  c[20] = c[20] === "A" ? "B" : "A";
  parts[1] = c.join("");
  await open(url + "#" + parts.join("."));
  await reader.click("#decrypt");
  await reader.waitForSelector("#reveal-error:not([hidden])");
  assert.ok(await reader.locator("#plain-wrap").isHidden());
});

await test("format can't be switched from key link to password link", async () => {
  const [url, frag] = (await makeLink("")).split("#");
  await open(url + "#p1." + frag.split(".")[1]);
  await reader.fill("#unlock-password", "x");
  await reader.click("#decrypt");
  await reader.waitForSelector("#reveal-error:not([hidden])");
});

await test("garbage link shows a friendly error", async () => {
  await open(base + "#garbage");
  assert.match(await reader.textContent("#reveal-error"), /broken or incomplete/);
});

await test("page only talks to its own site", async () => {
  assert.deepEqual([...hosts], [new URL(base).host]);
});

await test("no console or page errors", async () => {
  assert.deepEqual(errors, []);
});

await browser.close();
server.close();
console.log(`\n${passed} passed`);
