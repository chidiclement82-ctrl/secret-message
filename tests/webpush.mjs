// Checks supabase/functions/notify/webpush.js against an independent
// implementation built from Node's own crypto: the push payload must decrypt
// per RFC 8291/8188, and the VAPID JWT must verify per RFC 8292.
import assert from "node:assert/strict";
import { createDecipheriv, createECDH, createPublicKey, createVerify, hkdfSync, randomBytes } from "node:crypto";
import * as wp from "../supabase/functions/notify/webpush.js";

// A browser's subscription keys.
const ua = createECDH("prime256v1");
ua.generateKeys();
const auth = randomBytes(16);
const message = JSON.stringify({ title: "New secret message", body: "Someone sent you a message ✓", url: "inbox.html" });

const body = Buffer.from(await wp.encryptPayload(new TextEncoder().encode(message), wp.toB64(ua.getPublicKey()), wp.toB64(auth)));

// Decrypt as a browser would (RFC 8188 header, RFC 8291 key derivation).
const salt = body.subarray(0, 16);
const rs = body.readUInt32BE(16);
const idlen = body[20];
const asPublic = body.subarray(21, 21 + idlen);
const ciphertext = body.subarray(21 + idlen);
assert.equal(rs, 4096);
assert.equal(idlen, 65);
const ecdh = ua.computeSecret(asPublic);
const ikm = Buffer.from(hkdfSync("sha256", ecdh, auth, Buffer.concat([Buffer.from("WebPush: info\0"), ua.getPublicKey(), asPublic]), 32));
const cek = Buffer.from(hkdfSync("sha256", ikm, salt, Buffer.from("Content-Encoding: aes128gcm\0"), 16));
const nonce = Buffer.from(hkdfSync("sha256", ikm, salt, Buffer.from("Content-Encoding: nonce\0"), 12));
const decipher = createDecipheriv("aes-128-gcm", cek, nonce);
decipher.setAuthTag(ciphertext.subarray(-16));
const plain = Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]);
assert.equal(plain[plain.length - 1], 2, "last-record delimiter");
assert.equal(plain.subarray(0, -1).toString(), message);
console.log("✓ push payload decrypts like a browser would");

// VAPID: a valid ES256 JWT for the push service's origin, plus the key.
const vapid = await wp.newVapidKeys();
const header = await wp.vapidAuth("https://fcm.googleapis.com/fcm/send/abc", vapid, "https://example.org/");
const [, jwt, k] = header.match(/^vapid t=([^,]+), k=(.+)$/);
const [h, c, sig] = jwt.split(".");
const raw = Buffer.from(k, "base64url");
const pub = createPublicKey({ format: "jwk", key: { kty: "EC", crv: "P-256", x: raw.subarray(1, 33).toString("base64url"), y: raw.subarray(33).toString("base64url") } });
assert.ok(createVerify("SHA256").update(`${h}.${c}`).verify({ key: pub, dsaEncoding: "ieee-p1363" }, Buffer.from(sig, "base64url")));
const claims = JSON.parse(Buffer.from(c, "base64url").toString());
assert.equal(claims.aud, "https://fcm.googleapis.com");
assert.ok(claims.exp > Date.now() / 1000 && claims.exp <= Date.now() / 1000 + 24 * 3600, "expiry within 24h");
console.log("✓ VAPID signature verifies");
