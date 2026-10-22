// Sends "you have a new message" push notifications. Called by the database
// (see the notify trigger in supabase/schema.sql) whenever a message lands,
// never by browsers. Notifications carry no message text: everything stays
// end-to-end encrypted, the notification only says something arrived.
import { newVapidKeys, sendPush } from "./webpush.js";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const SUBJECT = "https://chidiclement82-ctrl.github.io/secret-message/";

// Call one of the service-only database functions.
async function db(fn: string, args: Record<string, unknown> = {}) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${fn}`, {
    method: "POST",
    headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, "content-type": "application/json" },
    body: JSON.stringify(args),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${fn}: ${res.status} ${text}`);
  return text ? JSON.parse(text) : null;
}

function sameSecret(a: string, b: string) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return new Response("method not allowed", { status: 405 });
  const config = await db("_push_config");
  if (!sameSecret(req.headers.get("x-notify-secret") ?? "", config.notify_secret)) {
    return new Response("forbidden", { status: 403 });
  }

  // First run: make the VAPID key pair. The private key never leaves the
  // database and this function.
  let vapid = config.vapid_public ? { publicKey: config.vapid_public, privateJwk: config.vapid_private } : null;
  if (!vapid) {
    const keys = await newVapidKeys();
    await db("_push_set_vapid", { public_key: keys.publicKey, private_jwk: keys.privateJwk });
    // Read back: if two calls raced, the database kept only the first pair.
    const saved = await db("_push_config");
    vapid = { publicKey: saved.vapid_public, privateJwk: saved.vapid_private };
  }

  const { thread_id, from_owner, init } = await req.json().catch(() => ({}));
  if (init) return Response.json({ ok: true, vapid_public: vapid?.publicKey ?? null });
  if (!vapid || typeof thread_id !== "string") return Response.json({ ok: false }, { status: 400 });

  // A visitor wrote: tell the owner. The owner replied: tell that visitor.
  const target = from_owner ? thread_id : "owner";
  const message = from_owner
    ? { title: "New reply", body: "You have a new reply to your secret message.", url: `./?open=${thread_id}`, tag: thread_id }
    : { title: "New secret message", body: "Someone sent you a message. Open your inbox to read it.", url: "inbox.html", tag: "owner" };

  const subs: { endpoint: string; p256dh: string; auth: string }[] = await db("_push_targets", { target }) ?? [];
  const results = await Promise.all(subs.map(async (sub) => {
    try {
      const status = await sendPush(sub, message, vapid!, SUBJECT);
      // 404/410: the browser unsubscribed or the subscription expired.
      if (status === 404 || status === 410) await db("_push_mark_dead", { endpoint: sub.endpoint });
      return status;
    } catch (e) {
      console.error("push failed", String(e));
      return 0;
    }
  }));
  return Response.json({ ok: true, sent: results.filter((s) => s >= 200 && s < 300).length, of: subs.length });
});
