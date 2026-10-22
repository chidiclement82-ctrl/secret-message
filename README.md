# Secret Message

An anonymous, end-to-end encrypted inbox with replies. Anyone can open the site and start a private conversation with the owner. The owner replies from their inbox, and the visitor reads replies with a private link.

- **Send page:** https://chidiclement82-ctrl.github.io/secret-message/ (share this anywhere)
- **Owner's inbox:** https://chidiclement82-ctrl.github.io/secret-message/inbox.html (not linked from the site; bookmark it)
- **Visitor's conversation:** `chat.html#<secret>`, given to the visitor after their first message and remembered on their device

## How it's end-to-end encrypted

- **Owner's keys:** the owner has an ECDH P-256 key pair, created in their browser when the inbox is set up. Its public key is pinned in `config.js`.
- **Each conversation's secret:** each conversation starts with a random 32-byte secret made on the visitor's device. It lives only in their private link after the `#`, which browsers never send to any server. HKDF turns it into:
  - **the conversation key** (AES-256-GCM), which encrypts every message in both directions
  - **the conversation token**, which lets the visitor add to and read the thread. The database stores only its SHA-256, which serves as the thread id.
- **Getting the key to the owner:** the visitor's browser seals the conversation key in an *envelope* for the owner. It uses a one-off ECDH key combined with the owner's public key, then HKDF and AES-GCM, and binds the thread id in. Only the owner's private key opens it.
- **Messages:**
  - They're padded to a multiple of 256 bytes, so length doesn't give away content.
  - Each is bound to its direction, so the database can't pass off a visitor's words as the owner's, or the other way round.
- **The owner's private key** is stored locked with a key made from the owner's passphrase (PBKDF2-SHA256, 600,000 rounds), and the passphrase never leaves the owner's device. The same PBKDF2 run gives an access token. The database keeps only its SHA-256 and only opens the inbox for someone who presents it.
- **The database** only ever sees ciphertext, thread ids and timestamps. Its tables can't be reached through the API; visitors can only call the functions in [`supabase/schema.sql`](supabase/schema.sql).
- **The pages** are only allowed to load their own files and talk to that one database. There are no accounts, cookies or trackers.

## Notifications

- **Who gets them:** the owner can turn on notifications for new messages (🔔 in the inbox), and a visitor for replies in their conversation (🔔 on their conversation page).
- **What they say:** only that something arrived. The text stays end-to-end encrypted and is only readable after opening the inbox or conversation.
- **How they're sent:**
  - When a message lands, a database trigger asks the `notify` Edge Function ([`supabase/functions/notify`](supabase/functions/notify)) to send a standard Web Push.
  - The push is encrypted to the browser (RFC 8291) and signed with VAPID (RFC 8292), using WebCrypto only.
  - The function made its own VAPID key on first run, so the private key never leaves Supabase.
- **iPhone:** add the page to the Home Screen first (Share → Add to Home Screen), then turn notifications on from there. That's Apple's rule for web notifications. The inbox has its own home-screen app that opens straight to the inbox.

**Limits, to be honest about:**
- **Lost passphrase:** if the owner forgets it, nobody can recover the messages.
- **Lost link:** if a visitor loses their link, and it isn't saved on their device, they can't get back into that conversation.
- **Shared link:** anyone who has a visitor's link can read that conversation.
- **What the database sees:** which messages belong to the same conversation, and when they were sent.
- **Trust in the hosting:** like any website, visitors have to trust the site's code as GitHub serves it. The code is all here to check.

## Files

| File | What it is |
|---|---|
| `index.html`, `send.js` | Send page: start a conversation, list conversations saved on this device |
| `chat.html`, `chat.js` | Visitor's conversation: read replies, send follow-ups, reply notifications |
| `sw.js` | Service worker that shows notifications |
| `supabase/functions/notify` | Edge Function that sends Web Push notifications |
| `inbox.html`, `inbox.js` | Owner's inbox: setup, unlock, read and reply, delete conversations, change passphrase |
| `lib.js` | Encryption and database calls (Web Crypto API, no libraries) |
| `config.js` | Database address and public key (all public by design) |
| `style.css` | Styles, light and dark |
| `supabase/schema.sql` | The database: tables and the only functions visitors can call |
| `404.html`, `site.webmanifest`, `*.png`, `favicon.svg`, `robots.txt`, `sitemap.xml` | Error page, app icon and install, link preview, search engines |
| `tests/e2e.mjs` | Browser tests against an in-memory copy of the database |
| `tests/webpush.mjs` | Checks the push encryption and VAPID signing against Node's own crypto |

## Tests

```sh
npm install
npx playwright install chromium
npm test
```

The tests cover:
- setup, including a code typed with phone-style dashes
- starting conversations, and what the database and the server actually see
- conversations saved on the visitor's device
- wrong and right passphrase
- replies reaching only the right visitor, and follow-ups
- broken links
- tampered and direction-flipped messages
- deleting a conversation and changing the passphrase
- the pinned key
- turning on notifications, and tapping one opening the right conversation
- the pages only talking to the site and the database

They run on every pull request, and a push to `main` is only published if they pass.

## Publishing

Every push to `main` goes live automatically (GitHub Pages, source: GitHub Actions).

If the address ever changes (for example, to your own domain), update it in `index.html` (canonical and `og:` tags), `robots.txt`, `sitemap.xml`, and the `/secret-message/` paths in `404.html`.
