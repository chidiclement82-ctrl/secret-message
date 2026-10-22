# Secret Message

An anonymous, end-to-end encrypted inbox. Anyone can open the site and send the owner a message. Only the owner can read it.

- **Send page:** https://chidiclement82-ctrl.github.io/secret-message/ (share this anywhere)
- **Owner's inbox:** https://chidiclement82-ctrl.github.io/secret-message/inbox.html (not linked from the site; bookmark it)

## How it's end-to-end encrypted

- The owner has an ECDH P-256 key pair, created in their browser when the inbox is set up.
- **Sending:** the visitor's browser makes a one-off key pair and combines it with the owner's public key (ECDH + HKDF-SHA256). It encrypts the message with the result using AES-256-GCM. Only this locked version is sent.
- **Storage:** the database (Supabase) only ever stores locked messages. Messages are padded to a multiple of 256 bytes so their length doesn't give away what's in them.
- **The owner's private key** is stored locked with a key made from the owner's passphrase (PBKDF2-SHA256, 600,000 rounds). The passphrase never leaves the owner's device.
- **Reading:** the same PBKDF2 run also gives an access token. The database keeps only a SHA-256 of that token, and only hands over messages to someone who presents the token. Messages are unlocked in the owner's browser.
- **Nothing else:**
  - The tables can't be reached through the API. Visitors can only call the functions in [`supabase/schema.sql`](supabase/schema.sql).
  - The pages' security policy only lets them load their own files and talk to that one database.
  - There are no accounts, cookies or trackers.
- **Optional extra protection:** pin the owner's public key in `config.js` (`pinnedPublicKey`). Senders then refuse any other key, even if someone took over the database.

**Limits, to be honest about:**
- **Forgotten passphrase:** nobody can recover the messages.
- **Trust in the hosting:** like any website, visitors have to trust the site's code as GitHub serves it. The code is all here to check.

## Files

| File | What it is |
|---|---|
| `index.html`, `send.js` | Send page |
| `inbox.html`, `inbox.js` | Owner's inbox: setup, unlock, read, copy, delete, change passphrase |
| `lib.js` | Encryption and database calls (Web Crypto API, no libraries) |
| `config.js` | Database address and public key (all public by design) |
| `style.css` | Styles, light and dark |
| `supabase/schema.sql` | The database: tables and the only functions visitors can call |
| `404.html`, `site.webmanifest`, `*.png`, `favicon.svg`, `robots.txt`, `sitemap.xml` | Error page, app icon and install, link preview, search engines |
| `tests/e2e.mjs` | Browser tests against an in-memory copy of the database |

## Tests

```sh
npm install
npx playwright install chromium
npm test
```

The tests cover:
- setup with a wrong code, a short passphrase, then the right code
- sending, anonymously and with a name
- what the database actually stores (only ciphertext, padded)
- unlocking with a wrong passphrase and the right one
- messages shown as text, not HTML
- tampered messages refused
- deleting a message and changing the passphrase
- the pages only talking to the site and the database

They run on every pull request, and a push to `main` is only published if they pass.

## Publishing

Every push to `main` goes live automatically (GitHub Pages, source: GitHub Actions).

If the address ever changes (for example, to your own domain), update it in `index.html` (canonical and `og:` tags), `robots.txt`, `sitemap.xml`, and the `/secret-message/` paths in `404.html`.
