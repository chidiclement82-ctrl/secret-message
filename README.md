# Secret Message

Write a private message, get a link, send it. Only someone with the link (and the password, if you set one) can read it.

## How it's end-to-end encrypted

- The message is encrypted in your browser with **AES-256-GCM** before it goes anywhere.
- The encrypted message and its key go in the link after the `#`. Browsers never send that part to a server, so the website only ever serves an empty page.
- **Optional password:** the key is then made from the password (PBKDF2-SHA256, 600,000 rounds) and isn't in the link. Share the password some other way.
- The page's security policy forbids it from contacting any server (`connect-src 'none'`) or loading outside scripts or fonts.
- Changed links fail to open instead of showing altered text.
- Nothing is stored, so a message can't be deleted after it's read. The link *is* the message.

## Features

- Works on phones and computers, in light and dark mode.
- **Share…** opens the phone's own share sheet (WhatsApp, Telegram, Signal, SMS…). There's also a direct WhatsApp button.
- Can be installed to the home screen like an app.
- Link previews show a "Someone sent you a secret message" card. Previews never see the secret: it's after the `#`, which isn't part of what they fetch.

## Files

| File | What it is |
|---|---|
| `index.html` | The page |
| `app.js` | Encryption and page logic (Web Crypto API, no libraries) |
| `style.css` | Styles, light and dark |
| `404.html` | Shown for any wrong address |
| `site.webmanifest`, `*.png`, `favicon.svg` | App icon, home-screen install and link-preview image |
| `robots.txt`, `sitemap.xml` | Help search engines find the site |
| `tests/e2e.mjs` | Browser tests: encrypt and decrypt, wrong password, tampered and broken links, no outside network requests |

No build step, no runtime dependencies, no server.

## Tests

```sh
npm install
npx playwright install chromium
npm test
```

Tests run on every pull request. A push to `main` is only published if they pass.

## Publishing

Every push to `main` goes live automatically at https://chidiclement82-ctrl.github.io/secret-message/ (GitHub Pages, source: GitHub Actions).

If the address ever changes (for example, to your own domain), update it in `index.html` (canonical and `og:` tags), `robots.txt`, `sitemap.xml`, and the `/secret-message/` paths in `404.html`.
