# Secret Message

Write a private message, get a link, send it. Only someone with the link (and the password, if you set one) can read it.

## How it's end-to-end encrypted

- The message is encrypted in your browser with **AES-256-GCM** before it goes anywhere.
- The encrypted message and its key go in the link after the `#`. Browsers never send that part to a server, so the website only ever serves an empty page.
- **Optional password:** the key is then made from the password (PBKDF2-SHA256, 600,000 rounds) and isn't in the link. Share the password some other way.
- The page's security policy forbids it from contacting any server (`connect-src 'none'`) or loading outside scripts or fonts.
- Changed links fail to open instead of showing altered text.
- Nothing is stored, so a message can't be deleted after it's read. The link *is* the message.

## Files

| File | What it is |
|---|---|
| `index.html` | The page |
| `app.js` | Encryption and page logic (Web Crypto API, no libraries) |
| `style.css` | Styles |

No build step, no dependencies, no server.

## Put it online

1. On GitHub, open **Settings → Pages**. Under **Build and deployment → Source**, choose **GitHub Actions**.
2. Open the **Actions** tab and run "Deploy to GitHub Pages". The site is live about a minute later.

Every push to `main` after that goes live automatically.
