# Maxihu1 website with real accounts

Sign up / log in works for everyone, on every device. Accounts are stored in a database on the server.

## Run it on your computer
1. Install Node.js 22.13 or newer (https://nodejs.org).
2. Open a terminal in this folder and run:  `node server.js`
3. Open http://localhost:3000

No `npm install` needed. Accounts are saved in the file `maxihu1.db` (made automatically).

## Put it online
The site needs a host that runs Node.js. GitHub Pages and other static hosts will NOT work.
Easy options: Render, Railway, Fly.io. Settings:
- Start command: `node server.js`
- Environment: `NODE_ENV=production`
- Keep the database: attach a persistent disk and set `DB_FILE` to a path on it (for example `/data/maxihu1.db`),
  otherwise accounts are lost when the host restarts.
- Use HTTPS (the hosts above do this for you).

## How it works
- Usernames: 3-24 characters (letters, numbers, `_ . -`), not case-sensitive.
- Passwords: at least 8 characters. Stored with scrypt and a random salt, never as plain text.
- Login keeps you in for 30 days using a secure cookie. 10 tries per 15 minutes per IP.
- Your website is `public/index.html`. Put other site files in `public/` too.
