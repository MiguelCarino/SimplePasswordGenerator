# Password

Make a strong password, and send it to someone without it leaking →
**[password.carino.systems](https://password.carino.systems)**

This is the plain-language version, built for people who are not going to enjoy
the words "threshold", "digest" or "GF(2⁸)". Three things, no jargon:

1. **Make one** — a strong password, with a length you pick.
2. **Send it safely** — split it into two halves that are useless on their own.
3. **Open what I was sent** — paste the two messages back together.

The technical version, with arbitrary *k*-of-*n* splitting, digests and the
algorithm walkthroughs, lives at
**[hash.carino.systems](https://hash.carino.systems)**. Both sites share the same
engine, so shares made on either one open on the other.

## Why splitting, and not just sending the password

Sending a password in one message means whoever reads that message has it —
the mail server, the backup of that mail server, anyone still logged into that
laptop. Chopping it into chunks does not help either: two thirds of a
24-character password leaves an 8-character brute force, which is minutes.

This uses **Shamir's Secret Sharing over GF(256)**. Any *k* parts rebuild the
secret and any *k−1* reveal **nothing at all** — not the secret, not its length,
not one character. That is information-theoretic, so the parts hold even against
an attacker with unlimited computing power. The simple site always makes 2 of 2.

Each part is emitted as a **whole message**, not a bare code — it says which part
it is, that another is coming, and where to open them. A recipient who has never
seen this before can act on it without being told anything.

Send the parts down **different channels** — one by email, one by text. Both by
email and you are back where you started.

## Guarantees

- Nothing is uploaded. No servers, no storage, no accounts — closing the tab
  erases everything.
- A `Content-Security-Policy` with `connect-src 'none'` means the browser
  *enforces* that, rather than this page merely promising it.
- Spellcheck and autocomplete are off on every secret field: browser "enhanced"
  spellcheckers ship the contents of text fields to a remote service.

## Links

Both tabs are addressable, so you can send someone straight to the one they need:

| Link | Opens |
|---|---|
| `#password` | make a password (the default) |
| `#send` | split a secret to send |
| `#open` | paste parts back together — this is the link inside every part message |

Older `#pass`, `#share`, `#split`, `#recover` and `#combine` links still work.

## Share format

`CS1-` followed by Crockford base32 — no `I`, `L`, `O` or `U`, so a part survives
being read aloud or copied by hand, and look-alikes fold back on decode:

    CS1-<base32 of [version, k, x, ...y, crc16]>

A CRC-16 catches a mistyped part before it is used, and a truncated SHA-256 of the
secret rides *inside* the split payload — so recovery is verified end to end while
the checksum leaks nothing on its own.

The engine is [`carino-secrets.js`](carino-secrets.js), vendored byte-identically
into every Carino site that handles secrets. Vendored rather than loaded from a
shared origin on purpose: no single compromise should reach across the fleet, and
each page stays provably self-contained.

## License

Licensed under the **GNU Affero General Public License v3.0 or later** (AGPL-3.0-or-later) — see [LICENSE](LICENSE). Copyright © 2026 Miguel Carino.
