# SimplePasswordGenerator
Simple Password Generator that also outputs encrypted string in the most commong algorithms for pragmatic purposes.

## Tabs

Two tabs, both deep-linkable so you can send someone straight to the one they need:

| Link | Opens |
|---|---|
| `#pass` | password generator (also the default) |
| `#share` | secret splitting |
| `#split` / `#recover` | the Share tab, on that specific sub-tab |

Tabs write the hash as you click, so Back returns to the previous tab.

**Share this password** on the Generate tab carries the current password straight into
Share, already split. **Generate a password** on the Share tab goes back the other way.

Shares regenerate as you type or paste — no button to press. The default is 2-of-2, so
a secret is split the moment it lands in the box.

## Splitting a secret to hand it over safely

Sharing a password by chopping it into chunks leaks it: two thirds of a 24-character
password leaves an 8-character brute force. This tool instead uses **Shamir's Secret
Sharing over GF(256)** — pick *n* shares and a threshold *k*, and any *k* of them
rebuild the secret while any *k−1* reveal **nothing at all**, not even its length.
That is an information-theoretic guarantee, so the shares hold even against an
attacker with unlimited computing power.

Send each share down a **different channel** — one by email, one by SMS, one read
aloud — so no single inbox or chat log ever holds enough to reconstruct anything.

Everything runs in the browser. No secret, share, or fragment is ever transmitted,
so there is no server to breach and nothing held in custody.

**Share format** — `CS1-` followed by Crockford base32 (no `I`, `L`, `O` or `U`, so
shares survive being read aloud or copied by hand; look-alikes fold back on decode):

    CS1-<base32 of [version, k, x, ...y, crc16]>

A CRC-16 catches a mistyped share before it is used, and a truncated SHA-256 of the
secret is carried *inside* the split payload — so recovery is verified end-to-end
while the checksum itself leaks nothing about the secret.

## License

Licensed under the **GNU Affero General Public License v3.0 or later** (AGPL-3.0-or-later) — see [LICENSE](LICENSE). Copyright © 2026 Miguel Carino.
