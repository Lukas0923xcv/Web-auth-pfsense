# Review request (draft to post)

Drafts for asking for a human review. Post them yourself; edit freely.

## Netgate forum (Packages, or General pfSense Questions)

**Title:** Looking for reviewers: WebAuthn/passkey second factor for the pfSense GUI (open source)

> I've been working on an open-source add-on that adds a passkey / security-key (WebAuthn) step after the normal password login on the pfSense CE web GUI. It is meant for people who reach the GUI through a Cloudflare Tunnel, but it works on the LAN too.
>
> Because it guards admin access to a firewall, I don't want anyone to rely on it before someone other than me has looked at it. It was written with the help of an AI assistant and has only had AI reviews so far, so a human review is what it needs most.
>
> - Code: https://github.com/Lukas0923xcv/web-auth-pfsense (Apache 2.0, about 3,000 lines of PHP)
> - Where to start, threat model, files in priority order: docs/REVIEW-GUIDE.md
> - The tests run anywhere with PHP 8.2+ (`sh tests/run_all.sh`), and docs/VM-TEST.md walks through a test on a pfSense CE 2.8.1 VM.
>
> It hooks into authgui.inc, auth_check.inc and xmlrpc.php, so I'd especially value feedback from anyone who knows those files, or WebAuthn. Findings, questions, or "I looked at X and it seemed fine" are all welcome, as GitHub issues (or privately via Security > Report a vulnerability).

## r/PFSENSE

**Title:** Open-source passkey (WebAuthn) 2FA for the pfSense web GUI: looking for people to review and test it

> I built an add-on that puts a passkey / security-key step after the password on the pfSense CE 2.8.1 GUI, mainly for access through a Cloudflare Tunnel. It is not a Netgate package and it patches three core files, so please don't put it on a production box yet.
>
> What I'm looking for:
> - **Reviewers**: anyone comfortable with PHP, WebAuthn or pfSense's auth code. Start with docs/REVIEW-GUIDE.md: it has the threat model and the files in priority order.
> - **Testers**: run docs/VM-TEST.md on a throw-away VM (about 45 minutes) and post the results as an issue.
>
> Repo: https://github.com/Lukas0923xcv/web-auth-pfsense
>
> It was written with an AI assistant and has only had AI reviews, which is exactly why I want human eyes on it. Thanks!
