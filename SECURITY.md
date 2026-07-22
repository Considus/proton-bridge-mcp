# Security

This is a tool for reading email with an assistant, so the whole thing is built on the assumption that the mail it handles is hostile. If you've found a way past that — a folder name or search term that reaches the IMAP session, an address the recipient rules should have refused, a file that gets written outside the attachments directory, a password that ends up somewhere it shouldn't — I'd genuinely like to know.

## Reporting a vulnerability

Please don't open a public issue for anything exploitable. Use GitHub's private reporting instead: go to the **Security** tab and choose **Report a vulnerability**. That opens a private advisory only you and I can see, and we can sort it out there before it's public.

Tell me what you found, how to reproduce it, and what it lets an attacker do. A proof of concept helps, but a clear description is plenty. I'll confirm I've received it within a few days, and I'll keep you posted while it's being fixed. Once there's a fix out, you're welcome to the credit if you want it.

## What's in scope

The server (`server.py`) and the setup tool (`setup.py`). The kinds of thing worth reporting: injection into the IMAP or SMTP session, a way to send mail as an address that isn't allowlisted, a way to mail an address that only appeared inside message content, escaping the attachments directory, or leaking the Bridge password out of the credential store.

Bugs in Proton Mail Bridge itself belong with Proton, not here — this project only talks to Bridge, it isn't part of it.

## Supported versions

This is a single active line of development on `main`. Fixes land there; there are no separately maintained older releases to back-port to.
