# Security

This is a tool for reading email with an assistant, so the whole thing is built on the assumption that the mail it handles is hostile. If you've found a way past that, I'd like to know. That might be a folder name or a search term that reaches the IMAP session, an address the recipient rules should have refused, a file that gets written outside the attachments directory, or a password that ends up somewhere it shouldn't.

## Reporting a vulnerability

Please report security issues **privately**, and don't open a public issue or a pull request.

Email **security@considus.com**, or, if you'd rather keep it on GitHub, use the **Report a vulnerability** button on this repository's [Security tab](https://github.com/Considus/proton-bridge-mcp/security), which opens GitHub's private reporting. GitHub asks you to sign in first, and only you and I can see the report.

Tell me what you found, how to reproduce it, which version or commit it affects, and what it lets an attacker do. A proof of concept helps, but a clear description is plenty.

I'll acknowledge your report within **3 business days** and keep you posted while I look into it. This is coordinated disclosure, so please give me a reasonable amount of time to ship a fix before you make it public. You're welcome to the credit once it's out, or to stay anonymous, whichever you'd prefer.

The same terms cover every Considus project and both websites, catchlight.app and considus.com, and the policy page for this project is at [considus.com/security](https://considus.com/security/).

## What's in scope

The server (`server.py`) and the setup tool (`setup.py`). The kinds of thing worth reporting: injection into the IMAP or SMTP session, a way to send mail as an address that isn't allowlisted, a way to mail an address that only appeared inside message content, escaping the attachments directory, or leaking the Bridge password out of the credential store.

Bugs in Proton Mail Bridge itself belong with Proton, not here. This project only talks to Bridge, it isn't part of it.

## Safe harbour

You won't face legal action from me or from Considus for research done in good faith, so long as you avoid violating anyone's privacy, avoid destroying data, and follow this policy.

## Supported versions

This is a single active line of development on `main`. Fixes land there, and there are no separately maintained older releases to back-port to.
