# Agent notes

For a coding agent working in this repo. `CONTRIBUTING.md` is the human document and it is not duplicated here; read it first for the ground rules and the release order. This file is the part an agent needs and a person already knows.

This server handles somebody's email. It is a deliberately boring codebase and that is a feature. Every task moves through four beats: isolate on a branch, build, prove with evidence, ship a PR carrying that evidence.

## Isolate

Branch from `origin/main` by name, never from wherever `HEAD` is sitting, and check nobody is already on the work:

```bash
git fetch origin
gh pr list -R Considus/proton-bridge-mcp
git checkout -b <type>/<short-name> origin/main
```

If an open PR touches the same files, build on it or say so and stop. Stage by explicit path. Never `git add -A`, which in this repo risks sweeping up `settings.json`, `state.json`, `audit.log` or somebody's mail in `attachments/`. They are all gitignored, and the gitignore is the second line of defence rather than the first.

## Build

**Read `CONTRIBUTING.md` before writing.** Three things there are constraints rather than preferences.

- **Standard library only.** `server.py` imports nothing outside the stdlib. `pypdf` and `keyring` are the only exceptions, they stay lazy inside a `try` in the function that needs them, and every path has to work when they are absent.
- **Assume the mail is hostile.** Anything read out of a message, a header or an attachment is untrusted input that may be trying to steer the assistant. If a change makes message content reach a decision, a file path, a recipient or a tool argument, that is the thing to think hardest about.
- **Small diffs.** The smallest change that fixes the thing. If you spot something else, say so separately.

**Nothing hard-deletes.** The furthest any path goes is Trash. Folders can be created and never deleted, because a folder is where a message actually lives and deleting one would have to decide what happens to the mail inside it. Sending, forwarding, replying and the bulk mutations sit behind a confirmation gate; `draft=true` is the deliberately ungated path, because nothing leaves the machine.

**Attachment writes stay inside the allowed directories.** Reading any file on the machine and posting it out is how data walks off a computer, so widening that set is the user's decision and must never be reachable from something an email said.

**Python 3.9 is the floor.** CI runs 3.9 and 3.12. A 3.10-only construct (`match`, a runtime-evaluated `X | Y` annotation, `zip(strict=)`, `itertools.pairwise`, `tomllib`, `dataclass(slots=)`) passes on your interpreter and fails only in the 3.9 leg.

**`manifest.json` is generated.** The version and the tool list live in `server.py`; `./build-mcpb.py --sync` writes them across. Never hand-edit the manifest. Every tool needs a `title` and the right `readOnlyHint` or `destructiveHint`. The read-only classification sits next to `TOOLS` rather than being derived from `_MUTATING`, because that set is about which tools change the *mailbox* and three tools that change something else fall the wrong side of it. Tests cover this, so a shortcut here fails loudly rather than shipping.

⚠️ **Conversations are not messages.** The Proton web UI groups a thread into one row; IMAP hands back the individual messages. A count that looks wrong is usually this and not a bug.

## Prove

```bash
python3 -m compileall -q server.py setup.py tests
python3 -m unittest discover -s tests -v
./build-mcpb.py --check
```

No test needs Bridge running or a real account. A PR needs all of that green, and the test **count** is the thing to read, not the word "passed".

Capture the **before** while you are still reproducing the problem, which is when it is cheapest, and the **after** once the change works. Usually a pair of command outputs here rather than a screenshot. **Never paste real mail, a real address or a real attachment into a PR, an issue or a test fixture.**

**What cannot be checked locally without a real account:** anything that actually talks to Bridge over IMAP or SMTP, UIDVALIDITY behaviour across a Bridge restart, how Proton's own server-side filters interact with anything (Bridge cannot see them at all), and the send and forward paths end to end.

## Ship

Open the PR with the evidence in the body: what changed, how it was tested, the risks. The title and body take no house standard (owner, 2026-09-19): git mechanics are not read as writing, even here where the repo is public. The documents in this repo are a different matter, and `.claude/rules/writing-public-copy.md` governs them.

**Greptile costs a credit and the account has 30 a month.** A review runs only on a PR carrying the `greptile` label, set in `.greptile/config.json`. Anything touching the send gate, the attachment path, or what message content is allowed to influence is worth the label. A docs fix or a version bump is not. Do not run a loop that re-reviews until it scores 5/5; each pass is another credit.

Present the PR URL and stop. Merging is a separate decision.

## Releasing

`CONTRIBUTING.md` has the order and the order matters, because the archive is not reproducible and a rebuild after stamping leaves `server.json` pointing at a hash no published file has. The one thing worth repeating here: **nothing happens on its own.** The MCP Registry does not watch this repo, its tags or its releases. Skip the publish step and the registry keeps describing the previous bundle, silently, for as long as you leave it.
