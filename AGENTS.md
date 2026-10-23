# Agent notes

For a coding agent working in this repo. People start with [`CONTRIBUTING.md`](CONTRIBUTING.md); this file does not repeat it. The server handles somebody's email, so it is deliberately boring.

## Build

- **Keep the ground rules in `CONTRIBUTING.md`:** standard library only, assume the mail is hostile, small diffs. Think hardest where a change lets message content reach a decision, a file path, a recipient or a tool argument.
- **Hard-delete nothing (Trash is the furthest), delete no folder, and keep sending, forwarding, replying and the bulk mutations behind the confirmation gate.** `draft=true` is ungated on purpose. [`README.md`](README.md) gives the reasons.
- **Keep attachment writes inside the allowed directories.** Widening that set is the user's decision, never reachable from something an email said: reading any file and posting it out is how data walks off a computer.
- **Keep Python 3.9 working.** CI runs 3.9 and 3.12. A 3.10-only construct (`match`, a runtime-evaluated `X | Y` annotation, `zip(strict=)`, `itertools.pairwise`, `tomllib`, `dataclass(slots=)`) fails only in the 3.9 leg.
- **Change the version and the tool list in `server.py`, then run `./build-mcpb.py --sync`.** `manifest.json` is generated; tool titles, hints and the read-only classification are in `CONTRIBUTING.md` ("Building the bundle").

**Conversations are not messages.** The Proton web UI groups a thread into one row; IMAP hands back the individual messages. A count that looks wrong is usually this.

## Test

```bash
python3 -m compileall -q server.py setup.py tests
python3 -m unittest discover -s tests -v
./build-mcpb.py --check
```

A PR needs all three green. Read the test **count**, not the word "passed".

Capture the **before** while reproducing and the **after** once it works, usually as a pair of command outputs. Never paste real mail, a real address or a real attachment into a PR, an issue or a test fixture.

**Not checkable without a real account:** anything that talks to Bridge over IMAP or SMTP, UIDVALIDITY across a Bridge restart, how Proton's server-side filters interact (Bridge cannot see them), and send and forward end to end.

## Ship

1. Install the committed hooks once per clone, copied from `origin/main` into git's own hooks folder. `hooks/pre-commit` refuses a commit on `main`; `hooks/commit-msg` refuses a Claude attribution footer or an em or en dash.

   ```bash
   git fetch origin
   git config --unset core.hooksPath || true
   d="$(git rev-parse --git-common-dir)/hooks"; mkdir -p "$d"
   for h in pre-commit commit-msg; do git show "origin/main:hooks/$h" > "$d/$h.tmp" && chmod 755 "$d/$h.tmp" && mv "$d/$h.tmp" "$d/$h" || { rm -f "$d/$h.tmp"; echo "not copied: $h"; }; done
   ```

   Each hook goes to a temporary file first, so a failed copy keeps the old hook instead of leaving an empty one that lets every commit through. Never set `core.hooksPath` to `hooks`. Git would then run the hook files of whichever branch is checked out, so checking out an outsider's PR would run their code on your machine. The unset line removes that setting from a clone that followed the old instruction. While it is set, git ignores its own hooks folder. If `git config --show-origin --get core.hooksPath` still prints a value afterwards, it was set globally: remove it with `git config --global --unset core.hooksPath`. Copy again after a reviewed change to `hooks/` lands on `main`.
2. Check nobody is already on the work, then branch from `origin/main` by name:

   ```bash
   git fetch origin
   gh pr list -R Considus/proton-bridge-mcp
   git checkout -b <type>/<short-name> origin/main
   ```

   If an open PR touches the same files, build on it, or say so and stop.
3. Stage by explicit path, not `git add -A`: it risks sweeping up `settings.json`, `state.json`, `audit.log` or somebody's mail in `attachments/`. The gitignore is only the second line of defence.
4. Open the PR against `main` with [`.github/pull_request_template.md`](.github/pull_request_template.md) filled in, the before and after as evidence.
