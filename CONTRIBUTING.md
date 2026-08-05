# Contributing

Thanks for taking a look. This is a small, deliberately boring codebase, and that's a feature — it handles someone's email, so surprises aren't welcome.

## Ground rules

A few things the project holds to, so a change is worth proposing if it fits them:

- **The server is standard-library only.** `server.py` imports nothing outside Python's stdlib. `pypdf` and `keyring` are optional, imported lazily inside a `try`, and the code works without them. Please keep it that way — a mail tool people run locally shouldn't drag in a dependency tree.
- **Assume the mail is hostile.** Anything read out of a message or attachment is untrusted input. If your change reads message content, think about what happens when that content is trying to make the assistant do something.
- **Small diffs.** The smallest change that fixes the thing, rather than a rewrite alongside it. If you spot something else, say so separately.

## Running the tests

None of them need Bridge running or a real account.

```bash
python3 -m unittest discover -s tests -v
```

CI runs the same tests on Python 3.9 and 3.12, plus a compile check. A pull request needs those green before it goes in.

## Building the bundle

`manifest.json` is what the MCP Registry and the Connectors Directory list, and it has to keep describing the server. The tool list and the version live in `server.py`, so the build copies them across and refuses to run if the two have drifted.

```bash
./build-mcpb.py --check
```

`--sync` writes the tool list and version into `manifest.json` from `server.py`, which is what you want after adding or renaming a tool. With no argument it checks, packs `dist/proton-bridge-mcp-<version>.mcpb`, and stamps the artifact's SHA-256 into `server.json`.

Every tool needs a title and the right `readOnlyHint` or `destructiveHint`, and a directory submission is rejected without them. The classification sits next to `TOOLS` in `server.py` rather than being derived from `_MUTATING`, because that set is about which tools change the *mailbox*, and three tools that change something else fall the wrong side of it. Tests cover this.

Releasing, and the order matters. Build once, upload the artifact that build produced, then publish `server.json` from the same run. The archive carries timestamps, so the build is not reproducible and a second build of identical sources hashes differently. Rebuild after stamping and `server.json` points at a hash no published file has, which a client reads as a corrupted download rather than a mistake in the listing.

## Proposing a change

Open a pull request against `main`. Say what it changes and why. If it touches anything that sends, files, or writes to disk, a line on how you tested it helps a lot.

## Found a security hole?

Please don't open a public issue for it. There's a private path in [SECURITY.md](SECURITY.md).
