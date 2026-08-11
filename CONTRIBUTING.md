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

## Releasing

The order matters, because the archive carries timestamps. The build is not reproducible, a second build of identical sources hashes differently, and a rebuild after stamping leaves `server.json` pointing at a hash no published file has. A client reads that as a corrupted download rather than as a mistake in the listing.

**Nothing here happens on its own.** The MCP Registry does not watch this repo, its tags or its releases. Cut a release without step 7 and the registry carries on describing the previous bundle, silently and for as long as you leave it.

1. **Bump the version in `server.py`**, not in `manifest.json`, which is generated from it. Then `./build-mcpb.py --sync`.
2. **Check the listing before going further.** The registry rejects a `description` over 100 characters, and it does so at publish time, long after a release has been cut. `mcp-publisher validate` catches it and publishes nothing.
3. **Build once.** `./build-mcpb.py` packs `dist/proton-bridge-mcp-<version>.mcpb` and stamps its SHA-256 and its download URL into `server.json`. That write has to be committed, which is why the build sits here rather than after the tag. Do not build again after this.
4. **Open a PR carrying the bump, the synced `manifest.json` and the stamped `server.json`, and merge it.** Everything below assumes `main` is final.
5. **Tag the merge commit.** The tag has to contain the stamp, so that the source it points at agrees with the listing and with the copy of `manifest.json` inside the bundle you are about to ship. Until 2026-08-11 this said to tag before building, which cannot do that, because at that point the stamp does not exist yet and lands on `main` untagged after the release.
6. **Cut the release with that exact file.**

   ```bash
   gh release create v<version> dist/proton-bridge-mcp-<version>.mcpb -R Considus/proton-bridge-mcp
   ```

7. **Publish, logging in immediately first.** The registry JWT expires quickly enough that a login from earlier in the same sitting will fail.

   ```bash
   SEED=$(openssl pkey -in <key.pem> -outform DER | tail -c 32 | xxd -p -c 64)
   mcp-publisher login dns --domain considus.com --private-key "$SEED"
   mcp-publisher publish
   ```

   The signing key is the only proof of the `com.considus` namespace. Its public half is the `v=MCPv1` TXT record on considus.com, so the key can be checked against DNS rather than taken on trust.

8. **Verify what was published, not what you built.** Download the release asset, hash it, and compare against `fileSha256` in `server.json`.
9. **Deprecate the version this replaces.**

   ```bash
   mcp-publisher status --status deprecated --message "Superseded by <version>." \
     com.considus/proton-bridge-mcp <old-version>
   ```

   Read the status back from `/v0/servers/com.considus%2Fproton-bridge-mcp/versions`. The `?search=` listing reports every version as active regardless, and will tell you the change failed when it did not.

10. **Rebuild the website if this README changed.** considus.com's product pages are generated from it, by `build-product-pages.py` in `Considus-Ops`.

## Proposing a change

Open a pull request against `main`. Say what it changes and why. If it touches anything that sends, files, or writes to disk, a line on how you tested it helps a lot.

## Found a security hole?

Please don't open a public issue for it. There's a private path in [SECURITY.md](SECURITY.md).
