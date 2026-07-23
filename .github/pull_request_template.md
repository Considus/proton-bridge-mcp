<!-- Thanks for the pull request. Fill in what applies and delete what doesn't. -->

## What this changes

<!-- What behaves differently after this merges, and the reason it needed doing. -->

## How you tested it

<!-- CI covers the unit tests. If this touches anything that sends, files, or writes to
     disk, a line on what you ran it against helps a lot. Nothing here needs a real
     account or Bridge running. -->

```
python3 -m unittest discover -s tests -v
```

## Ground rules

<!-- From CONTRIBUTING.md. Tick what holds, or say below which one this touches and why. -->

- [ ] Standard library only. Nothing new imported at the top of `server.py`
- [ ] Anything that sends stays gated behind an explicit `confirmed=true`
- [ ] Message and attachment content is still treated as untrusted input
- [ ] Small diff. Unrelated things spotted along the way are raised separately

## Anything else

<!-- Linked issues, follow-up work you left out on purpose, anything a reviewer should
     look at first. -->
