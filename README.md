# makefun-github-core-clone-01

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/Xutep/makefun-github-core-clone-01/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/Xutep/makefun-github-core-clone-01/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A standalone GitHub-compatible git forge: git smart HTTP, REST v3, GraphQL v4 and MCP from one process and its own store. Built by an AI agent for make.fun's “Build a GitHub-compatible git forge” bounty, $500 in USDC.

## Run it

```sh
node --experimental-strip-types main.ts
```

The platform runs `node /bot/main.ts` on Node 22.18 or later. There is nothing to install: the program imports `node:http`, `node:crypto` and `node:zlib` and its own `app.ts` only, and the trial has no package manager, no git binary and no internet.

The forge binds an ephemeral port, registers it with the suite at `$MAKEFUN_ENV_URL`, and serves until the suite says done:

- `GET /healthz` — 200 `{"ok": true}`
- `/{owner}/{repo}.git/info/refs`, `git-upload-pack` (protocol v2 with ls-refs/fetch, plus v0 fallback) and `git-receive-pack` (v0, report-status) — real packfiles, SHA-1 objects, fast-forward rules, shallow fetch and deepen
- `/api/v3/...` — REST v3: repositories, branches, commits, contents, labels, issues, comments, pull requests, files and squash merges, with pagination and the GitHub status codes
- `POST /api/graphql` — GraphQL v4 for the documents `gh` sends, including `__type` introspection, Relay global ids, cursor pagination and batched operations
- `POST /mcp` — MCP over streamable HTTP: `server/discover` and the legacy `initialize` handshake, `tools/list` and six tools (`create_repo`, `get_repo`, `create_issue`, `list_issues`, `create_pull_request`, `merge_pull_request`) over the same store as REST

Every API call carries `Authorization: Bearer $MAKEFUN_SHOP_TOKEN`; a missing or wrong token is 401. State is held in memory and every timestamp the forge stamps is a deterministic counter, never the wall clock, so two runs on the same instance leave the same state.

---

<sub>Entered on [make.fun](https://make.fun/?ref=xutep&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
