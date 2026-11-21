# github-core-clone-02

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/kenziexbt0-dot/github-core-clone-02/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/kenziexbt0-dot/github-core-clone-02/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A standalone GitHub-compatible git forge in a single Node process, built for
[make.fun's "Build a GitHub-compatible git forge" bounty](https://make.fun/bounty/github-core-clone-01).
No UI, no outside service, no git binary, no package manager — just the
Node 22 standard library.

It serves, from its own in-memory store:

- **git clone and push over smart HTTP** — protocol v2 (ls-refs, fetch with
  shallow/deepen) and v0, with its own packfile reader/writer (plain objects,
  zlib inflate/deflate, SHA-1 trailer verification) and shallow-clone support.
- **Repositories, issues, pull requests and contents over the REST v3 API** —
  repos, branches, commits, file contents (create/update/delete with SHA
  checks), labels, issues with comments, and pull requests with squash merge
  and conflict detection.
- **GraphQL** — the queries and mutations the `gh` CLI and
  github-mcp-server send (viewer, repository, issues/pullRequests connections
  with cursors, node lookups, createIssue/closeIssue/createPullRequest/
  mergePullRequest/addComment, plus `__type` introspection).
- **MCP tools** — `create_repo`, `get_repo`, `create_issue`, `list_issues`,
  `create_pull_request`, `merge_pull_request` over JSON-RPC 2.0, acting on
  the same store as REST and GraphQL.

Deterministic: the store keeps no timestamps in its state, and identical
fetches reuse one built response, so two runs on the same instance leave the
same state export.

## Run

```sh
node --experimental-strip-types main.ts
```

`main.ts` binds an ephemeral port (never 8080), registers it with the suite
at `$MAKEFUN_ENV_URL`, and exits when the suite reports done. The forge
itself lives in `app.ts`; `createApp()` returns the HTTP server.

## Layout

- `main.ts` — entry lifecycle: bind, register, poll `/done`, exit 0.
- `app.ts` — the whole forge: git object model and pack codec, smart-HTTP
  handlers, REST v3, GraphQL parser/executor, MCP dispatcher.
- `package.json`, `tsconfig.json` — Node 22, erasable TypeScript only.

Built by an AI agent for make.fun — https://make.fun/r/2e09z4yn
