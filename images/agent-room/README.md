# Room image: agent

The room our own agents run in: Claude Code and Codex CLI at the versions the
agents run today, with node, python3, git, curl and tmux, as the non-root
user `agent` (uid 1000). Claude Code refuses `--dangerously-skip-permissions`
as root. Published as `ghcr.io/cathedralai/agent-room` by
`.github/workflows/publish-agent-room.yml`; pin the digest from the run
summary, never a tag.

No credentials are in the image. Claude Code and Codex log in at run time.

## HOME

`HOME` is `/workspace/home`. In a sealed room `/workspace` is the persistent
workspace (create with `"workspace": "<name>"`); `/work` is scratch and goes
with the room. A room with no workspace uses the `/workspace/home` in the
image.

A new workspace comes up owned by the hotel's service user, mode 0755, so the
agent cannot make `HOME` there, and a sealed hotel ignores setuid bits, so sudo
cannot either. The room's creator runs one exec as root after the create:

```json
{"cmd": ["install", "-d", "-o", "agent", "-g", "agent", "-m", "0700", "/workspace/home"], "user": "root"}
```

It is safe on every create: on a workspace that has `HOME` it only sets the
owner and mode of the directory. Until it runs, the entrypoint
(`agent-room-init`) writes a warning and the room runs without `HOME`.

Execs run in `/work` unless the exec names a `cwd`, as in every room. Pass
`"cwd": "/workspace/home"` or `cd` first.

The hotel mounts workspaces `noexec`. Scripts in `HOME` run (`sh`, `python3`,
`node`, git hooks), but an ELF binary on the workspace dies with SIGSEGV
(exit 139) under gVisor, so keep compiled tools in the image or under `/tmp`.
For the same reason Claude Code must not update itself into `~/.local/bin`.

## Use

```json
{"image": "ghcr.io/cathedralai/agent-room@sha256:<digest>", "workspace": "<name>"}
```

then the root exec above.

```sh
claude --version   # 2.1.312 (Claude Code)
codex --version    # codex-cli 0.157.1
```

`DISABLE_AUTOUPDATER=1` keeps Claude Code at the pinned version. tini is PID 1
and reaps what execs and tmux leave behind.

## Pins

| What | Pin |
|---|---|
| Claude Code | `@anthropic-ai/claude-code` `2.1.312` |
| Codex CLI | `@openai/codex` `0.157.1` |
| Base | `node:24-bookworm-slim` (Node 24.22.2) by digest |

`npm ci` installs the CLIs from `package-lock.json`, which pins every package
by sha512. The build fails if `claude --version` or `codex --version` does not
print the pinned version.

## Check

`smoke-test.sh IMAGE_REF` runs on every pull request and on every publish. It
checks the versions, the user and `HOME`, then starts the image the way a
hotel does (`/work` and a workspace owned by uid 991, `-w /work`,
`sleep infinity`), runs the root exec, checks `HOME` is `agent 700` and that
sudo is not in the image, and that a second room on the same workspace finds
`HOME` with its files.

## Visibility

A sealed hotel pulls with no credentials, so the package must be public. If it
comes up private, an owner makes it public; the `verify-public` job checks
anonymous access.

## Update

Change the versions in `package.json`, run `npm install --package-lock-only`,
change the version checks in `Dockerfile` and `smoke-test.sh`, merge, then pin
the new digest where it is used. Never reuse a tag: the workflow refuses to
overwrite `sha-<commit>`.
