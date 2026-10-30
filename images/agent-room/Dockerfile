# Cathedral room image for our own agents: Claude Code and Codex CLI at the
# versions the agents run today, as the non-root user "agent".
#
# Claude Code refuses --dangerously-skip-permissions as root, so the agent is
# uid 1000. HOME is /workspace/home: in a sealed room /workspace is the
# persistent workspace mount and /work is scratch that goes with the room.
# The hotel makes a new workspace owned by root, so the agent cannot make its
# own HOME there; agent-home-init does it at room start through a sudo rule
# that allows that one command and nothing else.
#
# No credentials are in the image. Claude Code and Codex log in at run time.

ARG NODE_IMAGE=node:24-bookworm-slim@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c

FROM ${NODE_IMAGE}

ARG CLAUDE_CODE_VERSION=2.1.312
ARG CODEX_VERSION=0.157.1

LABEL org.opencontainers.image.title="Cathedral room: agent" \
      org.opencontainers.image.description="Claude Code ${CLAUDE_CODE_VERSION} and Codex CLI ${CODEX_VERSION} as a non-root user, HOME on the workspace" \
      org.opencontainers.image.source="https://github.com/cathedralai/cathedral-sandbox" \
      org.cathedral.agent-room.claude-code="${CLAUDE_CODE_VERSION}" \
      org.cathedral.agent-room.codex="${CODEX_VERSION}"

# tini reaps the processes that execs and tmux leave behind; sudo runs
# agent-home-init only.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git python3 sudo tini tmux \
    && rm -rf /var/lib/apt/lists/*

# The node image's user "node" holds uid 1000; the agent takes it.
RUN userdel --remove node \
    && if getent group node >/dev/null; then groupdel node; fi \
    && useradd --uid 1000 --user-group --no-create-home --home-dir /workspace/home --shell /bin/bash agent \
    && install -d -o root -g root -m 0755 /workspace \
    && install -d -o agent -g agent -m 0700 /workspace/home

# npm ci installs the exact versions in package-lock.json and checks each
# tarball against its sha512. The lockfile lists every platform package; the
# musl builds of Claude Code are not used on this glibc image, so drop them.
COPY package.json package-lock.json /opt/agent-tools/
RUN cd /opt/agent-tools \
    && npm ci --no-audit --no-fund \
    && rm -rf node_modules/@anthropic-ai/claude-code-linux-*-musl \
    && ln -s /opt/agent-tools/node_modules/.bin/claude /usr/local/bin/claude \
    && ln -s /opt/agent-tools/node_modules/.bin/codex /usr/local/bin/codex \
    && npm cache clean --force \
    && check_home="$(mktemp -d)" \
    && test "$(HOME="$check_home" claude --version)" = "${CLAUDE_CODE_VERSION} (Claude Code)" \
    && test "$(HOME="$check_home" codex --version)" = "codex-cli ${CODEX_VERSION}" \
    && rm -rf "$check_home" /root/.npm

COPY agent-home-init /usr/local/sbin/agent-home-init
COPY agent-room-init /usr/local/bin/agent-room-init
RUN chmod 0755 /usr/local/sbin/agent-home-init /usr/local/bin/agent-room-init \
    && echo 'agent ALL=(root) NOPASSWD: /usr/local/sbin/agent-home-init ""' > /etc/sudoers.d/agent-home \
    && chmod 0440 /etc/sudoers.d/agent-home \
    && visudo -cf /etc/sudoers.d/agent-home

# DISABLE_AUTOUPDATER keeps Claude Code at the pinned version.
ENV HOME=/workspace/home \
    LANG=C.UTF-8 \
    DISABLE_AUTOUPDATER=1

USER agent
WORKDIR /workspace/home

# The hotel starts a room as `<image> sleep infinity`, which replaces CMD and
# keeps this ENTRYPOINT.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/agent-room-init"]
CMD ["sleep", "infinity"]
