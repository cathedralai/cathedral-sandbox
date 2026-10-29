# Cathedral Library image: one environment plus Liquid AI LFM3-1.7B.
#
# BASE_IMAGE is a Library environment image pinned by digest (the OpenEnv
# images today). On top of it go llama.cpp and the LFM3-1.7B Q4_K_M weights,
# so the environment and its model run in the same sandbox with network
# deny_all and nothing to download.
#
# The weights, lfm3-ask, NOTICE and licenses are copied from the published
# room image by digest: the same bytes the LFM3 room runs. That image ships
# llama-cli only, so llama.cpp is built here at the room's pinned commit with
# the room's flags, adding llama-server for the OpenAI-compatible endpoint.
# The build is Debian bookworm (glibc 2.36). The OpenEnv bases are Debian
# trixie (glibc 2.41), which runs bookworm binaries unchanged.

ARG BASE_IMAGE
ARG LFM3_ROOM_IMAGE=ghcr.io/cathedralai/room-lfm3-1.7b@sha256:b1ba8837ea388c8c98720772b0f41af5813d4cebf214637fde20aae58a1ea761
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

FROM ${LFM3_ROOM_IMAGE} AS room

FROM ${DEBIAN_IMAGE} AS build

# Same pin as images/room-lfm3: llama.cpp b11960 (v0.8.0), the first with LFM3.
ARG LLAMA_CPP_COMMIT=8642541b255bfb5dc39cd351a178be09013a55d6

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates cmake git \
    && rm -rf /var/lib/apt/lists/*

RUN git init -q /src \
    && git -C /src fetch -q --depth 1 https://github.com/ggml-org/llama.cpp.git "${LLAMA_CPP_COMMIT}" \
    && git -C /src checkout -q FETCH_HEAD \
    && test "$(git -C /src rev-parse HEAD)" = "${LLAMA_CPP_COMMIT}"

# The room's flags: portable x86-64, every CPU variant as a loadable module,
# no web UI download. LLAMA_USE_PREBUILT_UI=OFF keeps the build offline after
# the source fetch; the server runs with --no-ui anyway.
RUN cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_RPATH='$ORIGIN' \
      -DGGML_NATIVE=OFF -DGGML_BACKEND_DL=ON -DGGML_CPU_ALL_VARIANTS=ON \
      -DGGML_OPENMP=ON \
      -DLLAMA_OPENSSL=OFF -DLLAMA_USE_PREBUILT_UI=OFF \
      -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
    && cmake --build /build --target llama-cli llama-server -j"$(nproc)"

# sapphirerapids (AMX) is dropped for the reason in images/room-lfm3: a CPU
# that reports AMX but does not enable it for the process gets SIGILL.
RUN mkdir -p /opt/llama/bin \
    && cp -a /build/bin/llama-cli /build/bin/llama-server /build/bin/*.so* /opt/llama/bin/ \
    && rm -f /opt/llama/bin/libggml-cpu-sapphirerapids.so \
    && test -e /opt/llama/bin/libggml-cpu-haswell.so \
    && test -e /opt/llama/bin/libggml-cpu-zen4.so

FROM ${BASE_IMAGE}

ARG BASE_IMAGE
# The base image's own command as one sh -c string (the workflow reads it
# from the base image). with-lfm3 starts it when the sandbox command does not.
ARG ENV_CMD

LABEL org.opencontainers.image.title="Cathedral Library environment with LFM3-1.7B" \
      org.opencontainers.image.description="Library environment and Liquid AI LFM3-1.7B Q4_K_M on llama.cpp b11960 in one image, CPU only, weights baked in" \
      org.opencontainers.image.source="https://github.com/cathedralai/cathedral-sandbox" \
      org.opencontainers.image.url="https://github.com/cathedralai/cathedral-sandbox/tree/main/images/library-lfm3" \
      org.opencontainers.image.licenses="BSD-3-Clause AND LicenseRef-LFM-Open-License-1.0 AND MIT" \
      org.cathedral.library.base="${BASE_IMAGE}" \
      org.cathedral.lfm3.llama-cpp="b11960" \
      org.cathedral.lfm3.gguf="LFM3-1.7B-Q4_K_M.gguf" \
      org.cathedral.lfm3.gguf-sha256="3793e1e6e2266919d6e015287221b41100175a98eddaba92e111aed3b05c93c4"

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/llama /opt/llama
COPY --from=room /opt/lfm3 /opt/lfm3
COPY --from=room /usr/local/bin/lfm3-ask /usr/local/bin/lfm3-ask
COPY with-lfm3 /usr/local/bin/with-lfm3

# Fail the build if the libraries do not resolve on this base or the weights
# are not the bytes the room image pins.
RUN chmod 0755 /usr/local/bin/lfm3-ask /usr/local/bin/with-lfm3 \
    && ln -s /opt/llama/bin/llama-cli /usr/local/bin/llama-cli \
    && ln -s /opt/llama/bin/llama-server /usr/local/bin/llama-server \
    && chmod -R a+rX /opt/llama /opt/lfm3 \
    && ! ldd /opt/llama/bin/llama-cli | grep 'not found' \
    && ! ldd /opt/llama/bin/llama-server | grep 'not found' \
    && echo "3793e1e6e2266919d6e015287221b41100175a98eddaba92e111aed3b05c93c4  /opt/lfm3/LFM3-1.7B-Q4_K_M.gguf" | sha256sum -c - \
    && test -s /opt/lfm3/LICENSE && test -s /opt/lfm3/NOTICE \
    && test -n "${ENV_CMD}"

# MODEL_* is the OpenAI-compatible contract the RL Workbench passes to agents.
ENV LFM3_MODEL=/opt/lfm3/LFM3-1.7B-Q4_K_M.gguf \
    MODEL_BASE_URL=http://127.0.0.1:8080/v1 \
    MODEL=lfm3-1.7b \
    MODEL_API_KEY=local \
    LIBRARY_ENV_CMD="${ENV_CMD}"

ENTRYPOINT ["/usr/local/bin/with-lfm3"]
CMD []
