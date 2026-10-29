# Cathedral room image: Liquid AI LFM3-1.7B (Q4_K_M) on llama.cpp, CPU only.
#
# The weights are baked in so the image runs in a sealed room (network
# deny_all) with no download. The llama.cpp build is portable x86-64: every
# CPU backend variant is built as a loadable module and ggml picks the best
# one the CPU reports at start, so it runs on AMD EPYC Genoa under gVisor and
# in an SEV-SNP guest without a build per host.

ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

FROM ${DEBIAN_IMAGE} AS build

# llama.cpp b11960 (v0.8.0) is the first release with LFM3 support.
ARG LLAMA_CPP_TAG=b11960
ARG LLAMA_CPP_COMMIT=8642541b255bfb5dc39cd351a178be09013a55d6
# Liquid AI's GGUF repo at a fixed revision; both files are also pinned by sha256.
ARG LFM3_REVISION=4b423c332fd97961416f2e8b69467758fd27370d
ARG LFM3_GGUF=LFM3-1.7B-Q4_K_M.gguf
ARG LFM3_GGUF_SHA256=3793e1e6e2266919d6e015287221b41100175a98eddaba92e111aed3b05c93c4
ARG LFM3_LICENSE_SHA256=4d28ca14dedc0b3d0fcc2b3339f0e79931faa33874f3d24f522183a8fc70068c

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates cmake curl git \
    && rm -rf /var/lib/apt/lists/*

RUN git init -q /src \
    && git -C /src fetch -q --depth 1 https://github.com/ggml-org/llama.cpp.git "${LLAMA_CPP_COMMIT}" \
    && git -C /src checkout -q FETCH_HEAD \
    && test "$(git -C /src rev-parse HEAD)" = "${LLAMA_CPP_COMMIT}"

# GGML_NATIVE=OFF keeps the build off the CI machine's instruction set.
# GGML_CPU_ALL_VARIANTS builds sse42 through zen4 and needs GGML_BACKEND_DL.
# Set CPU_VARIANTS=OFF only to test the layout on an arm64 workstation, where
# the toolchain here cannot build every arm variant. Published images use ON.
ARG CPU_VARIANTS=ON
RUN cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_RPATH='$ORIGIN' \
      -DGGML_NATIVE=OFF -DGGML_BACKEND_DL=ON -DGGML_CPU_ALL_VARIANTS=${CPU_VARIANTS} \
      -DGGML_OPENMP=ON \
      -DLLAMA_OPENSSL=OFF -DLLAMA_USE_PREBUILT_UI=OFF \
      -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
    && cmake --build /build --target llama-cli -j"$(nproc)"

# The sapphirerapids variant uses Intel AMX. A CPU that reports AMX but does
# not let the process enable it (a container, a sandbox) kills llama-cli with
# SIGILL as soon as that variant wins the pick, so it is not shipped. The
# decode speed of a 1.7B Q4 model is memory bound and does not need AMX; the
# AVX-512 variants below it run on the same hosts. Measured on a GitHub runner
# (Xeon Platinum 8573C): sapphirerapids exits 132, every other variant works.
# A build that lost its CPU variants would still link and then run on the
# slowest fallback, so fail here if the variants a Genoa host picks are absent.
RUN mkdir -p /opt/llama/bin /opt/lfm3/licenses \
    && cp -a /build/bin/llama-cli /build/bin/*.so* /opt/llama/bin/ \
    && cp /src/LICENSE /opt/lfm3/licenses/llama.cpp-LICENSE \
    && rm -f /opt/llama/bin/libggml-cpu-sapphirerapids.so \
    && ls /opt/llama/bin/libggml-cpu*.so \
    && if [ "$(uname -m)" = x86_64 ]; then \
         test -e /opt/llama/bin/libggml-cpu-haswell.so && test -e /opt/llama/bin/libggml-cpu-zen4.so; \
       fi

RUN curl -fsSL --retry 5 -o /opt/lfm3/${LFM3_GGUF} \
      "https://huggingface.co/LiquidAI/LFM3-1.7B-GGUF/resolve/${LFM3_REVISION}/${LFM3_GGUF}" \
    && echo "${LFM3_GGUF_SHA256}  /opt/lfm3/${LFM3_GGUF}" | sha256sum -c - \
    && curl -fsSL --retry 5 -o /opt/lfm3/LICENSE \
      "https://huggingface.co/LiquidAI/LFM3-1.7B-GGUF/resolve/${LFM3_REVISION}/LICENSE" \
    && echo "${LFM3_LICENSE_SHA256}  /opt/lfm3/LICENSE" | sha256sum -c -

FROM ${DEBIAN_IMAGE}

LABEL org.opencontainers.image.title="Cathedral room: LFM3-1.7B" \
      org.opencontainers.image.description="Liquid AI LFM3-1.7B Q4_K_M on llama.cpp b11960, CPU only, weights baked in" \
      org.opencontainers.image.source="https://github.com/cathedralai/cathedral-sandbox" \
      org.opencontainers.image.licenses="LicenseRef-LFM-Open-License-1.0 AND MIT" \
      org.cathedral.lfm3.llama-cpp="b11960" \
      org.cathedral.lfm3.gguf="LFM3-1.7B-Q4_K_M.gguf" \
      org.cathedral.lfm3.gguf-sha256="3793e1e6e2266919d6e015287221b41100175a98eddaba92e111aed3b05c93c4"

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/llama /opt/llama
COPY --from=build /opt/lfm3 /opt/lfm3
COPY NOTICE /opt/lfm3/NOTICE
COPY lfm3-ask /usr/local/bin/lfm3-ask
# The libraries must resolve from /opt/llama/bin alone: the build tree is gone here.
RUN chmod 0755 /usr/local/bin/lfm3-ask \
    && ln -s /opt/llama/bin/llama-cli /usr/local/bin/llama-cli \
    && chmod -R a+rX /opt/llama /opt/lfm3 \
    && ! ldd /opt/llama/bin/llama-cli | grep 'not found'

ENV LFM3_MODEL=/opt/lfm3/LFM3-1.7B-Q4_K_M.gguf
