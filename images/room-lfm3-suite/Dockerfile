# Cathedral sealed-pool image for one LFM3 GGUF model on llama.cpp, CPU only.
#
# Weights are baked in so the sandbox runs with network deny_all. The llama.cpp
# build is portable x86-64 (CPU variants as loadable modules) so it runs on
# AMD EPYC Genoa in an SEV-SNP guest. llama.cpp b11960 is the first release
# with LFM3, video, and d1 support.
#
# Build args pick the model. Pins live in models/<id>.env and are passed
# by .github/workflows/publish-room-lfm3-suite.yml.

ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

FROM ${DEBIAN_IMAGE} AS build

ARG LLAMA_CPP_TAG=b11960
ARG LLAMA_CPP_COMMIT=8642541b255bfb5dc39cd351a178be09013a55d6
ARG GGUF_REPO
ARG GGUF_REVISION
ARG GGUF_FILE
ARG GGUF_SHA256
ARG MMPROJ_FILE
ARG MMPROJ_SHA256
ARG LICENSE_SHA256

RUN test -n "$GGUF_REPO" && test -n "$GGUF_REVISION" && test -n "$GGUF_FILE" && test -n "$GGUF_SHA256" && test -n "$LICENSE_SHA256"

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates cmake curl git \
    && rm -rf /var/lib/apt/lists/*

RUN git init -q /src \
    && git -C /src fetch -q --depth 1 https://github.com/ggml-org/llama.cpp.git "${LLAMA_CPP_COMMIT}" \
    && git -C /src checkout -q FETCH_HEAD \
    && test "$(git -C /src rev-parse HEAD)" = "${LLAMA_CPP_COMMIT}"

# GGML_NATIVE=OFF keeps the build off the CI machine's instruction set.
# GGML_CPU_ALL_VARIANTS builds sse42 through zen4 and needs GGML_BACKEND_DL.
ARG CPU_VARIANTS=ON
RUN cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_RPATH='$ORIGIN' \
      -DGGML_NATIVE=OFF -DGGML_BACKEND_DL=ON -DGGML_CPU_ALL_VARIANTS=${CPU_VARIANTS} \
      -DGGML_OPENMP=ON \
      -DLLAMA_OPENSSL=OFF -DLLAMA_USE_PREBUILT_UI=OFF \
      -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
    && cmake --build /build --target llama-cli llama-server -j"$(nproc)"

RUN mkdir -p /opt/llama/bin /opt/lfm3/licenses \
    && cp -a /build/bin/llama-cli /build/bin/llama-server /build/bin/*.so* /opt/llama/bin/ \
    && cp /src/LICENSE /opt/lfm3/licenses/llama.cpp-LICENSE \
    && rm -f /opt/llama/bin/libggml-cpu-sapphirerapids.so \
    && ls /opt/llama/bin/libggml-cpu*.so \
    && if [ "$(uname -m)" = x86_64 ]; then \
         test -e /opt/llama/bin/libggml-cpu-haswell.so && test -e /opt/llama/bin/libggml-cpu-zen4.so; \
       fi

RUN curl -fsSL --retry 5 -o /opt/lfm3/${GGUF_FILE} \
      "https://huggingface.co/${GGUF_REPO}/resolve/${GGUF_REVISION}/${GGUF_FILE}" \
    && echo "${GGUF_SHA256}  /opt/lfm3/${GGUF_FILE}" | sha256sum -c - \
    && curl -fsSL --retry 5 -o /opt/lfm3/LICENSE \
      "https://huggingface.co/${GGUF_REPO}/resolve/${GGUF_REVISION}/LICENSE" \
    && echo "${LICENSE_SHA256}  /opt/lfm3/LICENSE" | sha256sum -c -

RUN if [ -n "${MMPROJ_FILE}" ]; then \
      test -n "${MMPROJ_SHA256}"; \
      curl -fsSL --retry 5 -o /opt/lfm3/${MMPROJ_FILE} \
        "https://huggingface.co/${GGUF_REPO}/resolve/${GGUF_REVISION}/${MMPROJ_FILE}"; \
      echo "${MMPROJ_SHA256}  /opt/lfm3/${MMPROJ_FILE}" | sha256sum -c -; \
    fi

FROM ${DEBIAN_IMAGE}

ARG GGUF_FILE
ARG MMPROJ_FILE
ARG LFM3_ALIAS
ARG LFM3_REASONING=off

LABEL org.opencontainers.image.title="Cathedral sandbox: ${LFM3_ALIAS}" \
      org.opencontainers.image.description="Liquid AI ${LFM3_ALIAS} on llama.cpp b11960, CPU only, weights baked in" \
      org.opencontainers.image.source="https://github.com/cathedralai/cathedral-sandbox" \
      org.opencontainers.image.licenses="LicenseRef-LFM-Open-License-1.0 AND MIT" \
      org.cathedral.lfm3.llama-cpp="b11960"

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/llama /opt/llama
COPY --from=build /opt/lfm3 /opt/lfm3
COPY NOTICE /opt/lfm3/NOTICE
COPY serve.sh /opt/lfm3/serve.sh
COPY lfm3-ask /usr/local/bin/lfm3-ask

RUN chmod 0755 /usr/local/bin/lfm3-ask /opt/lfm3/serve.sh \
    && ln -s /opt/llama/bin/llama-cli /usr/local/bin/llama-cli \
    && ln -s /opt/llama/bin/llama-server /usr/local/bin/llama-server \
    && chmod -R a+rX /opt/llama /opt/lfm3 \
    && ! ldd /opt/llama/bin/llama-cli | grep 'not found' \
    && ! ldd /opt/llama/bin/llama-server | grep 'not found'

ENV LFM3_MODEL=/opt/lfm3/${GGUF_FILE} \
    LFM3_MMPROJ=/opt/lfm3/${MMPROJ_FILE} \
    LFM3_ALIAS=${LFM3_ALIAS} \
    LFM3_REASONING=${LFM3_REASONING} \
    LFM3_HOST=0.0.0.0 \
    LFM3_PORT=8080 \
    LFM3_THREADS=0

EXPOSE 8080
ENTRYPOINT ["/opt/lfm3/serve.sh"]
