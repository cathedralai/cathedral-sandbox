# Cathedral room images: the Liquid AI LFM3 suite on llama.cpp, CPU only.
#
# One template for every model in the suite; the publish workflow passes each
# model's pins. The weights are baked in, so a room runs sealed (network
# deny_all) with nothing to download. lfm3-serve starts llama-server on
# 127.0.0.1:8080 with the contract of the LFM3-1.7B images:
# MODEL_BASE_URL=http://127.0.0.1:8080/v1, MODEL, MODEL_API_KEY=local.
#
# WEIGHTS=download takes Liquid AI's own GGUF and projector by revision and
# sha256. WEIGHTS=convert builds the GGUF from Liquid AI's safetensors with
# llama.cpp's converter at the same commit and quantizes it, for a model with
# no official GGUF (LFM3-1.7B-Base).

ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
ARG WEIGHTS=download

FROM ${DEBIAN_IMAGE} AS llama

# Same pin as the LFM3-1.7B room: llama.cpp b11960 (v0.8.0), the first
# release with LFM3, its vision and audio projectors and the d1 endpoint.
ARG LLAMA_CPP_COMMIT=8642541b255bfb5dc39cd351a178be09013a55d6

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates cmake git \
    && rm -rf /var/lib/apt/lists/*

RUN git init -q /src \
    && git -C /src fetch -q --depth 1 https://github.com/ggml-org/llama.cpp.git "${LLAMA_CPP_COMMIT}" \
    && git -C /src checkout -q FETCH_HEAD \
    && test "$(git -C /src rev-parse HEAD)" = "${LLAMA_CPP_COMMIT}"

# The room's flags: portable x86-64, every CPU variant as a loadable module,
# no web UI download.
RUN cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_RPATH='$ORIGIN' \
      -DGGML_NATIVE=OFF -DGGML_BACKEND_DL=ON -DGGML_CPU_ALL_VARIANTS=ON \
      -DGGML_OPENMP=ON \
      -DLLAMA_OPENSSL=OFF -DLLAMA_USE_PREBUILT_UI=OFF \
      -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
    && cmake --build /build --target llama-cli llama-server llama-quantize -j"$(nproc)"

# sapphirerapids (AMX) is dropped for the reason in the LFM3-1.7B room: a CPU
# that reports AMX but does not enable it for the process gets SIGILL.
RUN mkdir -p /opt/llama/bin /opt/lfm3/licenses \
    && cp -a /build/bin/llama-cli /build/bin/llama-server /build/bin/*.so* /opt/llama/bin/ \
    && cp /src/LICENSE /opt/lfm3/licenses/llama.cpp-LICENSE \
    && rm -f /opt/llama/bin/libggml-cpu-sapphirerapids.so \
    && test -e /opt/llama/bin/libggml-cpu-haswell.so \
    && test -e /opt/llama/bin/libggml-cpu-zen4.so

# Liquid AI's GGUF files at a fixed revision, each pinned by sha256.
FROM ${DEBIAN_IMAGE} AS weights-download
ARG HF_REPO
ARG HF_REVISION
ARG GGUF
ARG GGUF_SHA256
ARG MMPROJ=""
ARG MMPROJ_SHA256=""
ARG LICENSE_SHA256

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    [ -n "${GGUF_SHA256}" ]; \
    fetch() { \
      curl -fsSL --retry 5 -o "/opt/lfm3/$1" "https://huggingface.co/${HF_REPO}/resolve/${HF_REVISION}/$1"; \
      echo "$2  /opt/lfm3/$1" | sha256sum -c -; \
    }; \
    mkdir -p /opt/lfm3; \
    fetch "${GGUF}" "${GGUF_SHA256}"; \
    if [ -n "${MMPROJ}" ]; then fetch "${MMPROJ}" "${MMPROJ_SHA256}"; fi; \
    fetch LICENSE "${LICENSE_SHA256}"

# Liquid AI's safetensors at a fixed revision, converted to GGUF with the
# converter of the pinned llama.cpp commit, then quantized. CONVERT_FILES is
# "name:sha256 ..." for every file the converter reads.
FROM ${PYTHON_IMAGE} AS weights-convert
ARG HF_REPO
ARG HF_REVISION
ARG GGUF
ARG CONVERT_FILES
ARG LICENSE_SHA256
ARG QUANT=Q4_K_M

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=llama /src /src
COPY --from=llama /build/bin /opt/quantize
# The CI runner reports AMX, so the AMX variant would crash llama-quantize.
RUN rm -f /opt/quantize/libggml-cpu-sapphirerapids.so

# The checkpoint was saved with transformers 5.12.1; its tokenizer class
# (TokenizersBackend) is not in the 4.x line llama.cpp's requirements pin.
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.11.0 \
    && pip install --no-cache-dir transformers==5.12.1 "numpy~=2.2.6" "sentencepiece>=0.1.98,<0.3.0" protobuf /src/gguf-py

RUN set -eu; \
    mkdir -p /hf /opt/lfm3; \
    for entry in ${CONVERT_FILES} LICENSE:${LICENSE_SHA256}; do \
      name=${entry%%:*}; sum=${entry#*:}; \
      curl -fsSL --retry 5 -o "/hf/$name" "https://huggingface.co/${HF_REPO}/resolve/${HF_REVISION}/$name"; \
      echo "$sum  /hf/$name" | sha256sum -c -; \
    done; \
    python /src/convert_hf_to_gguf.py /hf --outtype bf16 --outfile /tmp/model-bf16.gguf; \
    /opt/quantize/llama-quantize /tmp/model-bf16.gguf "/opt/lfm3/${GGUF}" "${QUANT}" "$(nproc)"; \
    cp /hf/LICENSE /opt/lfm3/LICENSE; \
    rm -rf /hf /tmp/model-bf16.gguf

FROM weights-${WEIGHTS} AS weights

FROM ${DEBIAN_IMAGE}

ARG WEIGHTS
ARG MODEL_NAME
ARG DISPLAY_NAME
ARG LFM3_KIND=chat
ARG LFM3_CHECKS
ARG HF_REPO
ARG HF_REVISION
ARG GGUF
ARG GGUF_SHA256=""
ARG MMPROJ=""
ARG QUANT=Q4_K_M

LABEL org.opencontainers.image.title="Cathedral room: ${DISPLAY_NAME}" \
      org.opencontainers.image.description="Liquid AI ${DISPLAY_NAME} on llama.cpp b11960, CPU only, weights baked in" \
      org.opencontainers.image.source="https://github.com/cathedralai/cathedral-sandbox" \
      org.opencontainers.image.url="https://github.com/cathedralai/cathedral-sandbox/tree/main/images/room-lfm3-suite" \
      org.opencontainers.image.licenses="LicenseRef-LFM-Open-License-1.0 AND MIT" \
      org.cathedral.lfm3.llama-cpp="b11960" \
      org.cathedral.lfm3.model="${MODEL_NAME}" \
      org.cathedral.lfm3.hf-repo="${HF_REPO}" \
      org.cathedral.lfm3.hf-revision="${HF_REVISION}" \
      org.cathedral.lfm3.gguf="${GGUF}" \
      org.cathedral.lfm3.gguf-sha256="${GGUF_SHA256}" \
      org.cathedral.lfm3.mmproj="${MMPROJ}" \
      org.cathedral.lfm3.weights="${WEIGHTS}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl jq libgomp1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=llama /opt/llama /opt/llama
COPY --from=llama /opt/lfm3/licenses /opt/lfm3/licenses
COPY --from=weights /opt/lfm3 /opt/lfm3
COPY NOTICE.in /tmp/NOTICE.in
COPY test /opt/lfm3/test
COPY lfm3-serve lfm3-ask lfm3-decide lfm3-selftest /usr/local/bin/

# NOTICE names this model and says whether the weights are Liquid AI's files
# unmodified or converted here (LFM Open License 4(b)). SHA256SUMS records
# the bytes in the image, including a converted GGUF.
RUN set -eu; \
    if [ "${WEIGHTS}" = convert ]; then \
      changes="Cathedral converted the safetensors weights to GGUF with llama.cpp's convert_hf_to_gguf.py and quantized them to ${QUANT} with llama-quantize (llama.cpp b11960). Nothing else was changed."; \
    else \
      changes="The GGUF files are redistributed unmodified."; \
    fi; \
    sed -e "s|@DISPLAY_NAME@|${DISPLAY_NAME}|g" -e "s|@HF_REPO@|${HF_REPO}|g" \
        -e "s|@HF_REVISION@|${HF_REVISION}|g" -e "s|@CHANGES@|${changes}|g" \
        /tmp/NOTICE.in > /opt/lfm3/NOTICE; \
    rm /tmp/NOTICE.in; \
    ! grep -q '@[A-Z_]*@' /opt/lfm3/NOTICE; \
    chmod 0755 /usr/local/bin/lfm3-serve /usr/local/bin/lfm3-ask /usr/local/bin/lfm3-decide /usr/local/bin/lfm3-selftest; \
    ln -s /opt/llama/bin/llama-cli /usr/local/bin/llama-cli; \
    ln -s /opt/llama/bin/llama-server /usr/local/bin/llama-server; \
    chmod -R a+rX /opt/llama /opt/lfm3; \
    ! ldd /opt/llama/bin/llama-server | grep 'not found'; \
    ! ldd /opt/llama/bin/llama-cli | grep 'not found'; \
    test -s "/opt/lfm3/${GGUF}" && test -s /opt/lfm3/LICENSE; \
    if [ -n "${MMPROJ}" ]; then test -s "/opt/lfm3/${MMPROJ}"; fi; \
    if [ -n "${GGUF_SHA256}" ]; then echo "${GGUF_SHA256}  /opt/lfm3/${GGUF}" | sha256sum -c -; fi; \
    test -n "${MODEL_NAME}" && test -n "${LFM3_CHECKS}"; \
    case "${LFM3_KIND}" in chat | decision) ;; *) exit 1 ;; esac; \
    cd /opt/lfm3 && sha256sum *.gguf LICENSE test/* > SHA256SUMS

# MODEL_* is the OpenAI-compatible contract agents read to find their model.
ENV LFM3_MODEL=/opt/lfm3/${GGUF} \
    LFM3_MMPROJ=${MMPROJ:+/opt/lfm3/${MMPROJ}} \
    LFM3_KIND=${LFM3_KIND} \
    LFM3_CHECKS=${LFM3_CHECKS} \
    MODEL_BASE_URL=http://127.0.0.1:8080/v1 \
    MODEL=${MODEL_NAME} \
    MODEL_API_KEY=local

ENTRYPOINT ["/usr/local/bin/lfm3-serve"]
CMD []
