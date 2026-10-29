# Cathedral sealed-pool image for LFM3-1.7B-Base. No public GGUF; BF16
# safetensors on CPU via transformers. Last in the LFM rollout. Slow on CPU.

ARG DEBIAN_IMAGE=python:3.12-slim-bookworm@sha256:623674a14ef93d052bb9b0de4dbf5f28eb578a35263838941cc8aa43213c1487

FROM ${DEBIAN_IMAGE}

ARG HF_REPO=LiquidAI/LFM3-1.7B-Base
ARG HF_REVISION=545fc8f4c7b5fa9f405105274cd29c4f8f44b526
ARG WEIGHTS_SHA256=61a3f541d65b03a2180d08964bf0d55e349463a2706032814d455ae046bc8b59
ARG LICENSE_SHA256=4d28ca14dedc0b3d0fcc2b3339f0e79931faa33874f3d24f522183a8fc70068c

LABEL org.opencontainers.image.title="Cathedral sandbox: LFM3-1.7B-Base" \
      org.opencontainers.image.description="Liquid AI LFM3-1.7B-Base BF16 on transformers, CPU only" \
      org.opencontainers.image.source="https://github.com/cathedralai/cathedral-sandbox" \
      org.opencontainers.image.licenses="LicenseRef-LFM-Open-License-1.0 AND Apache-2.0"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
      --index-url https://download.pytorch.org/whl/cpu \
      torch \
    && pip install --no-cache-dir "transformers>=4.51" huggingface_hub

RUN python -c "from huggingface_hub import snapshot_download; snapshot_download('${HF_REPO}', revision='${HF_REVISION}', local_dir='/models')" \
    && echo "${WEIGHTS_SHA256}  /models/model.safetensors" | sha256sum -c - \
    && echo "${LICENSE_SHA256}  /models/LICENSE" | sha256sum -c -

COPY serve.py /opt/lfm3/serve.py
COPY NOTICE /opt/lfm3/NOTICE
RUN chmod 0755 /opt/lfm3/serve.py \
    && cp /models/LICENSE /opt/lfm3/LICENSE

EXPOSE 8080
ENV LFM3_HF_REPO=/models \
    LFM3_HOST=0.0.0.0 \
    LFM3_PORT=8080 \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1

ENTRYPOINT ["python", "/opt/lfm3/serve.py"]
