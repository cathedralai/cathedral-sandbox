#!/usr/bin/env bash
# smoke-tools.sh IMAGE_REF: the tools the sealed benchmark needs (AB#763) run
# in the image the way a sealed room runs it (network none, 2 CPUs, 8 GiB).
# llama-bench times the baked-in model, llama-server answers /health on
# loopback via curl, and python runs.
set -euo pipefail

image_ref="${1:?usage: smoke-tools.sh IMAGE_REF}"
name="lfm3-smoke-$$"

docker run -d --name "$name" --network none --cpus 2 --memory 8g "$image_ref" sleep infinity >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

docker exec "$name" python -c 'import json, sys; print("python", sys.version.split()[0])'
docker exec "$name" curl --version | head -n 1

bench="$(docker exec "$name" sh -c 'llama-bench -m "$LFM3_MODEL" -t 2 -p 16 -n 8 -r 1 -o csv')"
printf '%s\n' "$bench"
# One prompt row and one decode row, each with a positive avg_ts.
python3 - "$bench" <<'PY'
import csv, io, sys
rows = list(csv.DictReader(io.StringIO(sys.argv[1])))
kinds = {(int(r["n_prompt"]) > 0, int(r["n_gen"]) > 0) for r in rows if float(r["avg_ts"]) > 0}
assert (True, False) in kinds and (False, True) in kinds, rows
PY

docker exec -d "$name" sh -c 'llama-server -m "$LFM3_MODEL" --host 127.0.0.1 --port 8080 -t 2 -c 2048 >/tmp/server.log 2>&1'
for _ in $(seq 1 120); do
  if docker exec "$name" curl -fsS http://127.0.0.1:8080/health; then
    echo
    exit 0
  fi
  sleep 1
done
docker exec "$name" cat /tmp/server.log >&2 || true
echo "llama-server did not answer /health" >&2
exit 1
