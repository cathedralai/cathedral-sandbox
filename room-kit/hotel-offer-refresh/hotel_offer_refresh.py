#!/usr/bin/env python3
"""Re-offer a miner hotel after each new boot (AB#822 R1).

A guest reboot or a receipts restart gives the hotel a new binding. Polaris
then refuses the old offer (binding_differs_from_offer), the broker drains and
rejoins the hotel, and the rejoin needs a new offer signed by the hotkey. A
systemd timer runs this every 5 minutes on the hotel's host:

  1. refuse a hotkey file readable by group or others (as hotel_offer.py does);
  2. GET /room/attestation from the guest address and check it with
     hotel_offer.py (binding digest, REPORT_DATA, chip, TLS key that answered);
  3. compare binding_sha256 with the state file (the last offer that was
     posted); the same binding posts nothing;
  4. on a change log "binding_changed", sign an offer with hotel_offer.py,
     sequence = current unix seconds, and POST it; a refused or failed POST is
     retried with backoff, each try with a fresh sequence; on success log
     "offer_posted" and write the state file.

The sequence is the clock, not a counter, so a lost state file still posts a
sequence newer than any earlier offer (never offer_sequence_not_newer).

Config: an env file (paths and URLs only, never key material), see
hotel-offer-refresh.env.example. Nothing here prints the seed; hotel_offer.py
error messages never carry key material either.

Exit codes: 0 no change or offer posted; 1 bad config or hotkey file refused;
2 attestation unavailable or failed a check (guest down, booting, not the
guest); 3 every POST was refused or failed.
"""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

EXIT_OK, EXIT_CONFIG, EXIT_ATTESTATION, EXIT_POST = 0, 1, 2, 3
DEFAULT_HOTEL_OFFER = Path(__file__).resolve().parents[1] / "hotel_offer.py"


def load_hotel_offer(path: str | os.PathLike = DEFAULT_HOTEL_OFFER):
    spec = importlib.util.spec_from_file_location("hotel_offer", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def log(event: str, **fields) -> None:
    """One journal line per event: '<event> key=value ...'."""
    print(" ".join([event, *(f"{k}={v}" for k, v in fields.items())]), flush=True)


class Config:
    REQUIRED = ("HOTEL_OFFER_ORIGIN", "HOTEL_OFFER_ATTESTATION_URL", "HOTEL_OFFER_POST_URL",
                "HOTEL_OFFER_HOTKEY_FILE", "HOTEL_OFFER_STATE_FILE")

    def __init__(self, env) -> None:
        missing = [k for k in self.REQUIRED if not env.get(k)]
        if missing:
            raise ValueError(f"missing {', '.join(missing)} in the env file")
        self.origin = env["HOTEL_OFFER_ORIGIN"]
        self.attestation_url = env["HOTEL_OFFER_ATTESTATION_URL"]
        self.post_url = env["HOTEL_OFFER_POST_URL"]
        self.hotkey_file = env["HOTEL_OFFER_HOTKEY_FILE"]
        self.state_file = Path(env["HOTEL_OFFER_STATE_FILE"])
        self.network = env.get("HOTEL_OFFER_NETWORK", "finney")
        self.netuid = int(env.get("HOTEL_OFFER_NETUID", "94"))
        self.attempts = max(1, int(env.get("HOTEL_OFFER_POST_ATTEMPTS", "4")))
        self.backoff = float(env.get("HOTEL_OFFER_BACKOFF_SECONDS", "15"))


def check_hotkey_mode(path: str) -> None:
    """Fail early, every run, on the rule hotel_offer.load_seed enforces when it reads the seed."""
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError("hotkey file must be a regular file not readable by group or others (chmod 600)")


def read_state(path: Path) -> dict:
    try:
        state = json.loads(path.read_text())
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def write_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, sort_keys=True) + "\n")
    os.replace(tmp, path)


def refresh(cfg: Config, ho, *, clock=time.time, sleep=time.sleep) -> int:
    try:
        check_hotkey_mode(cfg.hotkey_file)
    except OSError as exc:  # names the path, never the contents
        log("hotkey_file_refused", reason=json.dumps(str(exc)))
        return EXIT_CONFIG

    try:
        origin = ho.check_origin(cfg.origin)
        attestation, peer = ho.fetch_attestation(ho.check_fetch_url(cfg.attestation_url))
        binding_sha256, machine, _ = ho.check_attestation(attestation, peer_spki=peer)
    except ho.OfferError as exc:
        log("attestation_unavailable", reason=json.dumps(str(exc)))
        return EXIT_ATTESTATION

    state = read_state(cfg.state_file)
    last = state.get("binding_sha256")
    if last == binding_sha256:
        return EXIT_OK
    log("binding_changed", old=last or "none", new=binding_sha256, machine=machine)

    try:
        seed = ho.load_seed(cfg.hotkey_file)
    except (ho.OfferError, OSError) as exc:
        log("hotkey_file_refused", reason=json.dumps(str(exc)))
        return EXIT_CONFIG

    previous = state.get("sequence") if isinstance(state.get("sequence"), int) else -1
    for attempt in range(1, cfg.attempts + 1):
        now = int(clock())
        sequence = max(now, previous + 1)
        try:
            offer = ho.build_offer(seed=seed, network=cfg.network, netuid=cfg.netuid, origin=origin,
                                   binding_sha256=binding_sha256, machine=machine, sequence=sequence,
                                   issued_at=datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                   withdraw=False)
        except ho.OfferError as exc:  # py-sr25519-bindings missing
            log("config_refused", reason=json.dumps(str(exc)))
            return EXIT_CONFIG
        previous = sequence
        try:
            answer = ho.post(cfg.post_url, offer)
        except ho.OfferError as exc:
            log("offer_refused", attempt=attempt, of=cfg.attempts, sequence=sequence, reason=json.dumps(str(exc)))
            if attempt < cfg.attempts:
                sleep(cfg.backoff * 2 ** (attempt - 1))
            continue
        write_state(cfg.state_file, {"binding_sha256": binding_sha256, "sequence": sequence,
                                     "offer_id": offer["offer_id"], "machine_id": machine, "posted_at": now})
        log("offer_posted", binding=binding_sha256, sequence=sequence, offer_id=offer["offer_id"],
            answer=json.dumps(answer[:200]))
        return EXIT_OK
    log("offer_failed", binding=binding_sha256, attempts=cfg.attempts)
    return EXIT_POST


def main(argv=None) -> int:
    try:
        cfg = Config(os.environ)
        ho = load_hotel_offer(os.environ.get("HOTEL_OFFER_PY") or DEFAULT_HOTEL_OFFER)
    except (ValueError, RuntimeError, OSError) as exc:
        log("config_refused", reason=json.dumps(str(exc)))
        return EXIT_CONFIG
    return refresh(cfg, ho)


if __name__ == "__main__":
    sys.exit(main())
