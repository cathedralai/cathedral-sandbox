"""Example Affine-shaped verify artifact for pin tests (not SN120 production)."""


def verify(payload: bytes, inputs: dict) -> dict:
    prefix = str(inputs.get("prefix", "AFFINE")).encode("ascii")
    if not payload.startswith(prefix + b":"):
        return {"passed": False, "reason": "prefix_mismatch", "score": 0}
    try:
        score = int(payload.split(b":", 1)[1].strip())
    except ValueError:
        return {"passed": False, "reason": "score_not_int", "score": 0}
    if 0 <= score <= 100:
        return {"passed": True, "reason": "ok", "score": score}
    return {"passed": False, "reason": "score_out_of_range", "score": score}
