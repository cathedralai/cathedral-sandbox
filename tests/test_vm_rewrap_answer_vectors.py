"""AB#1022: the signed re-wrap answer vectors (spec r3 7.5 with the r4 erratum) are what their
generator makes, every refusal comes from the reference verifier, and OpenSSH, an independent
reader and signer, agrees with the fixture wherever the fixture says what OpenSSH does."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

REPO = Path(__file__).resolve().parents[1]
GEN_PATH = REPO / "scripts" / "make_vm_rewrap_answer_vectors.py"
ANSWERS = json.loads((REPO / "tests" / "fixtures" / "vm_rewrap_answer_v2.json").read_text())
SHAPES = json.loads((REPO / "tests" / "fixtures" / "vm_ssh_key_shapes_v1.json").read_text())
CASES = {case["name"]: case for case in ANSWERS["cases"]}
SSH_KEYGEN = shutil.which("ssh-keygen")


def _ssh_keygen() -> str:
    """OpenSSH is the independent check: skipped on a machine without it, required in CI."""
    if SSH_KEYGEN is None:
        if os.environ.get("CI"):
            pytest.fail("CI must run the OpenSSH cross-checks, and ssh-keygen is missing")
        pytest.skip("needs OpenSSH ssh-keygen")
    return SSH_KEYGEN


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = _module("make_vm_rewrap_answer_vectors", GEN_PATH)


def _sig(case):
    return base64.b64decode(json.loads(case["body"])["sig"])


def _armor(blob):
    text = base64.b64encode(blob).decode()
    return ("-----BEGIN SSH SIGNATURE-----\n" + "\n".join(text[i:i + 70] for i in range(0, len(text), 70))
            + "\n-----END SSH SIGNATURE-----\n")


def test_fixtures_are_what_the_generator_makes():
    r = subprocess.run([sys.executable, str(GEN_PATH), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_the_contract_constants():
    assert ANSWERS["answer_schema"] == "cathedral.vm.rewrap-answer/v2"
    assert bytes.fromhex(ANSWERS["message_domain_hex"]) == b"cathedral.vm.rewrap-answer/v2\0"
    assert ANSWERS["namespace"] == "vm-rewrap-answer-v2@cathedral.computer"
    assert (ANSWERS["hash_algorithm"], ANSWERS["answer_max_bytes"], ANSWERS["sig_max_bytes"]) == ("sha512", 4096, 2400)


def test_every_key_type_has_a_valid_answer_and_each_refusal_is_the_reference_verifiers():
    valid = {case["name"] for case in ANSWERS["cases"] if case["refusal"] is None}
    assert valid == {"valid-ed25519", "valid-ecdsa-nistp256", "valid-ecdsa-nistp384", "valid-ecdsa-nistp521",
                     "valid-rsa-2048", "valid-rsa-8192", "valid-sk-ed25519", "valid-sk-ecdsa-nistp256"}
    kinds = {case["identity_ssh_public_key"].split(" ")[0] for case in ANSWERS["cases"] if case["name"] in valid}
    assert kinds == set(gen.KEY_TYPES)
    for case in ANSWERS["cases"]:
        assert gen.refusal(case["body"].encode(), case["identity_ssh_public_key"]) == case["refusal"], case["name"]
    # Each refusal the erratum names is shown by at least one case.
    assert {case["refusal"] for case in ANSWERS["cases"]} >= {
        None, "signature_invalid", "publickey_mismatch", "namespace", "hash_algorithm", "sshsig_version",
        "sshsig_format", "signature_type", "signature_encoding", "sk_user_presence", "answer_schema",
        "sig_too_long", "answer_too_long", "sig_encoding", "reserved"}
    # Erratum 2.6 names these negatives; each has a case.
    assert {"ed25519-trailing-in-signature", "ecdsa-trailing-after-s", "ecdsa-r-equals-n", "ecdsa-s-equals-n",
            "reserved-not-empty", "sshsig-truncated", "sshsig-truncated-in-header"} <= set(CASES)


def test_every_valid_answer_fits_and_the_worst_case_is_rsa_8192():
    for case in ANSWERS["cases"]:
        if case["refusal"] is None:
            body = case["body"].encode()
            assert case["body_bytes"] == len(body) <= 4096
            assert len(_sig(case)) <= 2400
            assert json.dumps(json.loads(body), sort_keys=True, separators=(",", ":")).encode() == body
    largest = max((c for c in ANSWERS["cases"] if c["refusal"] is None), key=lambda c: c["body_bytes"])
    assert (largest["name"], largest["body_bytes"]) == ("valid-rsa-8192", 3173) == \
        (largest["name"], ANSWERS["largest_valid_body_bytes"])
    # The two size refusals sit just past their bounds.
    assert CASES["answer-4097-bytes"]["body_bytes"] == 4097
    assert len(_sig(CASES["sig-2401-bytes"])) == 2401 and CASES["sig-2401-bytes"]["body_bytes"] <= 4096


def test_the_message_is_the_documented_154_bytes():
    for case in ANSWERS["cases"]:
        if "message_hex" not in case:
            continue
        doc = json.loads(case["body"])
        want = (b"cathedral.vm.rewrap-answer/v2\0" + bytes.fromhex(doc["offer_sha256"])
                + base64.b64decode(doc["epk"]) + base64.b64decode(doc["nonce"]) + base64.b64decode(doc["ct"]))
        assert len(want) == 154 and bytes.fromhex(case["message_hex"]) == want, case["name"]


def test_the_seal_inside_is_the_v1_envelope_vector():
    envelope = json.loads((REPO / "tests" / "fixtures" / "vm_rewrap_envelope_v1.json").read_text())["cases"][0]
    doc = json.loads(CASES["valid-ed25519"]["body"])
    assert {k: doc[k] for k in ("ct", "epk", "nonce", "offer_sha256")} == \
        {k: envelope["answer"][k] for k in ("ct", "epk", "nonce", "offer_sha256")}


def test_openssh_reads_each_case_as_the_fixture_says(tmp_path):
    ssh_keygen = _ssh_keygen()
    checked = 0
    for case in ANSWERS["cases"]:
        if case["openssh_accepts"] is None:
            continue
        (tmp_path / "answer.sig").write_text(_armor(_sig(case)))
        r = subprocess.run([ssh_keygen, "-Y", "check-novalidate", "-n", ANSWERS["namespace"], "-s",
                            str(tmp_path / "answer.sig")], input=bytes.fromhex(case["message_hex"]),
                           capture_output=True)
        assert (r.returncode == 0) == case["openssh_accepts"], (case["name"], r.stderr)
        checked += 1
    assert checked >= 30
    # Where OpenSSH accepts what the guest refuses: verify_vm.py rewrap must apply the guest's
    # rules itself, or it prints an answer the guest ignores (r2 review P3-a, P3-b).
    differ = sorted(c["name"] for c in ANSWERS["cases"] if c["openssh_accepts"] and c["refusal"])
    assert differ == ["ecdsa-mpint-not-minimal", "hash-sha256", "other-key", "reserved-not-empty",
                      "rsa-sha2-256", "rsa-short-signature", "sk-no-user-presence"]


@pytest.mark.parametrize("name, key", [
    ("valid-ed25519", lambda: gen.ed25519_key("ed25519")),
    ("valid-rsa-2048", lambda: gen.rsa_key(ANSWERS["test_keys"]["rsa-2048"])),
    ("valid-rsa-8192", lambda: gen.rsa_key(ANSWERS["test_keys"]["rsa-8192"])),
])
def test_ssh_keygen_signs_the_same_bytes(tmp_path, name, key):
    """Ed25519 and RSA PKCS#1 v1.5 are deterministic, so OpenSSH's own signer must give the
    fixture's SSHSIG byte for byte: the generator's encoding is OpenSSH's."""
    ssh_keygen = _ssh_keygen()
    path = tmp_path / "key"
    path.write_bytes(key().private.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
    os.chmod(path, 0o600)
    r = subprocess.run([ssh_keygen, "-Y", "sign", "-n", ANSWERS["namespace"], "-f", str(path)],
                       input=bytes.fromhex(CASES[name]["message_hex"]), capture_output=True)
    assert r.returncode == 0, r.stderr
    armored = b"".join(line for line in r.stdout.splitlines() if not line.startswith(b"-----"))
    assert base64.b64decode(armored) == _sig(CASES[name])


def test_key_shapes_refuse_only_what_the_erratum_names_and_todays_parser_accepts_them_all():
    sys.path.insert(0, str(REPO / "room-kit" / "vm"))
    import vm_measure
    allowed = {c["name"] for c in SHAPES["cases"] if c["refusal"] is None}
    assert {"ed25519", "ecdsa-nistp256", "ecdsa-nistp384", "ecdsa-nistp521", "rsa-2048", "rsa-8192",
            "sk-ed25519", "sk-ecdsa-nistp256", "sk-ed25519-blob-1100"} == allowed
    by_name = {c["name"]: c["refusal"] for c in SHAPES["cases"]}
    assert by_name["sk-ed25519-blob-1101"] == by_name["rsa-16384"] == "key_blob_too_long"
    assert by_name["rsa-1024"] == by_name["rsa-2047"] == by_name["rsa-8193"] == "rsa_modulus_bits"
    for case in SHAPES["cases"]:
        assert gen.key_shape(case["ssh_public_key"]) == case["refusal"], case["name"]
        # The shape is a create-only rule (r2 review P2-a): the identity parser that start,
        # rebundle, verify and the init use keeps accepting every one of these keys.
        assert vm_measure.ssh_public_key(case["ssh_public_key"]) == case["ssh_public_key"], case["name"]
    # Every valid answer's identity key is an allowed shape.
    for case in ANSWERS["cases"]:
        if case["refusal"] is None:
            assert gen.key_shape(case["identity_ssh_public_key"]) is None, case["name"]


def test_the_fixtures_hold_no_private_key_block():
    for path in ("vm_rewrap_answer_v2.json", "vm_ssh_key_shapes_v1.json"):
        text = (REPO / "tests" / "fixtures" / path).read_text()
        assert "PRIVATE KEY" not in text and "BEGIN OPENSSH" not in text


def test_a_valid_answer_with_any_bit_of_its_message_flipped_is_refused():
    case = CASES["valid-sk-ecdsa-nistp256"]
    doc = json.loads(case["body"])
    for field in ("epk", "nonce", "ct"):
        raw = bytearray(base64.b64decode(doc[field]))
        for i in range(len(raw)):
            raw[i] ^= 0x80
            changed = dict(doc, **{field: base64.b64encode(bytes(raw)).decode()})
            body = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode()
            assert gen.refusal(body, case["identity_ssh_public_key"]) == "signature_invalid", (field, i)
            raw[i] ^= 0x80
    other = dict(doc, offer_sha256=hashlib.sha256(b"x").hexdigest())
    assert gen.refusal(json.dumps(other, sort_keys=True, separators=(",", ":")).encode(),
                       case["identity_ssh_public_key"]) == "signature_invalid"


def test_the_on_curve_check_agrees_with_cryptography():
    """key_shape's curve equation and constants against an independent implementation: every
    ECDSA point in the shape vectors is on its curve exactly when cryptography loads it."""
    from cryptography.hazmat.primitives.asymmetric import ec
    curves = {"nistp256": ec.SECP256R1(), "nistp384": ec.SECP384R1(), "nistp521": ec.SECP521R1()}
    seen = 0
    for case in SHAPES["cases"]:
        r = gen.Reader(base64.b64decode(case["ssh_public_key"].split(" ")[1]), "x")
        kind = r.string().decode()
        if "ecdsa" not in kind:
            continue
        curve, point = r.string().decode(), r.string()
        if curve not in curves or len(point) != gen.CURVES[curve][2] or point[0] != 4:
            continue
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(curves[curve], point)
            loads = True
        except ValueError:
            loads = False
        assert gen.on_curve(curve, point) is loads, case["name"]
        assert (case["refusal"] is None) is loads, case["name"]
        seen += 1
    assert seen >= 5  # the four valid ECDSA keys and the point off the curve
