"""Synthetic Turin trust chain and CRL. Keys sign only test reports."""
from datetime import datetime, timedelta, timezone
from functools import lru_cache
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

NOW = datetime.now(timezone.utc).replace(microsecond=0)
CHIP = '0123456789abcdef' + '00' * 56
CPU = '1a:02:00'
TCB = bytes([1, 3, 3, 8, 0, 0, 0, 118])
FLOOR = 'turin:fmc=1,bl=3,tee=3,snp=8,ucode=118'
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


@lru_cache(None)
def keys():
    return rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 2048), ec.generate_private_key(ec.SECP384R1())


def cert(subject, issuer, public, signer, serial, extensions=(), validity=None):
    before, after = validity or (NOW - timedelta(days=1), NOW + timedelta(days=365))
    builder = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer))
               .public_key(public).serial_number(serial).not_valid_before(before).not_valid_after(after))
    for oid, raw in extensions:
        builder = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), raw), False)
    return builder.sign(signer, hashes.SHA384(), rsa_padding=PSS)


def make_crl(ark, *, revoked=False, stale=False, future=False, bad_signature=False,
             wrong_issuer=False, scoped=False, delta=False, missing_next=False):
    ark_key, ask_key, _ = keys()
    before = NOW + timedelta(days=1) if future else NOW - timedelta(hours=1)
    after = NOW + timedelta(days=2)
    if stale:
        before, after = NOW - timedelta(days=2), NOW - timedelta(days=1)
    builder = (x509.CertificateRevocationListBuilder().issuer_name(name('wrong') if wrong_issuer else ark.subject)
               .last_update(before))
    if not missing_next:
        builder = builder.next_update(after)
    if revoked:
        builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(2)
                                                  .revocation_date(NOW - timedelta(hours=2)).build())
    if scoped:
        builder = builder.add_extension(x509.IssuingDistributionPoint(
            full_name=None, relative_name=None, only_contains_user_certs=False, only_contains_ca_certs=True,
            only_some_reasons=None, indirect_crl=False, only_contains_attribute_certs=False), critical=True)
    if delta:
        builder = builder.add_extension(x509.DeltaCRLIndicator(1), critical=True)
    return builder.sign(ask_key if bad_signature else ark_key, hashes.SHA384(), rsa_padding=PSS)


def sign(report, cache, *, validity=None, crl_options=None):
    ark_key, ask_key, vcek_key = keys()
    validity = validity or {}
    ark = cert('ARK-Turin', 'ARK-Turin', ark_key.public_key(), ark_key, 1, validity=validity.get('ARK'))
    ask = cert('SEV-Turin', 'ARK-Turin', ask_key.public_key(), ark_key, 2, validity=validity.get('ASK'))
    tcb = report[0x180:0x188]
    exts = [('1.3.6.1.4.1.3704.1.4', report[0x1a0:0x1a8])]
    for suffix, offset in ((1, 1), (2, 2), (3, 3), (8, 7), (9, 0)):
        # DER nonnegative INTEGER, including values >=128.
        n = tcb[offset]
        raw = bytes([2, 2, 0, n]) if n >= 128 else bytes([2, 1, n])
        exts.append((f'1.3.6.1.4.1.3704.1.3.{suffix}', raw))
    vcek = cert('VCEK', 'SEV-Turin', vcek_key.public_key(), ask_key, 3, exts, validity.get('VCEK'))
    raw = bytearray(report)
    r, s = decode_dss_signature(vcek_key.sign(bytes(raw[:0x2a0]), ec.ECDSA(hashes.SHA384())))
    raw[0x2a0:0x2e8], raw[0x2e8:0x330] = r.to_bytes(72, 'little'), s.to_bytes(72, 'little')
    cache.mkdir(parents=True, exist_ok=True)
    (cache / 'Turin-cert_chain.pem').write_bytes(ask.public_bytes(serialization.Encoding.PEM) + ark.public_bytes(serialization.Encoding.PEM))
    (cache / f'vcek-{report[0x1a0:0x1a8].hex()}-{tcb.hex()}.der').write_bytes(vcek.public_bytes(serialization.Encoding.DER))
    (cache / 'ark.crl').write_bytes(make_crl(ark, **(crl_options or {})).public_bytes(serialization.Encoding.DER))
    return bytes(raw)


def cache_pin(cache):
    chain = x509.load_pem_x509_certificates((cache / 'Turin-cert_chain.pem').read_bytes())
    return hashlib.sha256(chain[1].public_bytes(serialization.Encoding.DER)).hexdigest()
