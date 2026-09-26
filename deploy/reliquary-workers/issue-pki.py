#!/usr/bin/env python3
"""Issue separate executor/API mTLS packages into a new private directory."""
from __future__ import annotations

import argparse
import ipaddress
import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--days", type=int, default=14)
    args = parser.parse_args()
    url = urlsplit(args.endpoint)
    host = url.hostname or ""
    if (url.scheme != "https" or not host or url.username or url.password
            or url.path not in ("", "/") or url.query or url.fragment or not 1 <= args.days <= 30):
        parser.error("provide an HTTPS origin and a lifetime of 1 to 30 days")
    try:
        subject_alt = "IP:" + str(ipaddress.ip_address(host))
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
            parser.error("invalid endpoint hostname")
        subject_alt = "DNS:" + host
    binary = shutil.which("openssl")
    if not binary:
        parser.error("OpenSSL is required")
    output = args.output.expanduser().absolute()
    old_mask = os.umask(0o077)
    try:
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
        issuer, executor, api = (output / name for name in ("issuer", "executor", "api"))
        for directory in (issuer, executor, api):
            directory.mkdir(mode=0o700)
        ca_config = "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\nCN=Cathedral exclusive executor CA\n[ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
        (issuer / "ca.cnf").write_text(ca_config)
        def openssl(*arguments):
            subprocess.run([binary, *arguments], cwd=issuer, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, timeout=60)
        openssl("req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", str(args.days),
                "-config", "ca.cnf", "-keyout", "ca.key", "-out", "ca.crt")
        for name, usage, destination in (("server", "serverAuth", executor), ("client", "clientAuth", api)):
            config = (f"[req]\nprompt=no\ndistinguished_name=dn\n[dn]\nCN=Cathedral {name}\n[leaf]\n"
                      f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\n")
            if name == "server":
                config += f"subjectAltName={subject_alt}\n"
            (issuer / f"{name}.cnf").write_text(config)
            openssl("req", "-new", "-newkey", "rsa:3072", "-nodes", "-sha256", "-config", f"{name}.cnf",
                    "-keyout", str(destination / f"{name}.key"), "-out", f"{name}.csr")
            openssl("x509", "-req", "-sha256", "-days", str(args.days), "-in", f"{name}.csr", "-CA", "ca.crt",
                    "-CAkey", "ca.key", "-set_serial", str(secrets.randbits(128) or 1), "-extfile", f"{name}.cnf",
                    "-extensions", "leaf", "-out", str(destination / f"{name}.crt"))
            shutil.copyfile(issuer / "ca.crt", destination / "ca.crt")
        print(f"Executor package: {executor}\nAPI package: {api}\nIssuer custody: {issuer}")
    finally:
        os.umask(old_mask)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.SubprocessError:
        raise SystemExit("PKI generation failed. No credential contents were printed.")
