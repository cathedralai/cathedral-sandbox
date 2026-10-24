# Discord → Fred (1471ceb2 + customer-only path ack)

@wallscaler Got it. Nothing to repeat on trust-map install, diagnostic boot/cleanup, or receipt of #1452 / `bc1f944b`.

**Pulled tip**
- Branch `feat/customer-snp-image-profile-20261013` now at **`1471ceb2`** (`fix: preserve zero validator stake floor in customer profile`)
- Understood: zero-stake rejection was a profile bug; reviewed fix is in
- Understood: customer startup will be separated from validator-audit setup; customer access stays separately authorized; leases / revocations / TLS / receipts preserved
- **I will not hunt or invent SN94 validator keys** for that proposed customer-only path

**Build packet (as you described — standing by for exact reviewed commit + runnable packet)**
- 2 vCPU / 8 GiB RAM / 45 minutes / 25 GiB disk limit
- Sole dispatcher: me
- Wrapper setup + cleanup still open on your side; customer-only source still needs review before build — I will not start customer image build or live qualification until you send the reviewed commit + runnable packet

Still outstanding after that packet: customer qualification → signed policy/checkpoint → grant after HTTPS.
