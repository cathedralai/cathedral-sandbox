# Discord → Fred (customer receipt vs subnet supply)

@wallscaler **Short answer: no — the demoable customer receipt does not become the SN94 supply / weight instrument.**

`cathedral_customer_receipt_v1` is the **customer API** contract (offline-verifiable signed assertions for that job’s execution / billing / teardown). Docs are explicit: it is **not** the current SN94 weight path, and it is **separate** from the subnet assurance receipt in `cathedral/receipt.py`. Entering subnet supply seeded by the compute we have still rides the **capacity / SAT / assurance** lane (and later job-pay only after lifecycle absence receipts + explicit supply-boundary / reward-policy activation). So the live TDX customer receipt **holds as a customer proof today**; it does **not** by itself seed or settle subnet supply. Measured SNP customer receipts (same product shape) still wait on qual + signed policy/checkpoint + grant-after-HTTPS — also still not automatic job-reward activation.
