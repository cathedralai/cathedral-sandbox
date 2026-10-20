# Discord → Fred (#1452 admission fix pulled)

@wallscaler Pulled PR [#1452](https://github.com/bigailabs/polariscomputer/pull/1452) tip **`bc1f944b`** (`Admit one signed boot allocation before fixed customer worker startup`). No ZIP.

**Source confirmed locally**
- Branch `feat/customer-snp-image-profile-20261013` @ `bc1f944bfe9512b00e9bc5a2c9892b7f8edf43f8`
- Customer profile tree under `ops/cathedral_snp/image_profiles/` including `customer_admission.py` (absolute deadline / one signed boot allocation)
- Understand this **completes the source fix within #4 only**
- **Customer-image build and live qualification still remain** — not started by me; will not treat diagnostic `8296f243` as customer image

Trust-map install + diagnostic boot/cleanup not repeated. Still waiting on your customer build packet (incl. SN94 validator/stake-policy pins if I don’t already have approved ones — I don’t), then image qual → signed policy/checkpoint → grant after HTTPS.
