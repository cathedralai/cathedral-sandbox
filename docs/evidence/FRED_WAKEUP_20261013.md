# Fred — staging status (wake-up)

## Done
- Phase 0 takeover; Cherry SSH confirmed; 3 existing guests untouched  
- Image on disk; hashes match addendum (`a7ad573b…`)  
- Staging key **expiry extended** to 2026-10-15T05:40:31Z (ID `b30b7437-…`) — **need the secret**  
- Isolated SQL broker **claim PROVED** for `systrap-snp-customer-v1`  
- Inventory seeded (`cathedral-snp-staging-cherry-001` / slot-001)  
- Boot draft for **new** guest on free ports `:2226` / `:8444` — **not launched**  
- Branch: `bigailabs/polariscomputer` `feat/snp-customer-staging-broker`

## Blocked — need from you
1. **Staging `cat_sk` value** for key `b30b7437-7d2d-53fc-b7b4-97f4f47f9081` (secure channel)  
2. **These 6 Polaris files** from `acaa2961` / `66deb72e` (ZIP only has tiny deltas):
   - `polaris/db/snp_runtime.py`
   - `polaris/providers/broker_runtime_connector_proposal.py`
   - `polaris/providers/snp_customer_adapter_proposal.py`
   - `polaris/providers/snp_postgres_journal_proposal.py`
   - `polaris/providers/snp_selected_runtime_proposal.py`
   - `tests/test_snp_customer_adapter_proposal.py`
3. Image/policy accept to boot the new guest  
4. 15-min central grant **after** guest HTTPS is up  

## Not using
- Prod TDX key  
- Railway `acaa2961` (still cold / compute disabled) until deploy  

## Next after (1)+(2)
Wire API join → boot new guest → canary: create → exec → native-evidence → usage → delete → guest-gone  
