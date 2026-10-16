# Independent cleanup / prober (staging SNP)

Fred’s canary requires **signed guest absence** after DELETE. Worker DELETE alone is not enough.

## Rules
- Prober key ≠ worker / central caller key  
- Proof must bind boot / slot / operation / binding (`central_guest_gone`)  
- Missing/invalid proof → keep hold + slot claim  
- After valid proof → one settlement/refund + retire slot/lease  

## Status
- **Not configured** on isolated staging yet  
- Need: separate Ed25519 (or existing Cathedral prober) keypair + pin in API startup  
- Owner: staging operator + whoever holds the prober secret (secure channel)

## After guest exists
1. Observe guest gone on host (process/port/QEMU pid)  
2. Emit signed lifecycle receipt tied to original claim  
3. Feed into delete closeout before releasing hold  
