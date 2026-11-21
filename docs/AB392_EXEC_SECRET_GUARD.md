# Required secrets on a sealed foreground command (AB#392)

Unreleased, opt-in guest protocol. No production flags, image pins, guest rollout
or client publication change. The existing sealed command and secret flags must
both be on. A client must independently trust the new measured guest code before
using it. An older guest rejects the additional request field rather than silently
running an unguarded command.

A historical write receipt does not prove that its file still exists. The sealed
exec plaintext may now include a nonempty `required_secrets` list (at most 64):

```json
{"cmd":["cat","/run/secrets/TOKEN"],"required_secrets":[{"name":"TOKEN","version":1,"envelope_sha256":"<64 lowercase hex>"}]}
```

Names must be unique, versions positive integers, and each entry has exactly
these three fields. Requirements stay inside the encrypted request. The guest
checks its own accepted write for this room incarnation, requires its receipt,
compares version and encrypted-envelope hash, and checks the file's captured
identity, size, timestamps, owner, single link and read-only regular-file mode.
No secret value digest is created or published. No requirement is sent to the
internal room API or copied into an error or outer receipt.

Under the same short lock as writes, the guest checks every requirement and holds
all matching entries before dispatching the command. Any mismatch gives a signed,
encrypted refusal and dispatches no command. No partial holds remain on refusal.
While held, a different write to that name is refused with `sealed_secret_in_use`.
An exact idempotent retry and writes to other names still work. Network waits do
not hold the secrets mutex or serialize unrelated rooms.

Each concurrent command owns a separate hold. Only a completed internal response
with integer exit code, `timed_out: false`, and no cancellation releases that
command's holds. A failed/malformed/missing response, timeout or cancellation
retains them until the room incarnation ends. There is no timer unlock, manual
reset route or automatic retry. Customers must preserve the uncertain command's
identity and inspect its receipts; ending the sandbox loses its ephemeral secrets.
A new write cannot be used to discover whether an uncertain command ran.

This is a foreground-command admission and replacement guard, not proof that the
command consumed the secret, that subprocesses it leaves behind have ended, or
that files survive sandbox deletion. Lifecycle teardown can still end the room.
The backing secret directory and guest OS remain trusted, and containers mount
it read-only. Metadata checks do not protect against malicious guest-root code.
A receipts-front restart changes its binding and loses accepted-write state, so
old requirements fail closed; do not treat restarting as safe recovery for an
unknown command. An operator must preserve the existing room lifecycle rules.

The client must obtain the expected name/version/envelope from independently
verified delivery evidence or its own sealed write, not an API acknowledgement.
This guard establishes no RS policy approval, AWS custody or billing authority.
API create orchestration, verified evidence extraction and CLI integration remain
separate AB#392 work. It is not a complete or enabled secrets-service rollout.

Tests run the real receipts front, cryptography, files and local HTTP with a
synthetic SNP report and fake internal room API. They cover changed/missing files,
unsafe paths/types, wrong versions/envelopes, missing receipt/state, signed sealed
refusals, multi-secret atomicity, concurrent commands, replacement races and
uncertain completion. Live measured-guest and Docker mount acceptance is still
required, together with independent review and full integration CI.
