# AB#732: first-word latency

## What exists

At sandbox commit `7bafb0262b47a2188f6b4ddb9ed68459fca25f04`,
`images/room-lfm3-suite/lfm3-serve` already starts one loopback llama-server
per room, keeps it resident beside the room command, and runs `lfm3-agent --warm`
once at boot. `lfm3-agent` sends each turn to that server. It does not start
another model process per turn. Adding a second resident model would not address
this source path.

This is source evidence, not proof that a particular deployed room retains its
process. Record the image digest, server PID/start time and warm-cache outcome
on the exact rooms used in the next live test before attributing latency to
model reloads.

## Existing measurements and limits

Mr Spock's 21 November run recorded median click-to-first-word times of
2,610 ms for five first turns and 2,566 ms for fifteen later turns on the Audio
image. Its trace separates about 990 ms for exec creation, 250 ms for the first
follow response, and 1,200 ms inside the room before the first delta. These are
owner-recorded measurements, not independently rerun here, and must not simply
be added when their intervals overlap.

The in-room trace starts the event envelope at about 369 ms, the working event
at 459 ms and the first delta at 1,206 ms. That trace alone cannot distinguish
request assembly, prompt evaluation, generation and output filtering. The
current model-residency diagnosis is therefore unproven.

AB#541 says first words within one second of model start; the current leader
request also asks for faster first words in the console. Report both the
click-to-visible-word and model-request-to-first-content intervals. Do not
substitute one for the other or mark the card Done by changing the timer origin.

## This draft change

Batch the stored/sent user-message serialization in one jq invocation, and
set the streaming field while assembling the request instead of reparsing it
with a second jq invocation. This removes two subprocess launches from the
first streamed request and one from later tool rounds. Media bytes still go
only to the sent request; stored conversation retains attachment names.

The model process, prompt, sampling, warm-cache hash inputs, tool behavior,
redaction, event envelope and receipt/transport paths retain their contracts.
The existing model stays room-local. This is a small startup reduction, not
completion of the one-second gate.

## Next implementation and acceptance steps

1. **Chaser:** land this slice after independent review and image tests. Keep
   the image's existing resident server. Use local request captures to compare
   serialized messages, media, history, sampling and tool rounds with main.
2. **Mr Spock:** publish the reviewed image, record its immutable digest, pin
   the intended catalog entries and prefetch only approved test hosts. No
   performance availability claim before that image is live.
3. **Mr Spock, Chaser diagnosis:** use fresh approved test rooms and record,
   separately, click, exec request/response, follow connect, resident server
   PID/start time, health/warm result, request accepted, first model content,
   first receipted delta and first visible word. Do not log prompts, environment
   values or credentials. Include five first turns and at least fifteen warm
   turns across the same tested model and hardware.
4. **Chaser:** optimize the measured remaining segment. If request assembly is
   still material, prototype a room-local persistent request client while
   preserving conversation locking, cancellation, redaction and event receipts.
   If transport dominates, measure API/broker exec/follow stages before proposing
   a persistent receipted turn channel. A raw model endpoint bypass is not an
   acceptable substitute. If model prompt evaluation dominates, validate the
   actual warm-cache restore and prefix reuse rather than weakening sampling
   or tools to improve a benchmark.
5. **Reviewbot and Mr Spock:** rerun signed-in timing, disconnect/resume with no
   output loss, transcript/account isolation, tool/media behavior and offline
   receipt verification. Record both timer origins and cold/warm distributions.
   Leave AB#732 and AB#541 in Review until their acceptance is demonstrated.

No new flags, production writes, image publication, catalog pin, rollout or
Done move is included in this draft. Mr Spock owns publication and live proof;
Chaser owns the client change and subsequent diagnosis.
