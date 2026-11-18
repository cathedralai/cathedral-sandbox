# Roll step: prefetch the desktop image (AB#670)

A re-seal roll empties the image store on the rolled hotel. On 13 Nov the
pre-load pf_2b2925d3d6f76e6c pulled the desktop image in 33 s (c46-sealed-2),
68 s (nc-sealed-2) and 71 s (nc-sealed-3), although all three held it on
11 Nov. The first customer desktop on a rolled hotel then pays 48 to 81 s
instead of 14 to 17 s. This step removes that cost. It is manual and runs
after the last `roll.sh apply` of a roll, once the hotel is undrained and the
const guard is GREEN.

Why a runbook step and not the catalog: `broker/catalog.go` `catalogTemplates`
has no desktop entry, so `prewarm_catalog` (AB#532) does not pull it. Adding
one changes the catalog listing and `broker/catalog.digest` (AB#546 gate) and
makes every hotel pull all catalog images. Not done here.

## Pin

Image: `ghcr.io/cathedralai/cathedral-desktop@sha256:e128515e1cf4c7648a50412832a1b5418ac002da4a2a5b118adf75d643840014`

It must equal Railway Polaris Cloud / production `CATHEDRAL_DESKTOP_IMAGE`
and the digest on the live catalogue Desktop entry. Check before the step.
Note: cathedral/start_commands.json:5 carries a different digest (`...ac002da4a2b5b118...`, no manifest on ghcr, 404 on 16 Nov). The pin above answers 200 on an anonymous manifest fetch. Do not copy the digest from that file.

Keep the pin unless a new image is published from an `image-v*` tag on main;
then update this file in the same PR that changes the pin.

## Steps

1. Pin check: the three digests above match. If not, stop and ask the pin owner (AB#699).
2. Prefetch as guest `cathedral-customer-sealed`. This is the guest that
   places customer rooms, and ownership of the pulled image ids is granted
   to it (AB#650). Sign the request with that guest's credentials, not the
   operator key.

       POST $BROKER/v1/images/prefetch
       {"images": ["ghcr.io/cathedralai/cathedral-desktop@sha256:e128515e1cf4c7648a50412832a1b5418ac002da4a2a5b118adf75d643840014"]}

   Answer is 202 with a `prefetch_id`.
3. Poll `GET $BROKER/v1/images/prefetch/<prefetch_id>` until the job is done.
   Expected: `state: done`, 3 hotels done, 0 failed (c46-sealed-2,
   nc-sealed-2, nc-sealed-3), size about 1.44 GB each. Any `failed`: read the
   error, retry once, otherwise leave the hotel and report.
4. Do not prefetch to `nc-sealed` (const) or `c46-sealed` (contest). They are
   outside the customer guest.
5. Check const guard is GREEN again.
6. Record the prefetch_id, per hotel finish times and the roll in the card
   comment for the roll.

## Cost of a missed step

One first desktop start on the rolled hotel takes 50 to 80 s. Nothing breaks.

## Evidence and owner

- 11 Nov: 7 warm starts 14 to 17 s (median 16 s); 3 first starts 48, 70, 81 s.
- 13 Nov: first start after prefetch 12.0 s to desktop.json.
- Owner: whoever runs `roll.sh apply` for the last hotel of the roll.
