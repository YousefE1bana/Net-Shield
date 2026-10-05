> **Historical UI-foundation evidence.** These screenshots predate the supported V2 backend. Current live evidence is in [Linux acceptance](../../LINUX-ACCEPTANCE.md); V2 automatic response is unsupported.

# UI V2 screenshot evidence

Captured on 2026-10-04 using real Flask read APIs through
`tests/ui/serve_console.py`. Capture is stopped, the temporary alert store is
empty, and automatic response is disabled **in the review process only**.
The unchanged product configuration still enables legacy automatic response.

No generated attack traffic, seeded alerts, fake flows, fabricated incidents,
successful firewall actions or fabricated time series are present in these images.
The scenario budgets are visibly labelled **planned**, and execution is gated.

`overview`, `lab`, `alerts`, `detections`, `response` and `health` have screenshots
at 1920, 1440, 1024, 390 and 320 pixels wide. Heights used are respectively
1080, 900, 900, 844 and 800; full-page captures may extend vertically beyond
the viewport. Page widths match viewport widths. Tables deliberately scroll
within their own labelled regions.

Additional images show scenario detail, safety preflight, navigation drawers
and real detector statistics. `before-desktop` and `before-mobile` show the
original UI inspected before editing; its narrow-phone document was 359px wide
in a 320px viewport.

Browser regression fixtures are separate test inputs and are not included in
this screenshot set. These images establish frontend rendering and truthful
empty states, not validated live detection or response.
