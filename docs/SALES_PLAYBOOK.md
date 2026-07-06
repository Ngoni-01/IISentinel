# IISentinel — Positioning & Sales Playbook
### How to sell this as needed technology, not a redundant fancy system

## The one-sentence pitch (memorize this)
"You are already paying for downtime — IISentinel makes you pay less for it,
using equipment you already own and a $80 sensor node where you own nothing."

## Why it is NOT redundant — the three arguments

**1. Consolidation, not addition.**
A typical mine or telecom operator runs 3-6 disconnected tools: the SCADA
vendor's HMI, an NMS for network gear, spreadsheet-based maintenance logs,
manual inspection rounds. IISentinel does not add a 7th tool — it replaces
the gaps BETWEEN them with one pane of glass and one consistent 0-100 health
language across all equipment. The pitch is subtraction: fewer tools, fewer
blind spots, one audit trail.

**2. It is built for THIS operating environment.**
Imported monitoring products assume always-on connectivity and $5,000
instrumentation points. IISentinel assumes intermittent links (edge buffering,
auto-flush), commodity hardware ($80 Pi nodes), and local notification
channels (Africa's Talking SMS, WhatsApp). No imported competitor does this
out of the box. This is your unfair advantage — say it plainly.

**3. Condition-based maintenance is money, not magic.**
The sale is not "AI." The sale is: catch a $150,000/hr pump failure 2 hours
early, once, and the system has paid for itself for a decade. Frame every
feature in cost-of-downtime terms:
  - Health trend + ETTF  → schedule the repair BEFORE the failure
  - Anomaly detection    → catch the weird failure the thresholds miss
  - Maintenance windows  → no alert fatigue during planned work
  - Audit log            → who changed what, when (compliance answer)
  - CBS interlock        → early warning layered UNDER certified safety systems

## Edition ladder (the Microsoft move you asked for)
Sell entry-level, expand later. Set ENABLED_MODULES per client:

| Edition | Modules | Who buys it | Anchor price logic |
|---|---|---|---|
| Network Edition | net | ISPs, corporate IT, campuses | per-device/month, cheapest |
| Telecom Edition | tc | tower cos, WISPs, MNO regions | per-site/month |
| Mining OT Edition | mc | mine engineering departments | per-shaft or per-plant |
| Mining OT + CBS Safety | mc+cbs | mines with blasting ops | premium — safety justifies it |
| Enterprise Suite | all | integrated operators | bundle discount vs à la carte |

The upsell path is natural: a mine buys Mining OT, then discovers its network
gear is the blind spot → adds Network. The edition system means you never
have to say "you must buy everything."

## The honest AI story (this WINS engineering audiences)
Never claim the model is pre-trained intelligence. Say exactly this:

"On day one, scoring is rule-based and fully explainable — an engineer can
read the exact formula. From the first hour, the system logs real telemetry
from YOUR equipment. After 500 real readings, the ML model trains on YOUR
data and takes over — and the dashboard shows you which mode it is in.
We never train on synthetic values, and you can see the sample count live."

This turns your biggest weakness (no training data at deployment) into your
most credible differentiator (transparent cold start, learns their plant,
provenance visible in the UI). Examiners and engineering managers will
respect this far more than any accuracy claim you cannot back.

## Pilot structure (how to land Unki/Blanket-class sites)
1. Free/cheap 30-day pilot: ONE section (e.g., Shaft 1 pumps), 5-10 devices,
   2 Pi nodes, Mining OT Edition only. Small ask, low risk to them.
2. Success criterion agreed IN WRITING up front: e.g., "system flags at
   least one degradation before the shift crew notices it."
3. Weekly shift report PDF lands in the engineering manager's inbox
   automatically — the product sells itself to their boss.
4. Expand: more sections → CBS add-on → network module → annual contract.

## Objection handling
- "We have SCADA." → "SCADA shows current values. IISentinel adds trend,
  prediction, and cross-domain correlation — it feeds FROM your SCADA
  (REST bridge, ~50 lines), it does not replace it."
- "Is the AI accurate?" → show the provenance badge + heuristic formula.
  "It starts explainable and learns your plant. You can audit every step."
- "Safety certification?" → "IISentinel is an early-warning layer subordinate
  to your certified blasting system. It never replaces certified PLCs."
  (Saying this unprompted builds more trust than any feature.)
- "What if the internet drops?" → demo the Pi buffering: unplug, readings
  queue to disk, replug, auto-flush. This demo closes deals here.

## What NOT to say
- Do not compare to YouTube/Google/Microsoft scale — you will lose the room.
  You are a focused industrial tool; the comparison is against clipboards,
  vendor lock-in, and blind spots. That fight you win.
- Do not quote uptime or accuracy numbers you have not measured on-site.
- Do not lead with the cascade engine in a first meeting — it is a great
  second-meeting wow, but pumps-not-failing is what they pay for.
