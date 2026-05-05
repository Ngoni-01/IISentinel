"""
IISentinel — Pilot Trial Playbook
════════════════════════════════════════════════════════════════════════
"Behind closed doors" demo and trial strategy for:
  · Zimplats / RioZim / Caledonia Mining (OT/CBS focus)
  · Econet Wireless / Liquid Intelligent Technologies (RF/Network)

READ THIS BEFORE ANY CLIENT MEETING.
════════════════════════════════════════════════════════════════════════

PHASE 0 — BEFORE YOU WALK IN (1 week out)
══════════════════════════════════════════

The single biggest mistake tech founders make in enterprise sales:
they demo the product before they understand the client's actual pain.

Do this first:
  1. Get the LinkedIn of their Head of OT / Head of Network Operations.
  2. Find their recent annual report — look for "downtime", "MTTR", 
     "network reliability", "SLA". These are the numbers you will 
     eventually replace with yours.
  3. For mining: look up their blast schedule. A Zimplats open-pit 
     blast happens every 2-3 weeks. That is your $450,000 hook.
  4. For Econet: look up their last outage that hit social media. 
     There will be one. That is your hook.
  5. Know one specific incident they had. Don't pretend you know 
     everything — say "we saw the [Month] outage reports on social 
     media — can you tell us what that cost internally?"

PHASE 1 — THE "NO ASK" MEETING (30 minutes)
════════════════════════════════════════════

You are NOT selling anything in this meeting. You are asking:

  "We're building IISentinel for infrastructure operators in Zimbabwe.
   We want to understand your current monitoring challenges before we 
   show you anything. What does a bad week look like for your ops team?"

Then shut up and listen for 20 minutes.

Questions that open wallets:
  · "What's your current MTTR when a base station goes down?"
  · "How do you currently get alerted to CBS integrity degradation?"
  · "What does an unplanned conveyor stop cost you per hour?"
  · "How many monitoring tools are you currently running?"
  · "When was the last time an anomaly caught you by surprise?"

Write down numbers. They'll tell you "$50,000 a day" or "3 hours MTTR."
Those are the numbers that go on your ROI slide.

PHASE 2 — THE LIVE DEMO (45 minutes, closed room)
══════════════════════════════════════════════════

Setup before they arrive:
  1. Run: python iis_agent.py --profile mining   (or telecom)
  2. Pull up dashboard at https://git-push-origin-main.onrender.com
  3. Navigate to Cascade tab — this is your "wow" moment
  4. Have the CBS Safety tab open on a second screen

The script:

  MINUTE 0-5: The hook
  ────────────────────
  "Before I show you the product, I want to show you something that 
   happened [simulate a cascade]. This is what a WAN degradation at 
   your NOC looks like rippling into a CBS hold.
   Your current system sees each of these events separately. 
   IISentinel sees them as one causal chain."
  [Run: CAS.scenario('wan') in the dashboard]

  MINUTE 5-15: Live data
  ──────────────────────
  "Everything you're seeing is live. These are your device types — 
   pumps, CBS controllers, base stations — sending real telemetry.
   The AI scores each device 0-100 and predicts failure before it 
   happens."
  [Click a degrading device gauge — show the detail modal]
  [Point to ETTF — "This device has 47 minutes before predicted failure"]

  MINUTE 15-25: The CBS moment
  ────────────────────────────
  "This is the moment that makes this different from SolarWinds or Zabbix."
  [Navigate to CBS Safety tab]
  "If this link drops below 90% — watch what happens."
  [Wait for a synthetic CBS hold to trigger, or trigger it manually]
  "The system issued a blast hold automatically. It sent an SMS to your
   blasting officer. It logged it with a timestamp. All before your 
   operator noticed. The cost of a misfire is $450,000 per blast. 
   This pays for itself in one prevented incident."

  MINUTE 25-35: Their specific pain
  ──────────────────────────────────
  Reference the numbers they gave you in Phase 1.
  "You mentioned your MTTR is [X hours]. Look at this — event to 
   automated command is under 60 seconds. That's not a dashboard 
   update. That's a command issued to the device."
  [Show Intelligence tab, point to failure probability ranking]

  MINUTE 35-45: The ask
  ──────────────────────
  "Here's what we want to propose. A 30-day shadow trial.
   We install a lightweight Python agent on one machine inside your 
   network — it needs outbound HTTPS only, no inbound ports, no 
   firewall changes. It runs alongside whatever you're using now.
   It doesn't replace anything. It just watches.
   After 30 days, we sit down and look at what it found that your 
   current tools missed. If it found nothing — fine, no cost to you.
   If it found something — you've already seen the value."

PHASE 3 — THE SHADOW TRIAL
══════════════════════════

What you deploy:
  - iis_agent.py with their real device IPs
  - A .env file with IIS_COLLECTOR_KEY set
  - A simple systemd service (Linux) or Task Scheduler (Windows)
  - Zero inbound firewall rules — outbound HTTPS to your Render URL only

What you need from them:
  - One machine inside their network (could be a Raspberry Pi you leave)
  - A list of device IPs they want monitored
  - SNMP community strings if they'll share them (nice to have, not required)
  - Contact for their NOC team

What you deliver after 30 days:
  - A PDF report: "30-day infrastructure health analysis"
  - Anomalies detected, incidents predicted, correlation events
  - ROI calculation: [incidents prevented] × [cost per incident]
  - Proposal for full deployment

PHASE 4 — PRICING (don't undersell)
════════════════════════════════════

The mistake: charging $50/month because you're nervous.
The reality: SolarWinds charges $2,000-$15,000/year per site.
Your advantage: you're local, you understand Zimbabwean infrastructure,
you have CBS safety integration that SolarWinds doesn't.

Anchor pricing:
  · Mining (safety-critical, CBS): $2,000-$5,000/month
    "One prevented blast misfire covers 12+ months of IISentinel"
  · Telecom (Econet/Liquid): $1,500-$3,000/month per region
    "Each avoided base station outage pays for a month"
  · Enterprise network: $500-$1,500/month

Start with a 3-month pilot at 50% discount. Full price after.

TECHNICAL DEPLOYMENT NOTES FOR TRIAL
═════════════════════════════════════

# 1. Install on client machine (Linux)
pip install requests icmplib pysnmp --break-system-packages

# 2. Create .env
echo "IIS_COLLECTOR_KEY=their_collector_key_from_specialist_panel" > .env

# 3. Create systemd service
sudo tee /etc/systemd/system/iis-agent.service > /dev/null << EOF
[Unit]
Description=IISentinel Collector Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/iis_agent.py --profile mining
WorkingDirectory=/opt
EnvironmentFile=/opt/.env
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable iis-agent
sudo systemctl start iis-agent
sudo journalctl -u iis-agent -f   # watch live

# 4. Windows (Task Scheduler alternative)
# Create a .bat file:
# python C:\IISentinel\iis_agent.py --profile mining
# Schedule it to run at startup with "Run whether user is logged on or not"

WHAT TO DO WHEN THEY SAY "OUR IT DEPARTMENT WON'T ALLOW IT"
════════════════════════════════════════════════════════════
This is the most common blocker. Counter:

1. "It requires zero inbound connections. Your firewall doesn't change.
    It's equivalent to any of your staff browsing the web."

2. "We can run it in read-only mode — it cannot write to any device,
    only read metrics."

3. "We can provide the source code for your IT team to audit."
   (Your code is open for inspection — this is actually your advantage
    over proprietary vendors like SolarWinds who black-box everything)

4. "We can deploy it on hardware you own — a $50 Raspberry Pi that 
    never leaves your premises. The only thing that leaves is metric data."

WHAT TO DO WHEN THEY SAY "WE ALREADY HAVE ZABBIX/SOLARWINDS"
══════════════════════════════════════════════════════════════
"Perfect. Those tools are excellent at what they do. They monitor devices.
 IISentinel does something different — it models causality across domains.
 Your CBS controller, your WAN link, and your base station don't talk to 
 each other in Zabbix. In IISentinel, a WAN degradation at 2am 
 automatically triggers a CBS hold recommendation before your operator 
 sees the first alert in Zabbix. We're not replacing your tools. 
 We're adding the layer that connects them."
"""

print(__doc__)
