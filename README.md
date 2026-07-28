# 🛡️ Thang Sentinel

A simulated enterprise Security Information & Event Management (SIEM) platform built in React. Designed to demonstrate SOC analyst workflows, detection engineering, and real-time security telemetry — no backend required.

![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react) ![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v15-red?style=flat) ![License](https://img.shields.io/badge/license-MIT-green?style=flat)

## Live Demo
**[StephenThang.github.io/thang_sentinel_dashboard](https://StephenThang.github.io/thang_sentinel_dashboard)**
<img width="1077" height="745" alt="image" src="https://github.com/user-attachments/assets/4c1a7acc-c508-4db0-a1b4-16f22e2f9f0f" />


---

## Features

**Detection Engine**
- 10 correlation rules (SENT-001 through SENT-010) firing on brute force, password spray, port scan, and IDS signature patterns
- MITRE ATT&CK v15 technique mapping on every alert (T1110.001, T1046, T1190, T1071.001, and more)
- Multi-stage campaign simulation: probes escalate into active attacks, occasionally achieving credential compromise

**Threat Intelligence**
- 12 simulated threat actor profiles with realistic ASNs, IP ranges, and attribution group names
- Weighted probabilistic spawn engine — higher-aggression actors appear more frequently
- Geolocation tracing with animated attack arc visualization on a live world map

**SOC Analyst Workflow**
- SPL-style search with field filters (`status=failed`, `src=185.*`, `country=Russia`, wildcards supported)
- One-click IP containment: block pushes a deny rule, kills the active campaign, and logs the SOAR response
- IP forensics drawer with reverse traceroute, reputation score, ASN attribution, and full event history
- Alert triage: acknowledge, block, or escalate with status tracking

**UI**
- Secure boot splash sequence on load
- Live threat posture gauge (GUARDED → SEVERE) driven by composite scoring
- Real-time perimeter traffic chart with inbound/outbound Mbps and failed auth overlays
- Critical incident banner when severity escalates
- Pause / resume / 4× speed controls
- Reduced-motion and keyboard-accessible throughout

---

## Stack

| Layer | Technology |
|---|---|
| Framework | React 18 (Vite) |
| Rendering | SVG (map, charts, gauge) — zero charting libraries |
| Styling | CSS-in-JS with CSS custom properties |
| Simulation | Pure JS state machine, no external data |
| Deployment | GitHub Pages via gh-pages |

---

## Run Locally

```bash
git clone https://github.com/StephenThang/thang_sentinel_dashboard.git
cd thang_sentinel_dashboard
npm install
npm run dev
```

Open `http://localhost:5173`

---

## Project Structure
