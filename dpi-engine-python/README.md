---
title: DPI Engine
emoji: 🚀
colorFrom: blue
colorTo: indigo
sdk: docker
pinned: false
---

# DPI Engine Python (FastAPI + Scapy)

This project is a Python implementation of a Deep Packet Inspection engine inspired by the C++ Packet Analyzer architecture. It parses PCAP traffic, extracts TLS SNI/HTTP Host, classifies applications, applies blocking rules, detects anomalies, and streams live packet updates to a dashboard using WebSockets.

## Install

1. Create and activate a Python 3.11 virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Run

1. Generate test data (optional):

```bash
python generate_sample.py
```

2. Start API + dashboard server:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Admin credentials (default):
- Username: `ithead`
- Password: `ITHead@2026`

You can override with environment variables:
- `DPI_ADMIN_USER`
- `DPI_ADMIN_PASS`

3. Open dashboard:
- Open [http://localhost:8000](http://localhost:8000), or open `index.html` directly and ensure API runs on `localhost:8000`.

## How To Use

1. Login as admin from the IT Head access panel.
2. Upload a `.pcap` file from the Upload Panel.
3. Watch the live packet feed stream via WebSocket.
4. Add/remove block rules (IP, domain, app) from the Rules section.
5. Review real-time stats, app distribution, detected domains, and anomaly alerts.
6. Export packet results using **Download CSV Report**.
