---
title: DPI Engine
emoji: 🚀
colorFrom: blue
colorTo: indigo
sdk: docker
pinned: false
---

# DPI Engine (Deep Packet Inspection) 🚀

This project is a powerful Python implementation of a Deep Packet Inspection (DPI) engine inspired by enterprise packet analyzer architectures. It parses PCAP traffic, extracts TLS SNI/HTTP Host, classifies applications, applies blocking rules, detects anomalies, and streams live packet updates to a dashboard using WebSockets.

## 🔴 Live Demo
The project is currently deployed and running live on Hugging Face Spaces:
👉 **[DPI Engine Live Dashboard](https://huggingface.co/spaces/dhruvgupta780/DPI-Engine)**

> **Note:** The live demo is fully open (no authentication required) and features a direct "Download Trial File" button so you can easily test the inspection capabilities.

## ✨ Features
- **Real-Time Packet Inspection:** Streams parsed packet data to the UI using WebSockets.
- **Application Classification:** Identifies protocols and applications (YouTube, Facebook, Netflix, etc.) based on packet signatures and SNI/Host headers.
- **Dynamic Block Rules:** Filter traffic by IP, Domain, or Application.
- **Anomaly Detection:** Flags suspicious packets and unusual patterns.
- **Comprehensive Dashboard:** View charts, statistics, and live packet flows with geolocation flags.

## 🛠️ Installation (Local)

1. Clone this repository and enter the directory.
2. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r dpi-engine-python/requirements.txt
   ```

## 🚀 Running Locally

1. Start the FastAPI server (it serves both backend and frontend):
   ```bash
   cd dpi-engine-python
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```
2. Open your browser and navigate to `http://localhost:8000`.

## 📂 Project Structure
All application code is located in the `dpi-engine-python/` directory.

- `dpi_engine.py`: Core DPI analysis logic and Scapy integration.
- `main.py`: FastAPI server, WebSockets, and API endpoints.
- `index.html`: The frontend UI dashboard.
- `Dockerfile`: Deployment configuration for Hugging Face/Docker.
