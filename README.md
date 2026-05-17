# DPI Engine (Deep Packet Inspection) 🚀

**DPI Engine** is a powerful, real-time packet analysis and network security tool built with Python. It acts like a digital security guard for your network, inspecting data packets as they flow through, identifying which applications they belong to, and blocking any unwanted or suspicious traffic.

## 🔴 Live Interactive Demo
We have deployed a live, fully functional demo of this project. You don't need to install anything to see how it works!
👉 **[Click here to view the Live DPI Engine Dashboard](https://huggingface.co/spaces/dhruvgupta780/DPI-Engine)**

*(Note: On the live dashboard, you can click the **"Download Trial File"** button to get a sample traffic file, and then upload it back to see the engine analyze the packets in real-time.)*

---

## 🔍 What does this project do?
In simple terms, when you connect to the internet, your data travels in small chunks called "packets". This engine:
1. **Reads these packets** from a network file (.pcap).
2. **Identifies the Application:** It looks inside the packet (using SNI/HTTP Headers) to figure out if the traffic is from YouTube, Facebook, Netflix, etc.
3. **Applies Security Rules:** It allows you to block specific IP addresses, Domains, or entire Applications.
4. **Shows Real-Time Data:** It streams all this information live to a beautiful web dashboard using WebSockets.

## ✨ Key Features
- **Real-Time Dashboard:** A clean, modern UI that updates instantly as packets are analyzed.
- **Application Recognition:** Detects over 10+ popular applications automatically.
- **Dynamic Blocking:** Add or remove blocking rules on the fly from the dashboard.
- **Anomaly Detection:** Automatically flags suspicious network patterns.
- **Data Export:** Download the analyzed network data as a CSV report.

## 🛠️ How to run it on your own computer

If you want to run this project locally on your machine, follow these simple steps:

**Step 1: Download the code**
Clone this repository to your computer.

**Step 2: Setup Python**
You need Python installed. Open your terminal and create a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
```

**Step 3: Install Requirements**
Install the necessary libraries (like FastAPI and Scapy):
```bash
pip install -r dpi-engine-python/requirements.txt
```

**Step 4: Start the Engine**
Run the server with this command:
```bash
cd dpi-engine-python
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Step 5: Open the Dashboard**
Go to your web browser and open `http://localhost:8000`. You will see the DPI Engine dashboard running!

---

## 📂 Project Structure
- `dpi_engine.py`: The "brain" of the project that analyzes the packets.
- `main.py`: The web server that connects the brain to the dashboard.
- `index.html`: The code for the beautiful web dashboard.
- `Dockerfile`: Deployment configuration to host the project online.
