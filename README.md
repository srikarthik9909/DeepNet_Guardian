# 🔐 DeepNet Guardian – Deep Learning–Driven Network Intrusion Detection System (NIDS)

[![CI/CD](https://github.com/srikarthik9909/DeepNet_Guardian/actions/workflows/CI_CD_PipeLine.yml/badge.svg)](https://github.com/srikarthik9909/DeepNet_Guardian/actions/workflows/CI_CD_PipeLine.yml)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-teal.svg)
![Docker](https://img.shields.io/badge/Docker-ready-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

> **DeepNet Guardian** is a **Deep Learning–based Network Intrusion Detection System (NIDS)** designed for **real-time cyber threat detection**.  
It captures **live network traffic**, extracts **79 CICFlowMeter-inspired flow features**, and runs **TensorFlow Lite (TFLite)** Deep Learning models to detect attacks such as **DDoS** and **Port Scanning** — instantly and at scale.

## 🏗️ System Architecture

DeepNet Guardian follows a modular design:

```Markdown
┌────────────┐       ┌──────────────┐       ┌─────────────┐
│  Packet    │       │   Feature    │       │  Detection  │
│  Capture   │──────▶│ Extraction   │──────▶│   Engine    │
│  (Scapy)   │       │ (79 Features)│       │ (TFLite DL) │
└────────────┘       └──────────────┘       └─────────────┘
                                                    │
                                                    ▼
                                       ┌─────────────────────┐
                                       │  Defender Logging   │
                                       │ (JSON / CSV Outputs)│
                                       └─────────────────────┘
                                                    │
                                                    ▼
                                       ┌─────────────────────┐
                                       │   CI/CD Pipeline    │
                                       │  (GitHub Actions)   │
                                       └─────────────────────┘
                                                    │
                       ┌────────────────────────────┴────────────────────────────┐
                       ▼                                                         ▼
         ┌─────────────────────────┐                             ┌────────────────────────┐
         │   Automated Testing     │                             │   Dockerization        │
         │   (Pytest, Linting)     │                             │   (Build & Deployment) │
         └─────────────────────────┘                             └────────────────────────┘

```

## 🚀 Why DeepNet Guardian?

Modern networks face ever-evolving cyber threats that rule-based firewalls and legacy IDS tools cannot stop.

DeepNet Guardian changes the game with deep learning applied directly to raw network flows:

* End-to-End NIDS Pipeline – From packet capture ➝ feature extraction ➝ model prediction.
* CICFlowMeter-Compatible Features – 79 robust statistical flow features.
* Lightweight Deep Learning Models – Optimized TFLite models for edge & cloud deployment.
* Real-Time Detection – Multi-core multiprocessing ensures predictions without delay.
* Complete Defense Logging – Every event is tracked with severity scores.
* DevSecOps Ready – CI/CD pipelines, Docker support, and monitoring with Prometheus & Grafana.

## 📁 Project Structure


```Markdown
DeepNet_Guardian/
├── api.py                 # FastAPI service for flow feature extraction
├── deepnet_guard.py       # Real-time detection engine using Deep Learning (TFLite)
├── defender/              # Structured logging of attacks & events
├── logs/                  # Log outputs (attack & neutral events)
├── tflites/               # Pre-trained Deep Learning models (DDoS, PortScan)
├── tests/                 # Unit + integration tests for CI/CD
├── .github/workflows/     # GitHub Actions workflows (CI/CD pipelines)
├── Dockerfile             # Container setup for deployment
├── requirements.txt       # Python dependencies
└── README.md              # Project documentation
```

## ⚡ Key Features

✅ Live Network Traffic Capture (Scapy)

✅ 79 Flow Features Extraction (CICFlowMeter-style)

✅ Deep Learning–Based Detection (TFLite models)

✅ Real-Time Multiprocessing Predictions

✅ Defender Attack Logging System (CSV + JSON with severity levels)

✅ Continuous Integration (CI) with GitHub Actions & PyTest

✅ Monitoring Ready (Prometheus + Grafana dashboards)

✅ Dockerized Deployment for scalable and portable security environments


## 🛠️ Installation & Setup

###Prerequisites

* Python 3.9+
* Git
* Docker (optional, for containerized deployment)

### Setup Steps

**Clone the repository**

```Bash
git clone https://github.com/srikarthik9909/DeepNet_Guardian.git
cd DeepNet_Guardian
```


**Create virtual environment**

```Bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

**Install dependencies**

```Bash
pip install -r requirements.txt
```

## 🚦 Running the System

### 1️⃣ Start Feature Extraction API

```Bash
python api.py
```

* Runs a FastAPI server that continuously captures packets.

* Exposes an /extract_features endpoint returning the latest 79 flow features.

### 2️⃣ Run DeepNet Guardian (Detection Engine)

```Bash
python deepnet_guard.py
```

* Fetches flow features from the API.
* Creates sequences for Deep Learning models.
* Runs DDoS & Port Scan detection in real time.
* Logs results into logs/ directory.

## 📊 Example Output

* Neutral Traffic → Loading animation shows scanning with no alerts.
* Attack Detected → Instant alert with severity classification:
  * NEUTRAL (<0.4)
  * MODERATE (0.4–0.7)
  * ATTACK (>0.7)

### Logs include:

```Json
{
  "event": {
    "timestamp": 1757355085.194920,
    "src_ip": "66.45.252.104",
    "attack_type": "port_scan",
    "intensity": 1
  },
  "detection": "ATTACK"
}
```
## 🐳 Docker Deployment

```Bash
# Build container
docker build -t deepnet_guardian .

# Run container
docker run -p 8000:8000 deepnet_guardian
```

## 🧪 Testing

Run unit + integration tests with:

```Bash
pytest
```

## 📈 Monitoring

* Prometheus scrapes metrics from the API.
* Grafana dashboards visualize:
  * Flow rates
  * Attack severity
  * Detection stats in real time
 
## 🤝 Contributing

We welcome contributions!

1. Fork this repo
2. Create a branch (feature-x)
3. Commit changes (git commit -m "add feature")
4. Push & create PR 🚀

## 👤 Author

**Pampana Sri Karthik**  [GitHub](https://github.com/srikarthik9909) [Linkedin](https://www.linkedin.com/in/srikarthikpampana/)

**Korukonda Daniel Blesson** [GitHub](https://github.com/DanielBlesson) [Linkedin](https://www.linkedin.com/in/daniel-blesson-korukonda-0ba6a8246/)

### ⚡ DeepNet Guardian is not just a project — it’s a step towards the future of intelligent, deep learning–based intrusion detection.

