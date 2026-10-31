# FinTrace AI: AI Financial Crime Network Investigator

> **TCS Hackathon 2026 — Challenge 07: AI Financial Crime Network Investigator (AI for Business)**

FinTrace AI is an enterprise-grade agentic financial intelligence platform engineered to detect, de-anonymize, and dismantle complex money laundering syndicates, pass-through mule rings, and device-collision fraud networks.

---

## Key Highlights

- **Multi-Agent Reasoning Committee**: Powered by Groq LLM (`openai/gpt-oss-120b`). Employs a Detective Agent (pattern discovery), Defense Agent (Devil's Advocate for false positive reduction), and Auditor Agent (evidence verification).
- **Heterogeneous Graph Intelligence**: Powered by `NetworkX` with 11,000+ nodes and 9,000+ edges, capturing multi-hop relationships across Accounts, Shared Hardware Devices, and Proxy IPs.
- **Machine Learning Anomaly Detection**: `Isolation Forest` velocity and behavioral deviation scoring combined with custom `Node2Vec` structural random-walk embeddings.
- **Dynamic Jury Adaptability**: Allows human evaluators to inject unseen scenarios in real time to witness dynamic autonomous re-planning.
- **Regulatory Compliance**: Human-in-the-Loop (HITL) approval gateway with official SAR (Suspicious Activity Report) generation adhering to FIU-IND / FATF guidelines.
- **AI Forensic Co-Pilot Chatbot**: Real-time forensic query engine connected directly to the Graph telemetry and ML models with structured tabular output.

---

## Tech Stack

- **Backend**: FastAPI, Python 3.11, NetworkX, Scikit-Learn (Isolation Forest), Groq Python SDK, Uvicorn
- **Frontend**: React 19, TypeScript, Vite, React Force Graph 2D, Lucide React, React Markdown
- **Data Ingestion**: Multi-tenant CSV Streaming Parser with Smart Connected Subgraph Ingestion

---

## Quick Start

### 1. Backend Setup
```bash
cd backend
pip install -r requirements.txt
python main.py
```
Backend runs on `http://localhost:8000`.

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Frontend runs on `http://localhost:5173`.

