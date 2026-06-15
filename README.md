# Secure-Distributed-File-System-with-AI-Monitoring-Agent
Secure Distributed File System with AES-256-GCM encryption, JWT Zero Trust authentication, real-time AI threat detection using Ollama, and GRC compliance monitoring.
A fully functional distributed file system built from scratch on localhost (no Docker). Implements Zero Trust security, military-grade encryption, and LLM-based root cause analysis for security events.

## Key Features
- **AES-256-GCM encryption** for every file chunk
- **JWT-based Zero Trust authentication** (NIST SP 800-207 aligned)
- **3-node storage cluster** with automatic replication
- **Real-time threat detection** (Brute force, Ransomware, DDoS, Exfiltration)
- **Local AI Agent** (Ollama qwen3:4b) for automated Root Cause Analysis
- **Live GRC dashboard** with NIST AI RMF, ISO 27001 & OWASP scoring
- **Multi-process architecture** – 7 independent Flask services

## OS Concepts Demonstrated
- Multi-process architecture
- Inter-process communication (HTTP/TCP sockets)
- Multithreading (heartbeat, replication, polling threads)
- File system I/O with encrypted chunk storage

## Tech Stack
- Python 3.10 + Flask
- AES-256-GCM (cryptography library)
- JWT HS256
- Ollama (qwen3:4b)
- HTML/JavaScript dashboard

## Quick Start
```bash
git clone https://github.com/yourusername/SDFS.git
cd SDFS
start_all.bat
