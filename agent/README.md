# IDS Agent

A network **Intrusion Detection System (IDS) Agent** built with Python. This project captures and analyses network packets in real-time, computing CICFlowMeter-style flow features to identify suspicious activity.

## Features

- Real-time packet capture using **Scapy**
- CICFlowMeter-compatible flow feature extraction (bulk stats, IAT, flags, etc.)
- Async I/O with **aiohttp**
- Offline testing suite

## Project Structure

```
agent/
├── ids_agent.py       # Core IDS agent logic
├── test_offline.py    # Offline test suite
├── requirements.txt   # Python dependencies
└── README.md
```

## Requirements

- Python 3.9+
- See `requirements.txt` for dependencies

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python ids_agent.py
```

## Team

This is a Final Year team project.

## License

MIT
