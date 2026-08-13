# AI-Based Intrusion Detection System (IDS)

An AI-powered **real-time Network Intrusion Detection System** built using **XGBoost** and the **CIC-IDS2017** dataset.

The system captures network traffic through an agent, extracts network-flow features, sends those features to the server, and uses the trained AI model to classify the traffic. Predictions and alerts are stored in a database and delivered to the frontend in real time using WebSockets.

## Features

- Real-time network intrusion detection
- XGBoost multiclass classification
- 15 traffic and attack classes
- Network-flow feature extraction through an agent
- Real-time AI prediction
- Attack confidence scoring
- Database storage for detections and logs
- Real-time alerts using WebSockets
- Frontend dashboard for monitoring
- Class-balanced training
- Correlated-feature removal
- `NaN` / `Inf` handling
- Outlier clipping
- Early stopping

## Supported Classes

The model supports the following 15 classes:

```text
BENIGN
Bot
DDoS
DoS GoldenEye
DoS Hulk
DoS Slowhttptest
DoS slowloris
FTP-Patator
Heartbleed
Infiltration
PortScan
SSH-Patator
Web Attack - Brute Force
Web Attack - SQL Injection
Web Attack - XSS