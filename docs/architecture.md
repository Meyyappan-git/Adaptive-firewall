# System Architecture & Detection Logic

## 1. Data Pipeline
The system processes network traffic in a linear pipeline to ensure low latency and explainability.

**Traffic $\to$ Feature Extraction $\to$ Detection $\to$ Scoring $\to$ Enforcement**

### Feature Extraction
Raw packets are aggregated into a sliding time window (default: 60s). The system calculates 11 key behavioral features for every source IP:
- **Volume**: Packet count, Byte count.
- **Rate**: Packets per second (PPS), Bytes per second (BPS).
- **Diversity**: Unique destination ports, Unique destination IPs.
- **Reliability**: Failed connection count.
- **Pattern**: Connection rate, Average packet size, Duration.

## 2. Detection Layer
The system employs a "Hybrid Detection" strategy to balance precision and recall.

### Rule-Based Detection (Deterministic)
Implemented as a set of configurable thresholds. If a feature exceeds a threshold, it triggers a specific security rule:
- **Port Scan**: `unique_ports > threshold` $\to$ High threat.
- **Connection Burst**: `connection_rate > threshold` $\to$ Moderate threat.
- **Flood**: `bps > threshold` $\to$ Moderate threat.

### ML Anomaly Detection (Probabilistic)
The system uses an **Isolation Forest** algorithm. 
- **Why Isolation Forest?** It is an unsupervised learning algorithm perfect for anomaly detection. It works by "isolating" observations. Anomalies are easier to isolate (shorter paths in the tree) than normal points.
- **Pipeline**: Features $\to$ StandardScaler $\to$ Isolation Forest $\to$ Anomaly Score (0.0 to 1.0).

## 3. The Adaptive Decision Engine
The "Adaptive" nature of the firewall comes from the **Threat Scoring Engine**.

### Scoring Formula
The final threat score (0-100) is a weighted average:
$$\text{Total Score} = (S_{rule} \times W_{rule}) + (S_{ml} \times W_{ml}) + (S_{behavior} \times W_{behavior})$$

### Action Mapping
Based on the final score, the system dynamically assigns a severity and an enforcement action:

| Score | Severity | Action | Enforcement |
| :--- | :--- | :--- | :--- |
| 0-24 | LOW | ALLOW | No restrictions |
| 25-49 | MODERATE | MONITOR | Increased logging, no blocking |
| 50-74 | HIGH | TEMPORARY_BLOCK | Block IP for $N$ seconds |
| 75-100 | CRITICAL | BLOCK | Immediate block & Critical Alert |

This allows the system to be lenient with minor anomalies while responding aggressively to clear attacks.
