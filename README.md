# Continuous Authentication Framework for IoT Devices

Source code and experimental datasets for the paper:

> **Continuous Authentication Framework for IoT Devices**
> Fahim Rahman, Manesh Thankappan, Danial Javaheri
> *Machine Learning and Knowledge Extraction (MAKE)*, MDPI, 2026.

## Overview

This repository contains the implementation of a lightweight continuous authentication framework for resource-constrained IoT devices.  The framework uses network, radio-frequency, and device-health telemetry to continuously reassess device trustworthiness during runtime, replacing the traditional one-time authentication model with an adaptive, multi-state trust evaluation.

**Key features:**

- Multi-domain telemetry collection (RSSI, BSSID, DNS, heap, latency, uptime, sequence numbers)
- Weighted feature scoring with sliding-window averaging
- Four-state authentication model: Authenticated, Suspect, Challenged, Rejected
- Adaptive cryptographic challenge-response (HMAC-SHA256)
- TLS-secured communication channel
- Minimal overhead (<1% memory, <1 kbps data rate)

## Repository Structure

```
iot-continuous-auth/
├── client/                         # ESP32 device firmware
│   └── iot_telemetry_firmware/
│       └── iot_telemetry_firmware.ino   # Arduino sketch for ESP32-C6
├── server/                         # Verification server (Python)
│   ├── verification_server.py      # Flask HTTPS server
│   ├── auth_engine.py              # Authentication state machine
│   ├── config.py                   # Configuration parameters
│   └── requirements.txt            # Python dependencies
├── certs/                          # TLS certificate generation
│   └── setup_certs.sh              # Self-signed CA and server certs
├── datasets/                       # Experimental telemetry datasets
│   ├── baseline.csv                # Baseline operation telemetry
│   └── telemetry_esp32-lab-01_*.csv # Full experimental telemetry
└── README.md
```

## Hardware Requirements

| Component | Details |
|-----------|---------|
| IoT Device | ESP32-C6 (e.g., ESP32-C6-Zero) |
| Server | ARM-based SBC (tested on Cubie A5E) or any Linux host |
| Network | IEEE 802.11 Wi-Fi with Internet connectivity |

## Setup Instructions

### 1. Generate TLS Certificates

```bash
cd certs
bash setup_certs.sh
```

Copy the contents of `ca.crt` into the `CA_CERT` variable in the Arduino firmware.

### 2. Server Deployment

```bash
cd server
pip install -r requirements.txt
python verification_server.py
```

The server starts on port 5000 with TLS enabled. Edit `config.py` to adjust authentication parameters (thresholds, window size, feature weights).

### 3. ESP32 Firmware

1. Open `client/iot_telemetry_firmware/iot_telemetry_firmware.ino` in Arduino IDE
2. Install the ESP32 board package (Espressif ESP32 Arduino Core)
3. Configure `WIFI_SSID`, `WIFI_PASSWORD`, `SERVER_URL`, and `HMAC_KEY`
4. Paste the CA certificate into `CA_CERT`
5. Select board: **ESP32-C6 Dev Module**
6. Upload to the device

### 4. Running Experiments

Once both server and device are running, telemetry is logged automatically to `datasets/`. Authentication events are recorded in `datasets/auth_events.csv`.

## Configuration

Key parameters in `server/config.py`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `WINDOW_SIZE` | 5 | Sliding window length for score averaging |
| `SUSPICION_THRESHOLD` | 0.65 | Score below which device becomes Suspect |
| `CHALLENGE_THRESHOLD` | 0.45 | Score below which a challenge is issued |
| `SUSPECT_PATIENCE` | 3 | Consecutive suspect cycles before challenge |
| `CHALLENGE_TIMEOUT_SEC` | 10.0 | Time allowed for challenge response |
| `MAX_CHALLENGE_FAILURES` | 3 | Failed challenges before Rejected state |

## Telemetry Fields

| Field | Source | Description |
|-------|--------|-------------|
| `rssi_dbm` | Wi-Fi | Received signal strength indicator |
| `bssid` / `wifi_bssid_hash` | Wi-Fi | Access point identifier (raw and hashed) |
| `channel` | Wi-Fi | Operating Wi-Fi channel |
| `dns1`, `dns2` | Network | DNS resolver addresses |
| `internet_state` | Network | External reachability (0=down, 2=up) |
| `heap_free`, `min_free_heap` | System | Available and minimum heap memory |
| `uptime_ms` | System | Time since last reset |
| `reset_reason` | System | Cause of last device reset |
| `latency_ms` | Network | Round-trip time to server |
| `seq` | Protocol | Monotonically increasing sequence number |
| `loop_jitter_ms` | Timing | Deviation from expected telemetry interval |

## License

MIT License. See individual source files for details.

## Citation

If you use this code or dataset in your research, please cite:

```bibtex
@article{rahman2026continuous,
  title={Continuous Authentication Framework for IoT Devices},
  author={Rahman, Fahim and Thankappan, Manesh and Javaheri, Danial},
  journal={Machine Learning and Knowledge Extraction},
  year={2026},
  publisher={MDPI}
}
```

## Author

Fahim Rahman — [fahimrahmanbooom@gmail.com](mailto:fahimrahmanbooom@gmail.com)
