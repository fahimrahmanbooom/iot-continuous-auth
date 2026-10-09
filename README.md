# Continuous Authentication Framework for IoT Devices

Source code and experimental datasets for the paper:

> **Continuous Authentication Framework for IoT Devices**
> Fahim Rahman, Manesh Thankappan, Danial Javaheri, Muhsin Hassanu, Raja Ujjan
> *Sensors*, MDPI, 2026.

## Overview

This repository contains the implementation of a lightweight continuous authentication framework for resource-constrained IoT devices.  The framework uses network, radio-frequency, and device-health telemetry to continuously reassess device trustworthiness during runtime, replacing the traditional one-time authentication model with an adaptive, multi-state trust evaluation.

**Key features:**

- Multi-domain telemetry collection (RSSI, BSSID, DNS, heap, latency, uptime, sequence numbers)
- Weighted feature scoring with sliding-window averaging
- Four-state authentication model: Authenticated, Suspect, Challenged, Rejected
- Selective cryptographic challenge-response (HMAC-SHA256)
- TLS-secured communication channel
- Reproducible trace-driven evaluation using recorded ESP32 telemetry

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
3. Copy `secrets.example.h` to `secrets.h` and set the Wi-Fi credentials and a unique random device key of at least 32 bytes
4. Set the same key on the server with `IOT_AUTH_ESP32_LAB_01_KEY`; do not commit `secrets.h` or a deployment key
5. Configure `SERVER_URL` and paste the CA certificate into `CA_CERT`
6. Select board: **ESP32-C6 Dev Module**
7. Upload to the device

Any key that has previously appeared in a public commit must be treated as
compromised and rotated before deployment.

### 4. Running Experiments

Once both server and device are running, telemetry is logged automatically to `datasets/`. Authentication events are recorded in `datasets/auth_events.csv`.

## Configuration

Key parameters in `server/config.py`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `WINDOW_SIZE` | 5 | Sliding window length for score averaging |
| `SUSPICION_THRESHOLD` | 0.75 | Score below which device becomes Suspect |
| `CHALLENGE_THRESHOLD` | 0.45 | Score below which a challenge is issued |
| `SUSPECT_PATIENCE` | 3 | Consecutive suspect cycles before challenge |
| `CHALLENGE_TIMEOUT_SEC` | 10.0 | Time allowed for challenge response |
| `MAX_CHALLENGE_FAILURES` | 3 | Failed challenges before Rejected state |
| `REENROLL_AFTER_VERIFICATION` | True | Adopt a new network context after a valid challenge response, once the next sample confirms it |
| `SERVER_PORT` | 5000 | Override with `IOT_AUTH_PORT` (macOS reserves 5000 for AirPlay Receiver) |

Sequence replay and reboot events trigger an immediate challenge because they
can otherwise disappear within the five-sample moving average. Run
`experiments/run_trace_injection.py` for the primary evaluation,
`experiments/run_sensitivity.py` for the 3-by-3 window and threshold analysis,
and `experiments/run_benign_and_baselines.py` for the benign-disruption,
weight-perturbation, and reference-rule analyses. All three replay the same
recorded trace; none collects new data.

## Physical Validation

The physical tests run the firmware on an ESP32-C6 against the live server.

```bash
cd certs && SERVER_IP=<server-ip> bash setup_certs.sh && cd ..
# put SERVER_HOST, SERVER_PORT, CA_CERT, Wi-Fi credentials, and HMAC_KEY in secrets.h
cd server && IOT_AUTH_PORT=5443 IOT_AUTH_ESP32_LAB_01_KEY=<key> \
  IOT_AUTH_CAPTURE_ENVELOPES=../datasets/captured_envelopes.jsonl \
  python verification_server.py
python experiments/device/serial_logger.py /dev/cu.usbmodemXXXX datasets/device_serial.log
python experiments/device/physical_events.py reboot           # USB reset of the board
python experiments/device/physical_events.py replay --age 120 # replay an older signed message
python experiments/device/physical_events.py replay --forge   # replay plus forged challenge answer
python experiments/device/analyze_physical.py 2026-10-09
```

The server writes one row per accepted message to `datasets/decisions.csv`.
The archived session, its summary, and the timeline figure are in
`datasets/physical/`.

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
  author={Rahman, Fahim and Thankappan, Manesh and Javaheri, Danial and Hassanu, Muhsin and Ujjan, Raja},
  journal={Sensors},
  year={2026},
  publisher={MDPI}
}
```

## Author

Fahim Rahman — [fahimrahmanbooom@gmail.com](mailto:fahimrahmanbooom@gmail.com)
