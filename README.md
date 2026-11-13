# `lh-gps-spoof-detector` (`lh-gps-spoof`)

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-gps-spoof-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-gps-spoof-detector/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Rust%20std%20only)-success.svg)](Cargo.toml)
[![Security Policy](https://img.shields.io/badge/Security-Strict%20#![forbid(unsafe_code)]-brightgreen.svg)](SECURITY.md)

**Production-grade, zero-dependency Rust 2021 Edition Multi-Band GNSS & India NavIC (IRNSS) Spoofing Detector, Doppler-Pseudorange & AGC/C/N₀ Anomaly Analyzer, Keplerian Ephemeris Verifier, and 10-Rule Resilient PNT Security Posture Auditor.**

---

## Architectural Overview

`lh-gps-spoof-detector` is engineered for critical aerospace, autonomous robotics, defense telemetry, and national positioning-navigation-timing (PNT) infrastructure. It provides real-time detection of hostile GNSS spoofers, meaconers, software-defined radio (SDR) replay transmitters, and clock-bias dragging vectors by analyzing physical RF properties and celestial mechanics invariants across multi-band GPS (L1/L2/L5) and India NavIC (IRNSS L5/S-band).

```
                      Hostile RF Field or Clean Sky Telemetry
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │   Multi-Band RF Receiver Front    │
                     │  (GPS L1/L2/L5 & NavIC L5/S-band) │
                     └─────────────────┬─────────────────┘
                                       │
                ┌──────────────────────┴──────────────────────┐
                ▼                                             ▼
  ┌───────────────────────────┐                 ┌───────────────────────────┐
  │ Physical Invariants Layer │                 │ Protocol & Ephemeris Layer│
  ├───────────────────────────┤                 ├───────────────────────────┤
  │ • C/N0 Overpower Surge    │                 │ • NMEA-0183 8-bit XOR     │
  │ • AGC Compression Drop    │                 │   Checksum Validator      │
  │ • Spatial Variance Drop   │                 │ • Keplerian MEO & GSO/GEO │
  │ • Doppler vs Code Rate    │                 │   Orbital Bounds Verifier │
  │ • Clock Bias Slew Rate    │                 │ • Dual PVT Solution Split │
  └─────────────┬─────────────┘                 └─────────────┬─────────────┘
                │                                             │
                └──────────────────────┬──────────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │ 10-Rule PNT Security Auditor      │
                     │ (SARIF v2.1.0, JSON, ANSI Tables) │
                     └───────────────────────────────────┘
```

---

## Physical Detection Principles & Mathematical Foundations

### 1. Carrier Doppler vs. Pseudorange Rate Consistency
A physical satellite in orbit moves with orbital velocity $\mathbf{v}_{\text{sat}}$, creating an apparent carrier Doppler shift $f_{d, s}$:
$$v_{\text{doppler}, s} = -\lambda_c \cdot f_{d, s} = -\frac{c}{f_c} \cdot f_{d, s}$$
Concurrently, the delta pseudorange rate over interval $\Delta t = t_k - t_{k-1}$ is:
$$\dot{\rho}_s(t_k) = \frac{\rho_s(t_k) - \rho_s(t_{k-1})}{t_k - t_{k-1}}$$
In an authentic transmission, code delay rate and carrier phase rate are physically bound by phase-code coherence:
$$\big| \dot{\rho}_s(t_k) - v_{\text{doppler}, s}(t_k) \big| \le \epsilon_{\text{threshold}} \quad (\epsilon = 2.5\text{ m/s})$$
Hostile SDR transmitters frequently manipulate pseudorange delays without updating carrier frequency synthesizers, triggering a severe rate mismatch.

### 2. Single-Antenna Spatial $C/N_0$ Variance Collapse
Genuine satellites arrive from disparate azimuth and elevation angles, traversing varying atmospheric path lengths:
$$\sigma_{C/N_0}^2 = \frac{1}{N} \sum_{i=1}^N \left( C/N_{0, i} - \overline{C/N_0} \right)^2$$
When satellites with elevation spread $\Delta\theta_{\text{elev}} \ge 25^\circ$ exhibit $\sigma_{C/N_0}^2 < 0.5\text{ dB}^2$, all satellite channels are originating from a single co-located RF horn or spoofing simulator.

### 3. $C/N_0$ Overpower & AGC Compression
The theoretical maximum power of civil GPS/NavIC signals at Earth's surface is approximately $-153\text{ dBW}$, yielding $C/N_0 \le 54.0\text{ dB-Hz}$. Spoofers attempting to overcome authentic signals typically induce:
$$C/N_0 > 54.0\text{ dB-Hz} \quad \text{or} \quad \Delta C/N_0 > 6.0\text{ dB}$$
Coincident with an Automatic Gain Control (AGC) attenuation drop $\Delta\text{AGC} \ge 8.0\%$ caused by RF front-end saturation.

### 4. Multi-Constellation GPS vs. India NavIC Position Split
Because India's NavIC (IRNSS) constellation operates in the geostationary/geosynchronous orbit regime with dedicated L5 ($1176.45\text{ MHz}$) and S-band ($2492.028\text{ MHz}$) signals, spoofers targeting standard GPS L1 ($1575.42\text{ MHz}$) create a spatial divergence:
$$\big\| \mathbf{r}_{\text{GPS}} - \mathbf{r}_{\text{NavIC}} \big\|_2 = \sqrt{(x_{\text{GPS}} - x_{\text{NavIC}})^2 + (y_{\text{GPS}} - y_{\text{NavIC}})^2 + (z_{\text{GPS}} - z_{\text{NavIC}})^2} > 35.0\text{ m}$$

### 5. Keplerian Broadcast Ephemeris Physical Bounds
Decoded broadcast ephemeris orbital elements are validated against physical orbital mechanics:
- **GPS MEO**: Semi-major axis $a = (\sqrt{A})^2 \in [26.4\times 10^6, 26.7\times 10^6]\text{ m}$, eccentricity $e \le 0.03$, inclination $i_0 \in [0.85, 1.10]\text{ rad}$ ($48.7^\circ - 63.0^\circ$).
- **NavIC GSO/GEO**: Semi-major axis $a \in [41.9\times 10^6, 42.4\times 10^6]\text{ m}$, eccentricity $e \le 0.03$, inclination $i_0 \le 0.65\text{ rad}$ ($\le 37.2^\circ$).

---

## 10-Rule Resilient PNT Security Posture Auditor

The engine audits receiver firmware configuration files against 10 strict PNT hardening rules:

| Rule ID | Severity | Deduction | CWE | Rule Description | Remediation |
|---|---|---|---|---|---|
| `LH-GNSS-001` | **CRITICAL** | -25 | CWE-290 | Multi-Constellation & India NavIC (IRNSS) Diversity | Enable simultaneous tracking of GPS and India NavIC (IRNSS L5/S-band). |
| `LH-GNSS-002` | **CRITICAL** | -25 | CWE-345 | Cryptographic Navigation Message Authentication (NMA) | Activate OS-NMA, Chimera, or NavIC L1C-NMA broadcast signature checks. |
| `LH-GNSS-003` | **CRITICAL** | -25 | CWE-682 | C/N0 Overpower Surge & AGC Compression Monitoring | Enable AGC telemetry analysis and reject $C/N_0 > 54\text{ dB-Hz}$. |
| `LH-GNSS-004` | **HIGH** | -10 | CWE-682 | Carrier Doppler vs. Pseudorange Rate Consistency | Enforce continuous cross-validation between carrier Doppler and delta-code rate. |
| `LH-GNSS-005` | **HIGH** | -10 | CWE-367 | Receiver Clock Bias Slew Rate & Step Guard | Bound receiver clock drift to physical crystal limits ($\le 50\text{ ns/s}$). |
| `LH-GNSS-006` | **HIGH** | -10 | CWE-682 | Coupled INS/IMU Kalman Innovation Verification | Tightly couple IMU accelerometer/gyroscope measurements with GNSS Kalman filter. |
| `LH-GNSS-007` | **HIGH** | -10 | CWE-20 | Keplerian Broadcast Ephemeris Orbital Physics Bounds | Validate decoded orbital parameters against celestial mechanics bounds. |
| `LH-GNSS-008` | **MEDIUM** | -4 | CWE-682 | Inter-Satellite Spatial C/N0 Variance Collapse & Mask | Enable spatial variance tracking ($\sigma^2 \ge 0.5\text{ dB}^2$) and elevation mask $\ge 10^\circ$. |
| `LH-GNSS-009` | **MEDIUM** | -4 | CWE-306 | Authenticated RTCM & Protected NMEA Telemetry | Authenticate RTCM 3.x streams and isolate NMEA telemetry from public networks. |
| `LH-GNSS-010` | **LOW** | -1 | CWE-778 | Resilient INS Dead-Reckoning Holdover & Logging | Enable automatic inertial holdover failover and persist RF forensic event logs. |

The posture score is defined as:
$$S = \max\left(0, 100 - \sum \text{Deductions}\right)$$

---

## Installation & Compilation

`lh-gps-spoof-detector` is engineered with **zero external crate dependencies** (`[dependencies]` is completely empty) and strictly enforces `#![forbid(unsafe_code)]`.

```bash
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-gps-spoof-detector.git
cd lh-gps-spoof-detector

# Verify formatting and linter
cargo fmt --check
cargo clippy --all-targets -- -D warnings

# Execute test suite (65+ tests)
cargo test --verbose

# Build release binary
cargo build --release
# Binary available at target/release/lh-gps-spoof
```

---

## CLI Command Reference

### 1. Audit Security Posture Configuration
```bash
# ANSI table output
./target/release/lh-gps-spoof scan fixtures/hardened_gnss_policy.json --format table

# OASIS SARIF v2.1.0 output (for GitHub Code Scanning / IDE integration)
./target/release/lh-gps-spoof scan fixtures/vulnerable_gnss_policy.json --format sarif

# Canonical JSON output
./target/release/lh-gps-spoof scan fixtures/hardened_gnss_policy.json --format json
```

### 2. Analyze Multi-Epoch GNSS Telemetry
```bash
# Analyze multi-band epoch stream for active spoofing anomalies
./target/release/lh-gps-spoof analyze-epochs fixtures/sample_gnss_epochs.json --format table
```

### 3. Verify NMEA-0183 Stream Checksum Integrity
```bash
# Verify 8-bit XOR checksums and extract PVT fixes
./target/release/lh-gps-spoof verify-nmea fixtures/sample_nmea_stream.txt --format table
```

### 4. Validate Keplerian Broadcast Ephemeris
```bash
# Verify celestial orbital parameters against GPS MEO and NavIC GSO/GEO limits
./target/release/lh-gps-spoof check-ephemeris fixtures/sample_ephemeris.json --format table
```

---

## License & Attribution

Copyright 2026 Logihertz Systems OPC Pvt. Ltd.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0).
