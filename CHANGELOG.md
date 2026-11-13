# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-13

### Added
- **Multi-Band GNSS & India NavIC (IRNSS) Physics Engine (`gnss_physics.rs`)**:
  - Carrier frequencies and speed of light constants: GPS L1 (1575.42 MHz), GPS L2 (1227.60 MHz), GPS/NavIC L5 (1176.45 MHz), and NavIC S-band (2492.028 MHz).
  - $C/N_0$ overpower threshold ($> 54.0\text{ dB-Hz}$) and step jump ($> 6.0\text{ dB}$) monitoring.
  - Receiver front-end AGC gain compression detector ($\Delta\text{AGC} \ge 8.0\%$ with $C/N_0$ surge).
  - Single-antenna spatial co-linearity detector via inter-satellite $C/N_0$ variance collapse ($\sigma_{C/N_0}^2 < 0.5\text{ dB}^2$).
  - Carrier Doppler frequency shift versus pseudorange change rate coherence verifier ($\epsilon_{\text{rate}} > 2.5\text{ m/s}$).
  - Receiver clock bias drag and time-pushing monitor ($|\dot{b}_{\text{clk}}| > 50\text{ ns/s}$, $|\Delta b_{\text{clk}}| > 100\text{ ns}$).
  - Constellation position split detector between GPS L1 and NavIC L5/S-band solutions ($> 35.0\text{ m}$).
- **NMEA-0183 & Keplerian Broadcast Ephemeris Verifier (`nmea_ephemeris.rs`)**:
  - NMEA-0183 sentence parsing and 8-bit XOR checksum verification (`$GPGGA`, `$GPRMC`, `$GPGSV`, `$GNGSA`, `$PIRNS`).
  - Keplerian orbital mechanics verifier for GPS Medium Earth Orbit (MEO) ($a \approx 26,559.7\text{ km}$, $e \le 0.03$, $i_0 \approx 55^\circ$) and India NavIC Geosynchronous / Geostationary Orbit (GSO/GEO) ($a \approx 42,164.2\text{ km}$, $e \le 0.03$).
- **Zero-Dependency Recursive JSON Engine (`json.rs`)**:
  - Fully recursive JSON lexer, parser, and serializer implemented without external crates.
- **10-Rule Deterministic PNT Security Posture Auditor (`auditor.rs`)**:
  - Evaluates system posture against normative rules `LH-GNSS-001` through `LH-GNSS-010`.
  - Standardized Logihertz Security Posture Score ($S_{\text{posture}} \in [0, 100]$) with status categorization: `HARDENED`, `ACCEPTABLE`, `DEGRADED`, and `NON-COMPLIANT`.
  - Exporters for ANSI terminal tables, Canonical JSON, and OASIS SARIF v2.1.0 (`exporters.rs`).
- **Production CLI (`lh-gps-spoof`)**:
  - `scan`: Audit GNSS receiver PNT security policy against the 10 normative rules.
  - `analyze-epochs`: Ingest and analyze multi-epoch GNSS/NavIC telemetry for spoofing anomalies.
  - `verify-nmea`: Validate NMEA-0183 stream checksums and sentence integrity.
  - `check-ephemeris`: Verify broadcast Keplerian orbital parameters against physical limits.
  - `--version` and `--help` options.
- **Zero External Dependencies**:
  - Pure Rust Standard Library (`std`) implementation strictly enforcing `#![forbid(unsafe_code)]`.
