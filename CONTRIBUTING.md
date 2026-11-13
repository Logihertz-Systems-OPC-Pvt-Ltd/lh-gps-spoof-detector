# Contributing to lh-gps-spoof-detector

Thank you for contributing to `lh-gps-spoof-detector` (`lh-gps-spoof`). This repository is part of the Logihertz 60-Tool Open-Source Ecosystem, providing a multi-band GNSS and India NavIC (IRNSS) spoofing detector, Doppler-pseudorange consistency analyzer, Keplerian ephemeris verifier, and 10-rule PNT security posture auditor.

## Core Architectural Mandates

1. **Zero External Crate Dependencies**:
   `Cargo.toml` must contain zero `[dependencies]` blocks. All orbital physics, Doppler-pseudorange math, NMEA-0183 XOR checksumming, recursive JSON parsing, and SARIF v2.1.0 generation must strictly utilize the Rust Standard Library (`std`).
2. **Safe Code Guarantee**:
   The entire crate strictly enforces `#![forbid(unsafe_code)]`. No `unsafe` blocks are permitted anywhere in the codebase.
3. **Multi-Constellation & Multi-Band Rigor**:
   All physical algorithms must support multi-band carrier frequencies (GPS L1, L2, L5 and NavIC L5, S-band) and handle edge cases such as low satellite counts or high geometric dilution of precision (HDOP).

## Development Workflow

### Prerequisites
- Rust 1.75+ (stable toolchain)
- Cargo

### Building from Source
```bash
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-gps-spoof-detector.git
cd lh-gps-spoof-detector
cargo build --release
```

### Running Tests and Linting
All code must pass formatting, Clippy analysis, and the unit test suite without any warnings:
```bash
# Verify formatting
cargo fmt --check

# Strict linting
cargo clippy --all-targets -- -D warnings

# Execute test suite
cargo test --verbose
```

## Pull Request Guidelines
- All new features or detection rules must include deterministic unit tests in `tests/integration_tests.rs`.
- Adhere to the Contributor Covenant Code of Conduct.
