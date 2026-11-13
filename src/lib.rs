// Copyright 2026 Logihertz Systems OPC Pvt. Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Logihertz Multi-Band GNSS & India NavIC (IRNSS) Spoofing Detector.
//!
//! A zero-dependency, pure Rust library providing:
//! - Multi-band carrier Doppler vs. pseudorange-rate consistency analysis
//! - Carrier-to-Noise (C/N0) overpower surge and RF front-end AGC compression monitoring
//! - Inter-satellite spatial C/N0 variance collapse detection
//! - Receiver clock bias slew rate and step jump monitoring
//! - Dual-solution position split detection (GPS L1 vs India NavIC L5/S-band)
//! - NMEA-0183 XOR checksum calculation and sentence telemetry parsing
//! - Keplerian broadcast ephemeris orbital mechanics verification
//! - 10-Rule Resilient PNT security posture auditing (SARIF v2.1.0, JSON, ANSI table)

#![forbid(unsafe_code)]

pub mod auditor;
pub mod exporters;
pub mod gnss_physics;
pub mod json;
pub mod nmea_ephemeris;

pub use auditor::{GnssAuditor, GnssPostureConfig, PostureReport, PostureRule};
pub use exporters::Exporter;
pub use gnss_physics::{
    AnomalySeverity, Constellation, EpochAnalysisReport, FrequencyBand, GnssEpoch,
    GnssPhysicsAnalyzer, Position3D, SatelliteMeasurement, SpoofingAnomaly, SpoofingAnomalyKind,
};
pub use nmea_ephemeris::{
    analyze_nmea_stream, calculate_nmea_checksum, parse_ephemeris_json, parse_nmea_sentence,
    verify_ephemeris, verify_nmea_checksum, EphemerisVerificationResult, KeplerianEphemeris,
    NmeaSentenceRecord, NmeaStreamReport,
};
