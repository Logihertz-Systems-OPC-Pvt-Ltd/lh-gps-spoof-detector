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

//! 10-Rule Resilient PNT & GNSS Spoofing Security Posture Auditor.
//! Evaluates receiver firmware configuration against multi-band NavIC/GPS diversity,
//! NMA authentication, C/N0 & AGC compression triggers, Doppler-pseudorange consistency,
//! clock slew boundaries, and INS holdover failover.

use crate::gnss_physics::AnomalySeverity;
use crate::json::{parse_json, JsonValue};
use std::collections::BTreeMap;

/// Configuration parameters for receiver GNSS security posture audit.
#[derive(Debug, Clone, PartialEq)]
pub struct GnssPostureConfig {
    pub multi_constellation_enabled: bool,
    pub navic_irnss_enabled: bool,
    pub multi_band_diversity: bool,
    pub nma_enabled: bool,
    pub cn0_surge_monitor_enabled: bool,
    pub agc_compression_monitor_enabled: bool,
    pub doppler_pseudorange_rate_check_enabled: bool,
    pub clock_bias_drift_guard_enabled: bool,
    pub ins_kalman_coupling_enabled: bool,
    pub keplerian_ephemeris_check_enabled: bool,
    pub spatial_variance_check_enabled: bool,
    pub elevation_mask_deg: f64,
    pub authenticated_rtcm: bool,
    pub secure_nmea_binding: bool,
    pub ins_holdover_failover_enabled: bool,
    pub forensic_event_logging_enabled: bool,
}

impl Default for GnssPostureConfig {
    fn default() -> Self {
        Self {
            multi_constellation_enabled: true,
            navic_irnss_enabled: true,
            multi_band_diversity: true,
            nma_enabled: true,
            cn0_surge_monitor_enabled: true,
            agc_compression_monitor_enabled: true,
            doppler_pseudorange_rate_check_enabled: true,
            clock_bias_drift_guard_enabled: true,
            ins_kalman_coupling_enabled: true,
            keplerian_ephemeris_check_enabled: true,
            spatial_variance_check_enabled: true,
            elevation_mask_deg: 10.0,
            authenticated_rtcm: true,
            secure_nmea_binding: true,
            ins_holdover_failover_enabled: true,
            forensic_event_logging_enabled: true,
        }
    }
}

/// Evaluated posture rule result.
#[derive(Debug, Clone, PartialEq)]
pub struct PostureRule {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: AnomalySeverity,
    pub deduction: u32,
    pub cwe: &'static str,
    pub passed: bool,
    pub remediation: &'static str,
    pub message: String,
}

/// Overall security posture assessment report.
#[derive(Debug, Clone, PartialEq)]
pub struct PostureReport {
    pub score: u32,
    pub passed_rules: usize,
    pub failed_rules: usize,
    pub total_deductions: u32,
    pub rules: Vec<PostureRule>,
    pub verdict: String,
}

/// Resilient GNSS Posture Auditor.
pub struct GnssAuditor;

impl GnssAuditor {
    /// Evaluates receiver configuration against the 10 Logihertz GNSS Security Posture Rules.
    pub fn audit_posture(cfg: &GnssPostureConfig) -> PostureReport {
        let mut rules = Vec::with_capacity(10);
        let mut total_deductions: u32 = 0;

        // Rule 1: LH-GNSS-001 (CRITICAL, 25, CWE-290)
        let r1_passed =
            cfg.multi_constellation_enabled && cfg.navic_irnss_enabled && cfg.multi_band_diversity;
        let r1_msg = if r1_passed {
            "Multi-constellation GPS and India NavIC (IRNSS) multi-band diversity (L1/L5/S-band) active.".to_string()
        } else {
            "Single-frequency or single-constellation receiver configuration lacks India NavIC or multi-band redundancy.".to_string()
        };
        if !r1_passed {
            total_deductions += 25;
        }
        rules.push(PostureRule {
            id: "LH-GNSS-001",
            title: "Multi-Constellation & India NavIC (IRNSS) Diversity",
            severity: AnomalySeverity::Critical,
            deduction: 25,
            cwe: "CWE-290",
            passed: r1_passed,
            remediation: "Enable simultaneous tracking of GPS (L1/L5) and India NavIC (IRNSS L5/S-band) to detect single-band spoofers.",
            message: r1_msg,
        });

        // Rule 2: LH-GNSS-002 (CRITICAL, 25, CWE-345)
        let r2_passed = cfg.nma_enabled;
        let r2_msg = if r2_passed {
            "Cryptographic Navigation Message Authentication (NMA / OS-NMA / NavIC L1C-NMA) enabled.".to_string()
        } else {
            "Navigation Message Authentication (NMA) disabled; receiver vulnerable to forged ephemeris and clock parameters.".to_string()
        };
        if !r2_passed {
            total_deductions += 25;
        }
        rules.push(PostureRule {
            id: "LH-GNSS-002",
            title: "Cryptographic Navigation Message Authentication (NMA)",
            severity: AnomalySeverity::Critical,
            deduction: 25,
            cwe: "CWE-345",
            passed: r2_passed,
            remediation: "Activate OS-NMA, Chimera, or NavIC L1C-NMA cryptographic broadcast signature verification.",
            message: r2_msg,
        });

        // Rule 3: LH-GNSS-003 (CRITICAL, 25, CWE-682)
        let r3_passed = cfg.cn0_surge_monitor_enabled && cfg.agc_compression_monitor_enabled;
        let r3_msg = if r3_passed {
            "C/N0 absolute overpower surge (>54 dB-Hz) and RF AGC compression drop monitors active."
                .to_string()
        } else {
            "C/N0 surge detector (>54 dB-Hz) or RF front-end AGC compression monitor disabled."
                .to_string()
        };
        if !r3_passed {
            total_deductions += 25;
        }
        rules.push(PostureRule {
            id: "LH-GNSS-003",
            title: "C/N0 Overpower Surge & AGC Compression Monitoring",
            severity: AnomalySeverity::Critical,
            deduction: 25,
            cwe: "CWE-682",
            passed: r3_passed,
            remediation: "Enable front-end AGC telemetry analysis and reject signals exceeding physical Earth-surface C/N0 limits (>54 dB-Hz).",
            message: r3_msg,
        });

        // Rule 4: LH-GNSS-004 (HIGH, 10, CWE-682)
        let r4_passed = cfg.doppler_pseudorange_rate_check_enabled;
        let r4_msg = if r4_passed {
            "Carrier Doppler vs. pseudorange rate cross-coherence validation active (|Δv| <= 2.5 m/s).".to_string()
        } else {
            "Carrier Doppler vs. code pseudorange rate consistency monitor disabled.".to_string()
        };
        if !r4_passed {
            total_deductions += 10;
        }
        rules.push(PostureRule {
            id: "LH-GNSS-004",
            title: "Carrier Doppler vs. Pseudorange Rate Consistency",
            severity: AnomalySeverity::High,
            deduction: 10,
            cwe: "CWE-682",
            passed: r4_passed,
            remediation: "Enforce continuous cross-validation between carrier phase Doppler velocity and delta-pseudorange rate.",
            message: r4_msg,
        });

        // Rule 5: LH-GNSS-005 (HIGH, 10, CWE-367)
        let r5_passed = cfg.clock_bias_drift_guard_enabled;
        let r5_msg = if r5_passed {
            "Receiver clock bias slew rate guard active (|db/dt| <= 50 ns/s, |Δb| <= 100 ns)."
                .to_string()
        } else {
            "Receiver clock bias slew rate guard disabled; receiver susceptible to clock dragging attacks.".to_string()
        };
        if !r5_passed {
            total_deductions += 10;
        }
        rules.push(PostureRule {
            id: "LH-GNSS-005",
            title: "Receiver Clock Bias Slew Rate & Step Guard",
            severity: AnomalySeverity::High,
            deduction: 10,
            cwe: "CWE-367",
            passed: r5_passed,
            remediation: "Bound receiver clock bias variations to physical crystal oscillator limits (50 ns/s) and flag discontinuities.",
            message: r5_msg,
        });

        // Rule 6: LH-GNSS-006 (HIGH, 10, CWE-682)
        let r6_passed = cfg.ins_kalman_coupling_enabled;
        let r6_msg = if r6_passed {
            "Tightly/deeply coupled INS/IMU Kalman filter innovation check active.".to_string()
        } else {
            "Coupled INS/IMU Kalman filter innovation check disabled; no kinematic sanity validation.".to_string()
        };
        if !r6_passed {
            total_deductions += 10;
        }
        rules.push(PostureRule {
            id: "LH-GNSS-006",
            title: "Coupled INS/IMU Kalman Innovation Verification",
            severity: AnomalySeverity::High,
            deduction: 10,
            cwe: "CWE-682",
            passed: r6_passed,
            remediation: "Integrate GNSS receiver with an inertial measurement unit (IMU) and validate measurement innovations in the Kalman filter.",
            message: r6_msg,
        });

        // Rule 7: LH-GNSS-007 (HIGH, 10, CWE-20)
        let r7_passed = cfg.keplerian_ephemeris_check_enabled;
        let r7_msg = if r7_passed {
            "Keplerian broadcast ephemeris orbital physics and semi-major axis bounds checking active.".to_string()
        } else {
            "Keplerian broadcast ephemeris orbital parameter validation disabled.".to_string()
        };
        if !r7_passed {
            total_deductions += 10;
        }
        rules.push(PostureRule {
            id: "LH-GNSS-007",
            title: "Keplerian Broadcast Ephemeris Orbital Physics Bounds",
            severity: AnomalySeverity::High,
            deduction: 10,
            cwe: "CWE-20",
            passed: r7_passed,
            remediation: "Validate decoded broadcast ephemeris parameters against physical orbital mechanics bounds for MEO and GEO/GSO satellites.",
            message: r7_msg,
        });

        // Rule 8: LH-GNSS-008 (MEDIUM, 4, CWE-682)
        let r8_passed = cfg.spatial_variance_check_enabled && cfg.elevation_mask_deg >= 10.0;
        let r8_msg = if r8_passed {
            format!(
                "Spatial C/N0 variance collapse detector active with elevation mask {:.1}° (>= 10°).",
                cfg.elevation_mask_deg
            )
        } else {
            format!(
                "Spatial C/N0 variance collapse check disabled or elevation mask {:.1}° is below 10°.",
                cfg.elevation_mask_deg
            )
        };
        if !r8_passed {
            total_deductions += 4;
        }
        rules.push(PostureRule {
            id: "LH-GNSS-008",
            title: "Inter-Satellite Spatial C/N0 Variance Collapse & Elevation Mask",
            severity: AnomalySeverity::Medium,
            deduction: 4,
            cwe: "CWE-682",
            passed: r8_passed,
            remediation: "Enable inter-satellite C/N0 variance monitoring (flagging σ² < 0.5 dB²) and enforce an elevation mask of at least 10°.",
            message: r8_msg,
        });

        // Rule 9: LH-GNSS-009 (MEDIUM, 4, CWE-306)
        let r9_passed = cfg.authenticated_rtcm && cfg.secure_nmea_binding;
        let r9_msg = if r9_passed {
            "Differential RTCM corrections cryptographically authenticated and NMEA bound securely."
                .to_string()
        } else {
            "Unauthenticated external RTCM corrections accepted or NMEA bound to insecure public network interface.".to_string()
        };
        if !r9_passed {
            total_deductions += 4;
        }
        rules.push(PostureRule {
            id: "LH-GNSS-009",
            title: "Authenticated Differential RTCM & Protected NMEA Telemetry",
            severity: AnomalySeverity::Medium,
            deduction: 4,
            cwe: "CWE-306",
            passed: r9_passed,
            remediation: "Authenticate RTCM 3.x correction streams and isolate NMEA serial/Ethernet sockets from untrusted networks.",
            message: r9_msg,
        });

        // Rule 10: LH-GNSS-010 (LOW, 1, CWE-778)
        let r10_passed = cfg.ins_holdover_failover_enabled && cfg.forensic_event_logging_enabled;
        let r10_msg = if r10_passed {
            "Autonomous INS dead-reckoning holdover on spoofing and forensic logging active."
                .to_string()
        } else {
            "Missing autonomous INS holdover failover upon spoofing detection or RF forensic logging disabled.".to_string()
        };
        if !r10_passed {
            total_deductions += 1;
        }
        rules.push(PostureRule {
            id: "LH-GNSS-010",
            title: "Resilient INS Dead-Reckoning Holdover & Forensic Logging",
            severity: AnomalySeverity::Low,
            deduction: 1,
            cwe: "CWE-778",
            passed: r10_passed,
            remediation: "Configure automatic failover to inertial dead-reckoning upon spoof detection and log RF audit telemetry.",
            message: r10_msg,
        });

        let score = 100_u32.saturating_sub(total_deductions);
        let passed_rules = rules.iter().filter(|r| r.passed).count();
        let failed_rules = rules.len() - passed_rules;

        let verdict = if score >= 90 {
            "HARDENED (Resilient PNT Architecture)".to_string()
        } else if score >= 60 {
            "DEFICIENT (Elevated Spoofing Vulnerability)".to_string()
        } else {
            "VULNERABLE (Critical Civil GNSS Exploitation Risk)".to_string()
        };

        PostureReport {
            score,
            passed_rules,
            failed_rules,
            total_deductions,
            rules,
            verdict,
        }
    }

    /// Parses posture configuration from a JSON string.
    pub fn parse_config_json(json_str: &str) -> Result<GnssPostureConfig, String> {
        let root = parse_json(json_str)?;
        let obj = match root {
            JsonValue::Object(map) => map,
            _ => return Err("Expected JSON object for posture configuration".to_string()),
        };

        let mut cfg = GnssPostureConfig::default();

        if let Some(v) = obj
            .get("multi_constellation_enabled")
            .and_then(|v| v.as_bool())
        {
            cfg.multi_constellation_enabled = v;
        }
        if let Some(v) = obj.get("navic_irnss_enabled").and_then(|v| v.as_bool()) {
            cfg.navic_irnss_enabled = v;
        }
        if let Some(v) = obj.get("multi_band_diversity").and_then(|v| v.as_bool()) {
            cfg.multi_band_diversity = v;
        }
        if let Some(v) = obj.get("nma_enabled").and_then(|v| v.as_bool()) {
            cfg.nma_enabled = v;
        }
        if let Some(v) = obj
            .get("cn0_surge_monitor_enabled")
            .and_then(|v| v.as_bool())
        {
            cfg.cn0_surge_monitor_enabled = v;
        }
        if let Some(v) = obj
            .get("agc_compression_monitor_enabled")
            .and_then(|v| v.as_bool())
        {
            cfg.agc_compression_monitor_enabled = v;
        }
        if let Some(v) = obj
            .get("doppler_pseudorange_rate_check_enabled")
            .and_then(|v| v.as_bool())
        {
            cfg.doppler_pseudorange_rate_check_enabled = v;
        }
        if let Some(v) = obj
            .get("clock_bias_drift_guard_enabled")
            .and_then(|v| v.as_bool())
        {
            cfg.clock_bias_drift_guard_enabled = v;
        }
        if let Some(v) = obj
            .get("ins_kalman_coupling_enabled")
            .and_then(|v| v.as_bool())
        {
            cfg.ins_kalman_coupling_enabled = v;
        }
        if let Some(v) = obj
            .get("keplerian_ephemeris_check_enabled")
            .and_then(|v| v.as_bool())
        {
            cfg.keplerian_ephemeris_check_enabled = v;
        }
        if let Some(v) = obj
            .get("spatial_variance_check_enabled")
            .and_then(|v| v.as_bool())
        {
            cfg.spatial_variance_check_enabled = v;
        }
        if let Some(v) = obj.get("elevation_mask_deg").and_then(|v| v.as_f64()) {
            cfg.elevation_mask_deg = v;
        }
        if let Some(v) = obj.get("authenticated_rtcm").and_then(|v| v.as_bool()) {
            cfg.authenticated_rtcm = v;
        }
        if let Some(v) = obj.get("secure_nmea_binding").and_then(|v| v.as_bool()) {
            cfg.secure_nmea_binding = v;
        }
        if let Some(v) = obj
            .get("ins_holdover_failover_enabled")
            .and_then(|v| v.as_bool())
        {
            cfg.ins_holdover_failover_enabled = v;
        }
        if let Some(v) = obj
            .get("forensic_event_logging_enabled")
            .and_then(|v| v.as_bool())
        {
            cfg.forensic_event_logging_enabled = v;
        }

        Ok(cfg)
    }

    /// Serializes a posture report to JSON.
    pub fn report_to_json(report: &PostureReport) -> JsonValue {
        let mut root = BTreeMap::new();
        root.insert("score".to_string(), JsonValue::Number(report.score as f64));
        root.insert(
            "passed_rules".to_string(),
            JsonValue::Number(report.passed_rules as f64),
        );
        root.insert(
            "failed_rules".to_string(),
            JsonValue::Number(report.failed_rules as f64),
        );
        root.insert(
            "total_deductions".to_string(),
            JsonValue::Number(report.total_deductions as f64),
        );
        root.insert(
            "verdict".to_string(),
            JsonValue::String(report.verdict.clone()),
        );

        let mut rules_arr = Vec::new();
        for r in &report.rules {
            let mut r_obj = BTreeMap::new();
            r_obj.insert("id".to_string(), JsonValue::String(r.id.to_string()));
            r_obj.insert("title".to_string(), JsonValue::String(r.title.to_string()));
            r_obj.insert(
                "severity".to_string(),
                JsonValue::String(r.severity.as_str().to_string()),
            );
            r_obj.insert(
                "deduction".to_string(),
                JsonValue::Number(r.deduction as f64),
            );
            r_obj.insert("cwe".to_string(), JsonValue::String(r.cwe.to_string()));
            r_obj.insert("passed".to_string(), JsonValue::Bool(r.passed));
            r_obj.insert("message".to_string(), JsonValue::String(r.message.clone()));
            r_obj.insert(
                "remediation".to_string(),
                JsonValue::String(r.remediation.to_string()),
            );
            rules_arr.push(JsonValue::Object(r_obj));
        }

        root.insert("rules".to_string(), JsonValue::Array(rules_arr));
        JsonValue::Object(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardened_config_score_100() {
        let cfg = GnssPostureConfig::default();
        let report = GnssAuditor::audit_posture(&cfg);
        assert_eq!(report.score, 100);
        assert_eq!(report.passed_rules, 10);
        assert_eq!(report.failed_rules, 0);
        assert_eq!(report.total_deductions, 0);
        assert!(report.verdict.contains("HARDENED"));
    }

    #[test]
    fn test_vulnerable_config_score_0() {
        let cfg = GnssPostureConfig {
            multi_constellation_enabled: false,
            navic_irnss_enabled: false,
            multi_band_diversity: false,
            nma_enabled: false,
            cn0_surge_monitor_enabled: false,
            agc_compression_monitor_enabled: false,
            doppler_pseudorange_rate_check_enabled: false,
            clock_bias_drift_guard_enabled: false,
            ins_kalman_coupling_enabled: false,
            keplerian_ephemeris_check_enabled: false,
            spatial_variance_check_enabled: false,
            elevation_mask_deg: 5.0, // < 10 deg!
            authenticated_rtcm: false,
            secure_nmea_binding: false,
            ins_holdover_failover_enabled: false,
            forensic_event_logging_enabled: false,
        };

        let report = GnssAuditor::audit_posture(&cfg);
        assert_eq!(report.score, 0);
        assert_eq!(report.passed_rules, 0);
        assert_eq!(report.failed_rules, 10);
        assert_eq!(report.total_deductions, 124);
        assert!(report.verdict.contains("VULNERABLE"));
    }

    #[test]
    fn test_partial_config_score() {
        let cfg = GnssPostureConfig {
            navic_irnss_enabled: false, // Fails Rule 1 (-25)
            nma_enabled: false,         // Fails Rule 2 (-25)
            ..Default::default()
        };
        let report = GnssAuditor::audit_posture(&cfg);
        assert_eq!(report.score, 50);
        assert_eq!(report.passed_rules, 8);
        assert_eq!(report.failed_rules, 2);
        assert_eq!(report.total_deductions, 50);
    }
}
