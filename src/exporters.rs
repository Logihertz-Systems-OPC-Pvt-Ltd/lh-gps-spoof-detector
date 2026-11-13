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

//! ANSI terminal table, Canonical JSON, and OASIS SARIF v2.1.0 exporters
//! for posture audits, epoch telemetry analysis, and ephemeris verification.

use crate::auditor::{GnssAuditor, PostureReport};
use crate::gnss_physics::{AnomalySeverity, EpochAnalysisReport, GnssPhysicsAnalyzer};
use crate::json::{to_canonical_json_string, to_pretty_json_string, JsonValue};
use crate::nmea_ephemeris::{
    ephemeris_report_to_json, EphemerisVerificationResult, NmeaStreamReport,
};
use std::collections::BTreeMap;

/// ANSI color and style helpers.
pub struct Ansi;

impl Ansi {
    pub const RESET: &'static str = "\x1b[0m";
    pub const BOLD: &'static str = "\x1b[1m";
    pub const RED: &'static str = "\x1b[31m";
    pub const GREEN: &'static str = "\x1b[32m";
    pub const YELLOW: &'static str = "\x1b[33m";
    pub const BLUE: &'static str = "\x1b[34m";
    pub const CYAN: &'static str = "\x1b[36m";
    pub const WHITE_BOLD: &'static str = "\x1b[1;37m";
    pub const BG_RED: &'static str = "\x1b[41;37;1m";
    pub const BG_GREEN: &'static str = "\x1b[42;30;1m";
}

/// Exporter for generating human-readable and machine-actionable reports.
pub struct Exporter;

impl Exporter {
    /// Formats a posture audit report as an ANSI terminal table.
    pub fn format_posture_table(report: &PostureReport) -> String {
        let mut out = String::new();

        let (score_color, score_bg) = if report.score >= 90 {
            (Ansi::GREEN, Ansi::BG_GREEN)
        } else if report.score >= 60 {
            (Ansi::YELLOW, Ansi::YELLOW)
        } else {
            (Ansi::RED, Ansi::BG_RED)
        };

        out.push_str(&format!(
            "\n{}{}========================================================================================{}\n",
            Ansi::BOLD,
            Ansi::CYAN,
            Ansi::RESET
        ));
        out.push_str(&format!(
            "{}  LOGIHERTZ RESILIENT PNT & GNSS SPOOFING POSTURE AUDITOR (lh-gps-spoof v0.1.0){}\n",
            Ansi::WHITE_BOLD,
            Ansi::RESET
        ));
        out.push_str(&format!(
            "{}{}========================================================================================{}\n",
            Ansi::BOLD,
            Ansi::CYAN,
            Ansi::RESET
        ));

        out.push_str(&format!(
            "  Overall Posture Score: {} {} / 100 {}   Verdict: {}{}{}\n",
            score_bg,
            report.score,
            Ansi::RESET,
            score_color,
            report.verdict,
            Ansi::RESET
        ));
        out.push_str(&format!(
            "  Rules Passed: {}{}/10{}  |  Rules Failed: {}{}/10{}  |  Total Deductions: -{}\n\n",
            Ansi::GREEN,
            report.passed_rules,
            Ansi::RESET,
            if report.failed_rules > 0 {
                Ansi::RED
            } else {
                Ansi::GREEN
            },
            report.failed_rules,
            Ansi::RESET,
            report.total_deductions
        ));

        out.push_str("┌─────────────┬──────────┬────────┬───────┬──────────────────────────────────────────────┐\n");
        out.push_str("│ Rule ID     │ Severity │ Status │ Deduct│ Rule Description                             │\n");
        out.push_str("├─────────────┼──────────┼────────┼───────┼──────────────────────────────────────────────┤\n");

        for r in &report.rules {
            let status_badge = if r.passed {
                format!("{} PASS {}", Ansi::GREEN, Ansi::RESET)
            } else {
                format!("{} FAIL {}", Ansi::RED, Ansi::RESET)
            };

            let sev_color = match r.severity {
                AnomalySeverity::Critical => Ansi::RED,
                AnomalySeverity::High => Ansi::YELLOW,
                AnomalySeverity::Medium => Ansi::CYAN,
                AnomalySeverity::Low => Ansi::BLUE,
            };

            let title_truncated = if r.title.len() > 44 {
                format!("{}...", &r.title[..41])
            } else {
                format!("{:<44}", r.title)
            };

            out.push_str(&format!(
                "│ {:<11} │ {}{:<8}{} │ {} │ -{:<4} │ {} │\n",
                r.id,
                sev_color,
                r.severity.as_str(),
                Ansi::RESET,
                status_badge,
                if r.passed { 0 } else { r.deduction },
                title_truncated
            ));

            if !r.passed {
                out.push_str(&format!(
                    "│             └─► {}Remediation:{} {:<57} │\n",
                    Ansi::BOLD,
                    Ansi::RESET,
                    if r.remediation.len() > 57 {
                        format!("{}...", &r.remediation[..54])
                    } else {
                        format!("{:<57}", r.remediation)
                    }
                ));
            }
        }

        out.push_str("└─────────────┴──────────┴────────┴───────┴──────────────────────────────────────────────┘\n\n");
        out
    }

    /// Formats an epoch sequence analysis report as an ANSI terminal table.
    pub fn format_epoch_analysis_table(report: &EpochAnalysisReport) -> String {
        let mut out = String::new();

        let (status_color, status_text) = if report.is_spoofed {
            (Ansi::RED, "CRITICAL SPOOFING DETECTED")
        } else if !report.anomalies.is_empty() {
            (Ansi::YELLOW, "ANOMALIES PRESENT (UNAUTHENTIC)")
        } else {
            (Ansi::GREEN, "AUTHENTIC GNSS STREAM")
        };

        out.push_str(&format!(
            "\n{}{}========================================================================================{}\n",
            Ansi::BOLD,
            Ansi::CYAN,
            Ansi::RESET
        ));
        out.push_str(&format!(
            "{}  GNSS MULTI-BAND & NAVIC TELEMETRY SPOOFING ANALYSIS (lh-gps-spoof v0.1.0){}\n",
            Ansi::WHITE_BOLD,
            Ansi::RESET
        ));
        out.push_str(&format!(
            "{}{}========================================================================================{}\n",
            Ansi::BOLD,
            Ansi::CYAN,
            Ansi::RESET
        ));

        out.push_str(&format!(
            "  Status: {}{}{}  |  Spoofing Probability: {:.1}%\n",
            status_color,
            status_text,
            Ansi::RESET,
            report.spoofing_probability * 100.0
        ));
        out.push_str(&format!(
            "  Total Epochs: {}  |  Monitored Satellites: {}  |  Anomalies Triggered: {}\n",
            report.total_epochs,
            report.evaluated_satellites,
            report.anomalies.len()
        ));
        out.push_str(&format!("  Summary: {}\n\n", report.summary));

        if report.anomalies.is_empty() {
            out.push_str(&format!(
                "  {}✔ All carrier Doppler, C/N0, AGC, and NavIC multi-band checks passed nominal physical bounds.{}\n\n",
                Ansi::GREEN,
                Ansi::RESET
            ));
            return out;
        }

        out.push_str("┌──────────┬──────────────────────────┬──────────┬────────┬──────────┬──────────┬────────────────────────────────┐\n");
        out.push_str("│ Time (s) │ Anomaly Code             │ Severity │ Sat ID │ Observed │Threshold │ Metric Unit                    │\n");
        out.push_str("├──────────┼──────────────────────────┼──────────┼────────┼──────────┼──────────┼────────────────────────────────┤\n");

        for a in &report.anomalies {
            let sat_str = a.sat_id.as_deref().unwrap_or("ALL");
            let sev_color = match a.severity {
                AnomalySeverity::Critical => Ansi::RED,
                AnomalySeverity::High => Ansi::YELLOW,
                AnomalySeverity::Medium => Ansi::CYAN,
                AnomalySeverity::Low => Ansi::BLUE,
            };

            out.push_str(&format!(
                "│ {:>8.2} │ {:<24} │ {}{:<8}{} │ {:<6} │ {:>8.2} │ {:>8.2} │ {:<30} │\n",
                a.epoch_time,
                a.kind.code(),
                sev_color,
                a.severity.as_str(),
                Ansi::RESET,
                sat_str,
                a.observed_value,
                a.threshold_value,
                format!("{:<30}", a.unit)
            ));
        }

        out.push_str("└──────────┴──────────────────────────┴──────────┴────────┴──────────┴──────────┴────────────────────────────────┘\n\n");
        out
    }

    /// Formats NMEA stream report into an ANSI table.
    pub fn format_nmea_table(report: &NmeaStreamReport) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "\n{}{}========================================================================================{}\n",
            Ansi::BOLD,
            Ansi::CYAN,
            Ansi::RESET
        ));
        out.push_str(&format!(
            "{}  NMEA-0183 STREAM & XOR CHECKSUM INTEGRITY REPORT (lh-gps-spoof v0.1.0){}\n",
            Ansi::WHITE_BOLD,
            Ansi::RESET
        ));
        out.push_str(&format!(
            "{}{}========================================================================================{}\n",
            Ansi::BOLD,
            Ansi::CYAN,
            Ansi::RESET
        ));

        let status_color = if report.is_authentic {
            Ansi::GREEN
        } else {
            Ansi::RED
        };
        let status_text = if report.is_authentic {
            "AUTHENTIC & VERIFIED"
        } else {
            "FORGED / CORRUPT CHECKSUMS"
        };

        out.push_str(&format!(
            "  Stream Integrity: {}{}{}  |  Total Sentences: {}\n",
            status_color,
            status_text,
            Ansi::RESET,
            report.total_sentences
        ));
        out.push_str(&format!(
            "  Valid Checksums: {}{}   Invalid Checksums: {}{}\n",
            report.valid_checksums,
            Ansi::RESET,
            report.invalid_checksums,
            Ansi::RESET
        ));
        out.push_str(&format!(
            "  Talkers Detected: {:?}   Sentence Types: {:?}\n\n",
            report.talkers_detected, report.sentence_types_detected
        ));

        if !report.anomalies.is_empty() {
            out.push_str(&format!(
                "{}Checksum Corruptions / Anomalies:{}\n",
                Ansi::RED,
                Ansi::RESET
            ));
            for anom in &report.anomalies {
                out.push_str(&format!("  - {}\n", anom));
            }
            out.push('\n');
        }

        out
    }

    /// Formats Keplerian ephemeris verification results into an ANSI table.
    pub fn format_ephemeris_table(results: &[EphemerisVerificationResult]) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "\n{}{}========================================================================================{}\n",
            Ansi::BOLD,
            Ansi::CYAN,
            Ansi::RESET
        ));
        out.push_str(&format!(
            "{}  KEPLERIAN BROADCAST EPHEMERIS ORBITAL PHYSICS VERIFIER (lh-gps-spoof v0.1.0){}\n",
            Ansi::WHITE_BOLD,
            Ansi::RESET
        ));
        out.push_str(&format!(
            "{}{}========================================================================================{}\n",
            Ansi::BOLD,
            Ansi::CYAN,
            Ansi::RESET
        ));

        out.push_str("┌────────┬───────────────┬─────────────────────────────┬───────────────┬────────────┐\n");
        out.push_str("│ Sat ID │ Constellation │ Orbit Classification        │ Semi-Major (m)│ Status     │\n");
        out.push_str("├────────┼───────────────┼─────────────────────────────┼───────────────┼────────────┤\n");

        for r in results {
            let status_badge = if r.is_valid {
                format!("{} VALID {}", Ansi::GREEN, Ansi::RESET)
            } else {
                format!("{} VIOL  {}", Ansi::RED, Ansi::RESET)
            };

            out.push_str(&format!(
                "│ {:<6} │ {:<13} │ {:<27} │ {:>13.1} │ {} │\n",
                r.sat_id,
                r.constellation.as_str(),
                if r.orbit_type.len() > 27 {
                    &r.orbit_type[..27]
                } else {
                    &r.orbit_type
                },
                r.semi_major_axis_m,
                status_badge
            ));

            for viol in &r.violations {
                out.push_str(&format!(
                    "│        └─► {}Violation:{} {:<58} │\n",
                    Ansi::RED,
                    Ansi::RESET,
                    if viol.len() > 58 {
                        format!("{}...", &viol[..55])
                    } else {
                        format!("{:<58}", viol)
                    }
                ));
            }
        }

        out.push_str("└────────┴───────────────┴─────────────────────────────┴───────────────┴────────────┘\n\n");
        out
    }

    /// Formats posture report as OASIS SARIF v2.1.0 JSON string.
    pub fn format_sarif(report: &PostureReport) -> String {
        let mut root = BTreeMap::new();
        root.insert("$schema".to_string(), JsonValue::String("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string()));
        root.insert(
            "version".to_string(),
            JsonValue::String("2.1.0".to_string()),
        );

        let mut driver = BTreeMap::new();
        driver.insert(
            "name".to_string(),
            JsonValue::String("lh-gps-spoof".to_string()),
        );
        driver.insert(
            "version".to_string(),
            JsonValue::String("0.1.0".to_string()),
        );
        driver.insert(
            "informationUri".to_string(),
            JsonValue::String(
                "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-gps-spoof-detector"
                    .to_string(),
            ),
        );

        let mut rules_arr = Vec::new();
        for r in &report.rules {
            let mut r_obj = BTreeMap::new();
            r_obj.insert("id".to_string(), JsonValue::String(r.id.to_string()));
            r_obj.insert("name".to_string(), JsonValue::String(r.title.to_string()));
            let mut short_desc = BTreeMap::new();
            short_desc.insert("text".to_string(), JsonValue::String(r.title.to_string()));
            r_obj.insert(
                "shortDescription".to_string(),
                JsonValue::Object(short_desc),
            );
            let mut help = BTreeMap::new();
            help.insert(
                "text".to_string(),
                JsonValue::String(format!("CWE: {}. Remediation: {}", r.cwe, r.remediation)),
            );
            r_obj.insert("help".to_string(), JsonValue::Object(help));
            rules_arr.push(JsonValue::Object(r_obj));
        }
        driver.insert("rules".to_string(), JsonValue::Array(rules_arr));

        let mut tool = BTreeMap::new();
        tool.insert("driver".to_string(), JsonValue::Object(driver));

        let mut results_arr = Vec::new();
        for r in &report.rules {
            if !r.passed {
                let mut res = BTreeMap::new();
                res.insert("ruleId".to_string(), JsonValue::String(r.id.to_string()));
                let level = match r.severity {
                    AnomalySeverity::Critical | AnomalySeverity::High => "error",
                    AnomalySeverity::Medium => "warning",
                    AnomalySeverity::Low => "note",
                };
                res.insert("level".to_string(), JsonValue::String(level.to_string()));
                let mut msg = BTreeMap::new();
                msg.insert("text".to_string(), JsonValue::String(r.message.clone()));
                res.insert("message".to_string(), JsonValue::Object(msg));
                results_arr.push(JsonValue::Object(res));
            }
        }

        let mut run = BTreeMap::new();
        run.insert("tool".to_string(), JsonValue::Object(tool));
        run.insert("results".to_string(), JsonValue::Array(results_arr));

        root.insert(
            "runs".to_string(),
            JsonValue::Array(vec![JsonValue::Object(run)]),
        );
        to_pretty_json_string(&JsonValue::Object(root))
    }

    /// Formats posture report as Canonical JSON string.
    pub fn format_posture_json(report: &PostureReport, pretty: bool) -> String {
        let val = GnssAuditor::report_to_json(report);
        if pretty {
            to_pretty_json_string(&val)
        } else {
            to_canonical_json_string(&val)
        }
    }

    /// Formats epoch analysis report as Canonical JSON string.
    pub fn format_epoch_json(report: &EpochAnalysisReport, pretty: bool) -> String {
        let val = GnssPhysicsAnalyzer::report_to_json(report);
        if pretty {
            to_pretty_json_string(&val)
        } else {
            to_canonical_json_string(&val)
        }
    }

    /// Formats ephemeris report as JSON string.
    pub fn format_ephemeris_json(results: &[EphemerisVerificationResult], pretty: bool) -> String {
        let val = ephemeris_report_to_json(results);
        if pretty {
            to_pretty_json_string(&val)
        } else {
            to_canonical_json_string(&val)
        }
    }
}
