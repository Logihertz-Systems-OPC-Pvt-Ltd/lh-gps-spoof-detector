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

//! `lh-gps-spoof`: Production-grade CLI binary for Multi-Band GNSS & India NavIC (IRNSS)
//! Spoofing Detection, Doppler-Pseudorange Consistency, Keplerian Ephemeris Physics Verification,
//! and 10-Rule PNT Security Posture Auditing.

#![forbid(unsafe_code)]

use lh_gps_spoof_detector::auditor::GnssAuditor;
use lh_gps_spoof_detector::exporters::Exporter;
use lh_gps_spoof_detector::gnss_physics::GnssPhysicsAnalyzer;
use lh_gps_spoof_detector::nmea_ephemeris::{
    analyze_nmea_stream, parse_ephemeris_json, verify_ephemeris,
};
use std::env;
use std::fs;
use std::process;

const VERSION_STRING: &str = "lh-gps-spoof 0.1.0 (Logihertz Resilient PNT Security Engine)";

fn print_version() {
    println!("{}", VERSION_STRING);
}

fn print_help() {
    println!(
        r#"{}

USAGE:
    lh-gps-spoof <SUBCOMMAND> [OPTIONS] <FILE>

SUBCOMMANDS:
    scan <config.json>            Evaluate 10-rule GNSS & NavIC security posture against policy JSON
    analyze-epochs <epochs.json>  Analyze multi-epoch GNSS telemetry for C/N0 surge, AGC compression,
                                  spatial variance collapse, Doppler rate mismatches & NavIC split
    verify-nmea <stream.nmea>     Parse NMEA-0183 stream, verify 8-bit XOR checksums & extract fixes
    check-ephemeris <eph.json>    Verify Keplerian broadcast ephemeris orbital physics for GPS & NavIC

OPTIONS:
    --format <table|json|sarif>   Output formatting (default: table)
    -h, --help                    Print help information
    -V, --version                 Print version information

EXAMPLES:
    # Audit GNSS receiver configuration against 10-rule posture:
    lh-gps-spoof scan fixtures/hardened_gnss_policy.json --format table
    lh-gps-spoof scan fixtures/vulnerable_gnss_policy.json --format sarif

    # Analyze multi-band GPS/NavIC epoch telemetry for active spoofing:
    lh-gps-spoof analyze-epochs fixtures/sample_gnss_epochs.json --format table

    # Verify NMEA-0183 stream checksum integrity:
    lh-gps-spoof verify-nmea fixtures/sample_nmea_stream.txt

    # Validate Keplerian broadcast ephemeris parameters:
    lh-gps-spoof check-ephemeris fixtures/sample_ephemeris.json --format table
"#,
        VERSION_STRING
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        process::exit(1);
    }

    let first_arg = args[1].as_str();
    if first_arg == "-V" || first_arg == "--version" || first_arg == "version" {
        print_version();
        process::exit(0);
    }

    if first_arg == "-h" || first_arg == "--help" || first_arg == "help" {
        print_help();
        process::exit(0);
    }

    let subcommand = first_arg;
    let mut file_path = None;
    let mut format = "table".to_string();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                if i + 1 < args.len() {
                    format = args[i + 1].to_lowercase();
                    i += 1;
                } else {
                    eprintln!("Error: --format requires an argument (table, json, or sarif)");
                    process::exit(2);
                }
            }
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            }
            "-V" | "--version" => {
                print_version();
                process::exit(0);
            }
            arg if !arg.starts_with('-') && file_path.is_none() => {
                file_path = Some(arg.to_string());
            }
            other => {
                eprintln!("Error: Unknown argument '{}'", other);
                process::exit(2);
            }
        }
        i += 1;
    }

    let path = match file_path {
        Some(p) => p,
        None => {
            eprintln!(
                "Error: Missing required file path for subcommand '{}'",
                subcommand
            );
            eprintln!("Run 'lh-gps-spoof --help' for usage instructions.");
            process::exit(2);
        }
    };

    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Error reading file '{}': {}", path, err);
            process::exit(2);
        }
    };

    match subcommand {
        "scan" => {
            let config = match GnssAuditor::parse_config_json(&content) {
                Ok(cfg) => cfg,
                Err(err) => {
                    eprintln!("Error parsing posture configuration: {}", err);
                    process::exit(2);
                }
            };

            let report = GnssAuditor::audit_posture(&config);

            match format.as_str() {
                "json" => println!("{}", Exporter::format_posture_json(&report, true)),
                "sarif" => println!("{}", Exporter::format_sarif(&report)),
                _ => print!("{}", Exporter::format_posture_table(&report)),
            }

            if report.score < 60 || report.failed_rules > 0 {
                process::exit(1);
            } else {
                process::exit(0);
            }
        }
        "analyze-epochs" => {
            let epochs = match GnssPhysicsAnalyzer::parse_epochs_json(&content) {
                Ok(eps) => eps,
                Err(err) => {
                    eprintln!("Error parsing GNSS epoch stream JSON: {}", err);
                    process::exit(2);
                }
            };

            let report = GnssPhysicsAnalyzer::analyze_epoch_sequence(&epochs);

            match format.as_str() {
                "json" => println!("{}", Exporter::format_epoch_json(&report, true)),
                _ => print!("{}", Exporter::format_epoch_analysis_table(&report)),
            }

            if report.is_spoofed {
                process::exit(1);
            } else {
                process::exit(0);
            }
        }
        "verify-nmea" => {
            let report = analyze_nmea_stream(&content);

            match format.as_str() {
                "json" => {
                    let mut map = std::collections::BTreeMap::new();
                    map.insert(
                        "total_sentences".to_string(),
                        lh_gps_spoof_detector::json::JsonValue::Number(
                            report.total_sentences as f64,
                        ),
                    );
                    map.insert(
                        "valid_checksums".to_string(),
                        lh_gps_spoof_detector::json::JsonValue::Number(
                            report.valid_checksums as f64,
                        ),
                    );
                    map.insert(
                        "invalid_checksums".to_string(),
                        lh_gps_spoof_detector::json::JsonValue::Number(
                            report.invalid_checksums as f64,
                        ),
                    );
                    map.insert(
                        "is_authentic".to_string(),
                        lh_gps_spoof_detector::json::JsonValue::Bool(report.is_authentic),
                    );
                    let anom_arr: Vec<lh_gps_spoof_detector::json::JsonValue> = report
                        .anomalies
                        .iter()
                        .map(|a| lh_gps_spoof_detector::json::JsonValue::String(a.clone()))
                        .collect();
                    map.insert(
                        "anomalies".to_string(),
                        lh_gps_spoof_detector::json::JsonValue::Array(anom_arr),
                    );
                    println!(
                        "{}",
                        lh_gps_spoof_detector::json::to_pretty_json_string(
                            &lh_gps_spoof_detector::json::JsonValue::Object(map)
                        )
                    );
                }
                _ => print!("{}", Exporter::format_nmea_table(&report)),
            }

            if !report.is_authentic {
                process::exit(1);
            } else {
                process::exit(0);
            }
        }
        "check-ephemeris" => {
            let ephemeris_list = match parse_ephemeris_json(&content) {
                Ok(list) => list,
                Err(err) => {
                    eprintln!("Error parsing ephemeris JSON: {}", err);
                    process::exit(2);
                }
            };

            let mut results = Vec::new();
            let mut any_violations = false;

            for eph in &ephemeris_list {
                let res = verify_ephemeris(eph);
                if !res.is_valid {
                    any_violations = true;
                }
                results.push(res);
            }

            match format.as_str() {
                "json" => println!("{}", Exporter::format_ephemeris_json(&results, true)),
                _ => print!("{}", Exporter::format_ephemeris_table(&results)),
            }

            if any_violations {
                process::exit(1);
            } else {
                process::exit(0);
            }
        }
        unknown => {
            eprintln!("Error: Unknown subcommand '{}'", unknown);
            eprintln!("Run 'lh-gps-spoof --help' for usage instructions.");
            process::exit(2);
        }
    }
}
