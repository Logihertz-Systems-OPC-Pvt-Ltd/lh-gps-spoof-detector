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

//! Comprehensive integration test suite for `lh-gps-spoof-detector`.

use lh_gps_spoof_detector::auditor::{GnssAuditor, GnssPostureConfig};
use lh_gps_spoof_detector::exporters::Exporter;
use lh_gps_spoof_detector::gnss_physics::{
    AnomalySeverity, Constellation, FrequencyBand, GnssEpoch, GnssPhysicsAnalyzer, Position3D,
    SatelliteMeasurement, SpoofingAnomalyKind, FREQ_GPS_L1_HZ, FREQ_GPS_L2_HZ,
    FREQ_GPS_NAVIC_L5_HZ, FREQ_NAVIC_S_BAND_HZ, SPEED_OF_LIGHT_M_S,
};
use lh_gps_spoof_detector::json::{
    parse_json, to_canonical_json_string, to_pretty_json_string, JsonValue,
};
use lh_gps_spoof_detector::nmea_ephemeris::{
    analyze_nmea_stream, calculate_nmea_checksum, parse_ephemeris_json, parse_nmea_sentence,
    verify_ephemeris, verify_nmea_checksum, KeplerianEphemeris,
};

// ============================================================================
// 1. JSON Lexer, Parser, and Serializer Tests (12 tests)
// ============================================================================

#[test]
fn test_json_parse_primitives() {
    assert_eq!(parse_json("null").unwrap(), JsonValue::Null);
    assert_eq!(parse_json("true").unwrap(), JsonValue::Bool(true));
    assert_eq!(parse_json("false").unwrap(), JsonValue::Bool(false));
    assert_eq!(parse_json("42").unwrap(), JsonValue::Number(42.0));
    assert_eq!(parse_json("-17.5").unwrap(), JsonValue::Number(-17.5));
    assert_eq!(parse_json("1.25e2").unwrap(), JsonValue::Number(125.0));
    assert_eq!(
        parse_json("\"hello world\"").unwrap(),
        JsonValue::String("hello world".to_string())
    );
}

#[test]
fn test_json_parse_strings_with_escapes() {
    let s = "\"line1\\nline2\\tquote: \\\" \\\\ end\"";
    let val = parse_json(s).unwrap();
    assert_eq!(
        val,
        JsonValue::String("line1\nline2\tquote: \" \\ end".to_string())
    );
}

#[test]
fn test_json_parse_array() {
    let s = "[1, 2, \"test\", true, null]";
    let val = parse_json(s).unwrap();
    if let JsonValue::Array(arr) = val {
        assert_eq!(arr.len(), 5);
        assert_eq!(arr[0], JsonValue::Number(1.0));
        assert_eq!(arr[2], JsonValue::String("test".to_string()));
        assert_eq!(arr[3], JsonValue::Bool(true));
        assert_eq!(arr[4], JsonValue::Null);
    } else {
        panic!("Expected array");
    }
}

#[test]
fn test_json_parse_nested_object() {
    let s =
        r#"{"name": "GPS", "bands": ["L1", "L5"], "meta": {"active": true, "freq": 1575420000.0}}"#;
    let val = parse_json(s).unwrap();
    if let JsonValue::Object(map) = val {
        assert_eq!(map.get("name").unwrap().as_str().unwrap(), "GPS");
        let bands = map.get("bands").unwrap().as_array().unwrap();
        assert_eq!(bands.len(), 2);
        let meta = map.get("meta").unwrap().as_object().unwrap();
        assert!(meta.get("active").unwrap().as_bool().unwrap());
        assert_eq!(meta.get("freq").unwrap().as_f64().unwrap(), 1575420000.0);
    } else {
        panic!("Expected object");
    }
}

#[test]
fn test_json_syntax_error_unclosed_string() {
    assert!(parse_json("\"unclosed").is_err());
}

#[test]
fn test_json_syntax_error_unclosed_array() {
    assert!(parse_json("[1, 2, 3").is_err());
}

#[test]
fn test_json_syntax_error_unclosed_object() {
    assert!(parse_json("{\"key\": 1").is_err());
}

#[test]
fn test_json_syntax_error_trailing_comma() {
    assert!(parse_json("[1, 2,]").is_err());
}

#[test]
fn test_json_syntax_error_unexpected_token() {
    assert!(parse_json("invalid").is_err());
}

#[test]
fn test_json_canonical_serialization() {
    let mut map = std::collections::BTreeMap::new();
    map.insert("b".to_string(), JsonValue::Number(2.0));
    map.insert("a".to_string(), JsonValue::Number(1.0));
    let val = JsonValue::Object(map);
    let canonical = to_canonical_json_string(&val);
    assert_eq!(canonical, "{\"a\": 1, \"b\": 2}");
}

#[test]
fn test_json_pretty_serialization() {
    let mut map = std::collections::BTreeMap::new();
    map.insert("key".to_string(), JsonValue::String("value".to_string()));
    let val = JsonValue::Object(map);
    let pretty = to_pretty_json_string(&val);
    assert!(pretty.contains("  \"key\": \"value\""));
}

#[test]
fn test_json_empty_array_and_object() {
    assert_eq!(parse_json("[]").unwrap(), JsonValue::Array(Vec::new()));
    assert_eq!(
        parse_json("{}").unwrap(),
        JsonValue::Object(std::collections::BTreeMap::new())
    );
}

// ============================================================================
// 2. GNSS Physics, Constants & Math Tests (15 tests)
// ============================================================================

#[test]
fn test_physical_constants_exactness() {
    assert_eq!(SPEED_OF_LIGHT_M_S, 299_792_458.0);
    assert_eq!(FREQ_GPS_L1_HZ, 1_575_420_000.0);
    assert_eq!(FREQ_GPS_L2_HZ, 1_227_600_000.0);
    assert_eq!(FREQ_GPS_NAVIC_L5_HZ, 1_176_450_000.0);
    assert_eq!(FREQ_NAVIC_S_BAND_HZ, 2_492_028_000.0);
}

#[test]
fn test_constellation_parsing() {
    assert_eq!(Constellation::from_str("GPS"), Constellation::Gps);
    assert_eq!(Constellation::from_str("GP"), Constellation::Gps);
    assert_eq!(Constellation::from_str("NAVIC"), Constellation::NavIc);
    assert_eq!(Constellation::from_str("IRNSS"), Constellation::NavIc);
    assert_eq!(Constellation::from_str("GALILEO"), Constellation::Galileo);
    assert_eq!(Constellation::from_str("GLONASS"), Constellation::Glonass);
    assert_eq!(Constellation::from_str("XYZ"), Constellation::Unknown);
}

#[test]
fn test_frequency_band_nominal_frequencies() {
    let b_l1 = FrequencyBand::L1;
    let b_l2 = FrequencyBand::L2;
    let b_l5 = FrequencyBand::L5;
    let b_s = FrequencyBand::SBand;

    assert_eq!(
        b_l1.nominal_frequency_hz(Constellation::Gps),
        FREQ_GPS_L1_HZ
    );
    assert_eq!(
        b_l2.nominal_frequency_hz(Constellation::Gps),
        FREQ_GPS_L2_HZ
    );
    assert_eq!(
        b_l5.nominal_frequency_hz(Constellation::NavIc),
        FREQ_GPS_NAVIC_L5_HZ
    );
    assert_eq!(
        b_s.nominal_frequency_hz(Constellation::NavIc),
        FREQ_NAVIC_S_BAND_HZ
    );
}

#[test]
fn test_carrier_wavelengths() {
    let lambda_l1 = SPEED_OF_LIGHT_M_S / FREQ_GPS_L1_HZ;
    assert!((lambda_l1 - 0.19029367).abs() < 1e-6);

    let lambda_l5 = SPEED_OF_LIGHT_M_S / FREQ_GPS_NAVIC_L5_HZ;
    assert!((lambda_l5 - 0.25482805).abs() < 1e-6);

    let lambda_s = SPEED_OF_LIGHT_M_S / FREQ_NAVIC_S_BAND_HZ;
    assert!((lambda_s - 0.12030070).abs() < 1e-6);
}

#[test]
fn test_doppler_range_rate_calculation() {
    let meas = SatelliteMeasurement {
        sat_id: "G01".to_string(),
        constellation: Constellation::Gps,
        band: FrequencyBand::L1,
        carrier_freq_hz: FREQ_GPS_L1_HZ,
        pseudorange_m: 21_000_000.0,
        doppler_hz: 1000.0,
        cn0_dbhz: 42.0,
        elevation_deg: 45.0,
        azimuth_deg: 90.0,
    };

    let rate = meas.doppler_range_rate_m_s();
    let expected = -(SPEED_OF_LIGHT_M_S / FREQ_GPS_L1_HZ) * 1000.0;
    assert!((rate - expected).abs() < 1e-9);
}

#[test]
fn test_position_3d_distance_and_norm() {
    let p1 = Position3D::new(0.0, 0.0, 0.0);
    let p2 = Position3D::new(3.0, 4.0, 12.0);
    assert_eq!(p1.distance_to(&p2), 13.0);
    assert_eq!(p2.norm(), 13.0);
}

#[test]
fn test_cn0_surge_anomaly_trigger() {
    let ep = GnssEpoch {
        timestamp_sec: 1.0,
        receiver_clock_bias_ns: 0.0,
        agc_level_pct: 50.0,
        pv_solution: None,
        navic_solution: None,
        measurements: vec![SatelliteMeasurement {
            sat_id: "G01".to_string(),
            constellation: Constellation::Gps,
            band: FrequencyBand::L1,
            carrier_freq_hz: FREQ_GPS_L1_HZ,
            pseudorange_m: 20_000_000.0,
            doppler_hz: 0.0,
            cn0_dbhz: 56.2, // > 54.0 dB-Hz!
            elevation_deg: 50.0,
            azimuth_deg: 180.0,
        }],
    };

    let report = GnssPhysicsAnalyzer::analyze_epoch_sequence(&[ep]);
    assert!(report.is_spoofed);
    assert_eq!(report.anomalies[0].kind, SpoofingAnomalyKind::Cn0Surge);
    assert_eq!(report.anomalies[0].severity, AnomalySeverity::Critical);
}

#[test]
fn test_cn0_step_jump_anomaly() {
    let m1 = SatelliteMeasurement {
        sat_id: "G02".to_string(),
        constellation: Constellation::Gps,
        band: FrequencyBand::L1,
        carrier_freq_hz: FREQ_GPS_L1_HZ,
        pseudorange_m: 20_000_000.0,
        doppler_hz: 0.0,
        cn0_dbhz: 40.0,
        elevation_deg: 40.0,
        azimuth_deg: 100.0,
    };
    let mut m2 = m1.clone();
    m2.cn0_dbhz = 48.5; // Jump of +8.5 dB (> 6.0 dB)

    let ep1 = GnssEpoch {
        timestamp_sec: 10.0,
        receiver_clock_bias_ns: 0.0,
        agc_level_pct: 50.0,
        pv_solution: None,
        navic_solution: None,
        measurements: vec![m1],
    };
    let ep2 = GnssEpoch {
        timestamp_sec: 11.0,
        receiver_clock_bias_ns: 0.0,
        agc_level_pct: 50.0,
        pv_solution: None,
        navic_solution: None,
        measurements: vec![m2],
    };

    let report = GnssPhysicsAnalyzer::analyze_epoch_sequence(&[ep1, ep2]);
    assert!(report
        .anomalies
        .iter()
        .any(|a| a.kind == SpoofingAnomalyKind::Cn0StepJump));
}

#[test]
fn test_agc_compression_anomaly() {
    let m1 = SatelliteMeasurement {
        sat_id: "G01".to_string(),
        constellation: Constellation::Gps,
        band: FrequencyBand::L1,
        carrier_freq_hz: FREQ_GPS_L1_HZ,
        pseudorange_m: 20_000_000.0,
        doppler_hz: 0.0,
        cn0_dbhz: 40.0,
        elevation_deg: 40.0,
        azimuth_deg: 100.0,
    };
    let mut m2 = m1.clone();
    m2.cn0_dbhz = 44.5; // Mean C/N0 increases by 4.5 dB (>= 3.0 dB)

    let ep1 = GnssEpoch {
        timestamp_sec: 10.0,
        receiver_clock_bias_ns: 0.0,
        agc_level_pct: 60.0,
        pv_solution: None,
        navic_solution: None,
        measurements: vec![m1],
    };
    let ep2 = GnssEpoch {
        timestamp_sec: 11.0,
        receiver_clock_bias_ns: 0.0,
        agc_level_pct: 50.0, // AGC drops by 10% (>= 8.0%)
        pv_solution: None,
        navic_solution: None,
        measurements: vec![m2],
    };

    let report = GnssPhysicsAnalyzer::analyze_epoch_sequence(&[ep1, ep2]);
    assert!(report
        .anomalies
        .iter()
        .any(|a| a.kind == SpoofingAnomalyKind::AgcCompression));
}

#[test]
fn test_spatial_variance_authentic_distribution() {
    let measurements = vec![
        SatelliteMeasurement {
            sat_id: "G01".to_string(),
            constellation: Constellation::Gps,
            band: FrequencyBand::L1,
            carrier_freq_hz: FREQ_GPS_L1_HZ,
            pseudorange_m: 20_000_000.0,
            doppler_hz: 0.0,
            cn0_dbhz: 38.0,
            elevation_deg: 15.0,
            azimuth_deg: 30.0,
        },
        SatelliteMeasurement {
            sat_id: "G02".to_string(),
            constellation: Constellation::Gps,
            band: FrequencyBand::L1,
            carrier_freq_hz: FREQ_GPS_L1_HZ,
            pseudorange_m: 20_100_000.0,
            doppler_hz: 0.0,
            cn0_dbhz: 41.5,
            elevation_deg: 35.0,
            azimuth_deg: 120.0,
        },
        SatelliteMeasurement {
            sat_id: "G03".to_string(),
            constellation: Constellation::Gps,
            band: FrequencyBand::L1,
            carrier_freq_hz: FREQ_GPS_L1_HZ,
            pseudorange_m: 20_200_000.0,
            doppler_hz: 0.0,
            cn0_dbhz: 45.0,
            elevation_deg: 65.0,
            azimuth_deg: 210.0,
        },
        SatelliteMeasurement {
            sat_id: "G04".to_string(),
            constellation: Constellation::Gps,
            band: FrequencyBand::L1,
            carrier_freq_hz: FREQ_GPS_L1_HZ,
            pseudorange_m: 20_050_000.0,
            doppler_hz: 0.0,
            cn0_dbhz: 47.0,
            elevation_deg: 80.0,
            azimuth_deg: 300.0,
        },
    ];

    let ep = GnssEpoch {
        timestamp_sec: 1.0,
        receiver_clock_bias_ns: 0.0,
        agc_level_pct: 50.0,
        measurements,
        pv_solution: None,
        navic_solution: None,
    };

    let report = GnssPhysicsAnalyzer::analyze_epoch_sequence(&[ep]);
    assert!(!report
        .anomalies
        .iter()
        .any(|a| a.kind == SpoofingAnomalyKind::SpatialVarianceCollapse));
}

#[test]
fn test_spatial_variance_insufficient_elevation_spread_ignored() {
    // All satellites at same elevation -> elevation spread < 25 deg
    let measurements = vec![
        SatelliteMeasurement {
            sat_id: "G01".to_string(),
            constellation: Constellation::Gps,
            band: FrequencyBand::L1,
            carrier_freq_hz: FREQ_GPS_L1_HZ,
            pseudorange_m: 20_000_000.0,
            doppler_hz: 0.0,
            cn0_dbhz: 42.0,
            elevation_deg: 30.0,
            azimuth_deg: 30.0,
        },
        SatelliteMeasurement {
            sat_id: "G02".to_string(),
            constellation: Constellation::Gps,
            band: FrequencyBand::L1,
            carrier_freq_hz: FREQ_GPS_L1_HZ,
            pseudorange_m: 20_100_000.0,
            doppler_hz: 0.0,
            cn0_dbhz: 42.0,
            elevation_deg: 32.0,
            azimuth_deg: 120.0,
        },
        SatelliteMeasurement {
            sat_id: "G03".to_string(),
            constellation: Constellation::Gps,
            band: FrequencyBand::L1,
            carrier_freq_hz: FREQ_GPS_L1_HZ,
            pseudorange_m: 20_200_000.0,
            doppler_hz: 0.0,
            cn0_dbhz: 42.0,
            elevation_deg: 31.0,
            azimuth_deg: 210.0,
        },
        SatelliteMeasurement {
            sat_id: "G04".to_string(),
            constellation: Constellation::Gps,
            band: FrequencyBand::L1,
            carrier_freq_hz: FREQ_GPS_L1_HZ,
            pseudorange_m: 20_050_000.0,
            doppler_hz: 0.0,
            cn0_dbhz: 42.0,
            elevation_deg: 33.0,
            azimuth_deg: 300.0,
        },
    ];

    let ep = GnssEpoch {
        timestamp_sec: 1.0,
        receiver_clock_bias_ns: 0.0,
        agc_level_pct: 50.0,
        measurements,
        pv_solution: None,
        navic_solution: None,
    };

    let report = GnssPhysicsAnalyzer::analyze_epoch_sequence(&[ep]);
    assert!(!report
        .anomalies
        .iter()
        .any(|a| a.kind == SpoofingAnomalyKind::SpatialVarianceCollapse));
}

#[test]
fn test_clock_bias_drift_rate_anomaly() {
    let ep1 = GnssEpoch {
        timestamp_sec: 10.0,
        receiver_clock_bias_ns: 100.0,
        agc_level_pct: 50.0,
        pv_solution: None,
        navic_solution: None,
        measurements: vec![],
    };
    let ep2 = GnssEpoch {
        timestamp_sec: 11.0,
        receiver_clock_bias_ns: 175.0, // db/dt = 75.0 ns/s > 50.0 ns/s
        agc_level_pct: 50.0,
        pv_solution: None,
        navic_solution: None,
        measurements: vec![],
    };

    let report = GnssPhysicsAnalyzer::analyze_epoch_sequence(&[ep1, ep2]);
    assert!(report
        .anomalies
        .iter()
        .any(|a| a.kind == SpoofingAnomalyKind::ClockBiasDriftRate));
}

#[test]
fn test_clock_bias_step_jump_anomaly() {
    let ep1 = GnssEpoch {
        timestamp_sec: 10.0,
        receiver_clock_bias_ns: 50.0,
        agc_level_pct: 50.0,
        pv_solution: None,
        navic_solution: None,
        measurements: vec![],
    };
    let ep2 = GnssEpoch {
        timestamp_sec: 11.0,
        receiver_clock_bias_ns: 200.0, // jump = 150 ns > 100 ns
        agc_level_pct: 50.0,
        pv_solution: None,
        navic_solution: None,
        measurements: vec![],
    };

    let report = GnssPhysicsAnalyzer::analyze_epoch_sequence(&[ep1, ep2]);
    assert!(report
        .anomalies
        .iter()
        .any(|a| a.kind == SpoofingAnomalyKind::ClockBiasStepJump));
}

#[test]
fn test_multiconstellation_position_split_anomaly() {
    let ep = GnssEpoch {
        timestamp_sec: 50.0,
        receiver_clock_bias_ns: 0.0,
        agc_level_pct: 50.0,
        pv_solution: Some(Position3D::new(1000.0, 2000.0, 3000.0)),
        navic_solution: Some(Position3D::new(1000.0, 2000.0, 3045.0)), // distance = 45m > 35m
        measurements: vec![],
    };

    let report = GnssPhysicsAnalyzer::analyze_epoch_sequence(&[ep]);
    assert!(report.is_spoofed);
    assert!(report
        .anomalies
        .iter()
        .any(|a| a.kind == SpoofingAnomalyKind::MultiConstellationPositionSplit));
}

#[test]
fn test_parse_epochs_json_and_roundtrip() {
    let json_text = r#"{
        "epochs": [
            {
                "timestamp_sec": 12.5,
                "receiver_clock_bias_ns": 4.2,
                "agc_level_pct": 52.0,
                "pv_solution": { "x": 10.0, "y": 20.0, "z": 30.0 },
                "measurements": [
                    {
                        "sat_id": "G05",
                        "constellation": "GPS",
                        "band": "L1",
                        "pseudorange_m": 21000000.0,
                        "doppler_hz": 500.0,
                        "cn0_dbhz": 41.0,
                        "elevation_deg": 50.0,
                        "azimuth_deg": 180.0
                    }
                ]
            }
        ]
    }"#;

    let epochs = GnssPhysicsAnalyzer::parse_epochs_json(json_text).unwrap();
    assert_eq!(epochs.len(), 1);
    assert_eq!(epochs[0].measurements[0].sat_id, "G05");
    let rep = GnssPhysicsAnalyzer::analyze_epoch_sequence(&epochs);
    let json_val = GnssPhysicsAnalyzer::report_to_json(&rep);
    assert!(json_val.is_object());
}

// ============================================================================
// 3. NMEA-0183 & Keplerian Ephemeris Tests (15 tests)
// ============================================================================

#[test]
fn test_nmea_checksum_calculation_basic() {
    let sentence = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,";
    assert_eq!(calculate_nmea_checksum(sentence), 0x47);
}

#[test]
fn test_nmea_checksum_verify_valid() {
    let valid = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47";
    assert!(verify_nmea_checksum(valid).unwrap());
}

#[test]
fn test_nmea_checksum_verify_corrupt() {
    let corrupt = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*99";
    assert!(!verify_nmea_checksum(corrupt).unwrap());
}

#[test]
fn test_nmea_checksum_missing_delimiter() {
    let bad = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,47";
    assert!(verify_nmea_checksum(bad).is_err());
}

#[test]
fn test_nmea_parse_gpgga_full() {
    let line = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47";
    let rec = parse_nmea_sentence(line).unwrap();
    assert_eq!(rec.talker, "GP");
    assert_eq!(rec.sentence_type, "GGA");
    assert_eq!(rec.utc_time.unwrap(), "123519");
    assert!((rec.latitude.unwrap() - 48.1173).abs() < 1e-4);
    assert!((rec.longitude.unwrap() - 11.5166).abs() < 1e-4);
    assert_eq!(rec.fix_quality, Some(1));
    assert_eq!(rec.num_satellites, Some(8));
    assert_eq!(rec.hdop, Some(0.9));
    assert_eq!(rec.altitude_m, Some(545.4));
}

#[test]
fn test_nmea_parse_gprmc_full() {
    let line = "$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A";
    let rec = parse_nmea_sentence(line).unwrap();
    assert_eq!(rec.talker, "GP");
    assert_eq!(rec.sentence_type, "RMC");
    assert_eq!(rec.speed_knots, Some(22.4));
    assert!(rec.latitude.is_some());
}

#[test]
fn test_nmea_parse_southern_western_hemispheres() {
    let line = "$GPGGA,123519,3351.500,S,15112.500,W,1,06,1.2,10.0,M,0.0,M,,*24";
    let rec = parse_nmea_sentence(line).unwrap();
    assert!(rec.latitude.unwrap() < 0.0);
    assert!(rec.longitude.unwrap() < 0.0);
}

#[test]
fn test_nmea_parse_proprietary_pirns() {
    let line = "$PIRNS,NAV,01,55.0,180.0,43.1,02,52.0,195.0,41.6*26";
    let rec = parse_nmea_sentence(line).unwrap();
    assert_eq!(rec.talker, "P");
    assert_eq!(rec.sentence_type, "IRNS");
    assert!(rec.is_valid_checksum);
}

#[test]
fn test_analyze_nmea_stream_authentic() {
    let stream = r#"
$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47
$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A
"#;
    let rep = analyze_nmea_stream(stream);
    assert_eq!(rep.total_sentences, 2);
    assert_eq!(rep.valid_checksums, 2);
    assert_eq!(rep.invalid_checksums, 0);
    assert!(rep.is_authentic);
}

#[test]
fn test_analyze_nmea_stream_with_forgery() {
    let stream = r#"
$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47
$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*00
"#;
    let rep = analyze_nmea_stream(stream);
    assert_eq!(rep.total_sentences, 2);
    assert_eq!(rep.valid_checksums, 1);
    assert_eq!(rep.invalid_checksums, 1);
    assert!(!rep.is_authentic);
    assert_eq!(rep.anomalies.len(), 1);
}

#[test]
fn test_keplerian_gps_valid_meo_bounds() {
    let eph = KeplerianEphemeris {
        sat_id: "G14".to_string(),
        constellation: Constellation::Gps,
        epoch_toe_sec: 432000.0,
        sqrt_a: 5153.65, // ~26,560 km
        eccentricity: 0.008,
        inclination_rad: 0.9599, // ~55 deg
        omega_rad: 1.0,
        omega_dot_rad_s: -8.0e-9,
        mean_anomaly_rad: 0.5,
        delta_n_rad_s: 3.5e-9,
        af0_s: 0.0,
        af1_s_s: 0.0,
        af2_s_s2: 0.0,
    };
    let res = verify_ephemeris(&eph);
    assert!(res.is_valid);
    assert!(res.violations.is_empty());
}

#[test]
fn test_keplerian_gps_invalid_semi_major_axis() {
    let eph = KeplerianEphemeris {
        sat_id: "G14".to_string(),
        constellation: Constellation::Gps,
        epoch_toe_sec: 432000.0,
        sqrt_a: 5000.0, // a = 25,000,000 m < 26,400,000 m
        eccentricity: 0.008,
        inclination_rad: 0.9599,
        omega_rad: 1.0,
        omega_dot_rad_s: -8.0e-9,
        mean_anomaly_rad: 0.5,
        delta_n_rad_s: 3.5e-9,
        af0_s: 0.0,
        af1_s_s: 0.0,
        af2_s_s2: 0.0,
    };
    let res = verify_ephemeris(&eph);
    assert!(!res.is_valid);
    assert!(res.violations[0].contains("Semi-major axis"));
}

#[test]
fn test_keplerian_gps_invalid_eccentricity_and_inclination() {
    let eph = KeplerianEphemeris {
        sat_id: "G14".to_string(),
        constellation: Constellation::Gps,
        epoch_toe_sec: 432000.0,
        sqrt_a: 5153.65,
        eccentricity: 0.08,    // > 0.03
        inclination_rad: 0.40, // < 0.85 rad
        omega_rad: 1.0,
        omega_dot_rad_s: -8.0e-9,
        mean_anomaly_rad: 0.5,
        delta_n_rad_s: 3.5e-9,
        af0_s: 0.0,
        af1_s_s: 0.0,
        af2_s_s2: 0.0,
    };
    let res = verify_ephemeris(&eph);
    assert!(!res.is_valid);
    assert_eq!(res.violations.len(), 2);
}

#[test]
fn test_keplerian_navic_valid_geo_gso() {
    let eph = KeplerianEphemeris {
        sat_id: "I02".to_string(),
        constellation: Constellation::NavIc,
        epoch_toe_sec: 432000.0,
        sqrt_a: 6493.4, // a = 42,164,243 m
        eccentricity: 0.002,
        inclination_rad: 0.5061, // ~29 deg
        omega_rad: 0.8,
        omega_dot_rad_s: 0.0,
        mean_anomaly_rad: 0.0,
        delta_n_rad_s: 0.0,
        af0_s: 0.0,
        af1_s_s: 0.0,
        af2_s_s2: 0.0,
    };
    let res = verify_ephemeris(&eph);
    assert!(res.is_valid);
    assert!(res.violations.is_empty());
}

#[test]
fn test_parse_ephemeris_json_valid() {
    let json_text = r#"{
        "ephemeris": [
            {
                "sat_id": "G01",
                "constellation": "GPS",
                "sqrt_a": 5153.65,
                "eccentricity": 0.005,
                "inclination_rad": 0.9599
            }
        ]
    }"#;
    let list = parse_ephemeris_json(json_text).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].sat_id, "G01");
}

// ============================================================================
// 4. Posture Auditor & 10 Rules Tests (15 tests)
// ============================================================================

#[test]
fn test_auditor_all_pass_score_100() {
    let cfg = GnssPostureConfig::default();
    let rep = GnssAuditor::audit_posture(&cfg);
    assert_eq!(rep.score, 100);
    assert_eq!(rep.passed_rules, 10);
    assert_eq!(rep.failed_rules, 0);
    assert_eq!(rep.total_deductions, 0);
    assert!(rep.verdict.contains("HARDENED"));
}

#[test]
fn test_auditor_all_fail_score_0() {
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
        elevation_mask_deg: 5.0,
        authenticated_rtcm: false,
        secure_nmea_binding: false,
        ins_holdover_failover_enabled: false,
        forensic_event_logging_enabled: false,
    };
    let rep = GnssAuditor::audit_posture(&cfg);
    assert_eq!(rep.score, 0);
    assert_eq!(rep.passed_rules, 0);
    assert_eq!(rep.failed_rules, 10);
    assert_eq!(rep.total_deductions, 124);
    assert!(rep.verdict.contains("VULNERABLE"));
}

#[test]
fn test_auditor_rule_1_navic_diversity() {
    let cfg = GnssPostureConfig {
        navic_irnss_enabled: false,
        ..Default::default()
    };
    let rep = GnssAuditor::audit_posture(&cfg);
    assert_eq!(rep.score, 75);
    let r1 = rep.rules.iter().find(|r| r.id == "LH-GNSS-001").unwrap();
    assert!(!r1.passed);
    assert_eq!(r1.deduction, 25);
}

#[test]
fn test_auditor_rule_2_nma() {
    let cfg = GnssPostureConfig {
        nma_enabled: false,
        ..Default::default()
    };
    let rep = GnssAuditor::audit_posture(&cfg);
    assert_eq!(rep.score, 75);
    let r2 = rep.rules.iter().find(|r| r.id == "LH-GNSS-002").unwrap();
    assert!(!r2.passed);
    assert_eq!(r2.deduction, 25);
}

#[test]
fn test_auditor_rule_3_cn0_surge_and_agc() {
    let cfg = GnssPostureConfig {
        agc_compression_monitor_enabled: false,
        ..Default::default()
    };
    let rep = GnssAuditor::audit_posture(&cfg);
    assert_eq!(rep.score, 75);
    let r3 = rep.rules.iter().find(|r| r.id == "LH-GNSS-003").unwrap();
    assert!(!r3.passed);
    assert_eq!(r3.deduction, 25);
}

#[test]
fn test_auditor_rule_4_doppler_pseudorange() {
    let cfg = GnssPostureConfig {
        doppler_pseudorange_rate_check_enabled: false,
        ..Default::default()
    };
    let rep = GnssAuditor::audit_posture(&cfg);
    assert_eq!(rep.score, 90);
    let r4 = rep.rules.iter().find(|r| r.id == "LH-GNSS-004").unwrap();
    assert!(!r4.passed);
    assert_eq!(r4.deduction, 10);
}

#[test]
fn test_auditor_rule_5_clock_drift() {
    let cfg = GnssPostureConfig {
        clock_bias_drift_guard_enabled: false,
        ..Default::default()
    };
    let rep = GnssAuditor::audit_posture(&cfg);
    assert_eq!(rep.score, 90);
    let r5 = rep.rules.iter().find(|r| r.id == "LH-GNSS-005").unwrap();
    assert!(!r5.passed);
    assert_eq!(r5.deduction, 10);
}

#[test]
fn test_auditor_rule_6_ins_kalman() {
    let cfg = GnssPostureConfig {
        ins_kalman_coupling_enabled: false,
        ..Default::default()
    };
    let rep = GnssAuditor::audit_posture(&cfg);
    assert_eq!(rep.score, 90);
    let r6 = rep.rules.iter().find(|r| r.id == "LH-GNSS-006").unwrap();
    assert!(!r6.passed);
    assert_eq!(r6.deduction, 10);
}

#[test]
fn test_auditor_rule_7_keplerian() {
    let cfg = GnssPostureConfig {
        keplerian_ephemeris_check_enabled: false,
        ..Default::default()
    };
    let rep = GnssAuditor::audit_posture(&cfg);
    assert_eq!(rep.score, 90);
    let r7 = rep.rules.iter().find(|r| r.id == "LH-GNSS-007").unwrap();
    assert!(!r7.passed);
    assert_eq!(r7.deduction, 10);
}

#[test]
fn test_auditor_rule_8_elevation_mask_low() {
    let cfg = GnssPostureConfig {
        elevation_mask_deg: 8.0, // < 10.0 deg
        ..Default::default()
    };
    let rep = GnssAuditor::audit_posture(&cfg);
    assert_eq!(rep.score, 96);
    let r8 = rep.rules.iter().find(|r| r.id == "LH-GNSS-008").unwrap();
    assert!(!r8.passed);
    assert_eq!(r8.deduction, 4);
}

#[test]
fn test_auditor_rule_9_rtcm_insecure() {
    let cfg = GnssPostureConfig {
        authenticated_rtcm: false,
        ..Default::default()
    };
    let rep = GnssAuditor::audit_posture(&cfg);
    assert_eq!(rep.score, 96);
    let r9 = rep.rules.iter().find(|r| r.id == "LH-GNSS-009").unwrap();
    assert!(!r9.passed);
    assert_eq!(r9.deduction, 4);
}

#[test]
fn test_auditor_rule_10_forensic_logging() {
    let cfg = GnssPostureConfig {
        forensic_event_logging_enabled: false,
        ..Default::default()
    };
    let rep = GnssAuditor::audit_posture(&cfg);
    assert_eq!(rep.score, 99);
    let r10 = rep.rules.iter().find(|r| r.id == "LH-GNSS-010").unwrap();
    assert!(!r10.passed);
    assert_eq!(r10.deduction, 1);
}

#[test]
fn test_auditor_parse_config_json() {
    let json_text = r#"{
        "multi_constellation_enabled": true,
        "navic_irnss_enabled": true,
        "elevation_mask_deg": 15.0
    }"#;
    let cfg = GnssAuditor::parse_config_json(json_text).unwrap();
    assert!(cfg.multi_constellation_enabled);
    assert!(cfg.navic_irnss_enabled);
    assert_eq!(cfg.elevation_mask_deg, 15.0);
}

#[test]
fn test_auditor_parse_config_json_invalid() {
    assert!(GnssAuditor::parse_config_json("[1, 2, 3]").is_err());
}

#[test]
fn test_auditor_report_to_json_structure() {
    let cfg = GnssPostureConfig::default();
    let rep = GnssAuditor::audit_posture(&cfg);
    let json_val = GnssAuditor::report_to_json(&rep);
    assert!(json_val.is_object());
    let map = json_val.as_object().unwrap();
    assert_eq!(map.get("score").unwrap().as_f64().unwrap(), 100.0);
}

// ============================================================================
// 5. Exporters (ANSI Table, JSON, SARIF v2.1.0) Tests (12 tests)
// ============================================================================

#[test]
fn test_exporter_posture_table_output() {
    let cfg = GnssPostureConfig::default();
    let rep = GnssAuditor::audit_posture(&cfg);
    let table = Exporter::format_posture_table(&rep);
    assert!(table.contains("LOGIHERTZ RESILIENT PNT & GNSS SPOOFING POSTURE AUDITOR"));
    assert!(table.contains("LH-GNSS-001"));
    assert!(table.contains("PASS"));
}

#[test]
fn test_exporter_posture_table_vulnerable_remediation() {
    let cfg = GnssPostureConfig {
        nma_enabled: false,
        ..Default::default()
    };
    let rep = GnssAuditor::audit_posture(&cfg);
    let table = Exporter::format_posture_table(&rep);
    assert!(table.contains("FAIL"));
    assert!(table.contains("Remediation:"));
}

#[test]
fn test_exporter_epoch_table_clean() {
    let rep = GnssPhysicsAnalyzer::analyze_epoch_sequence(&[]);
    let table = Exporter::format_epoch_analysis_table(&rep);
    assert!(table.contains("GNSS MULTI-BAND & NAVIC TELEMETRY SPOOFING ANALYSIS"));
    assert!(table.contains("AUTHENTIC"));
}

#[test]
fn test_exporter_epoch_table_with_anomalies() {
    let ep = GnssEpoch {
        timestamp_sec: 1.0,
        receiver_clock_bias_ns: 0.0,
        agc_level_pct: 50.0,
        pv_solution: None,
        navic_solution: None,
        measurements: vec![SatelliteMeasurement {
            sat_id: "G01".to_string(),
            constellation: Constellation::Gps,
            band: FrequencyBand::L1,
            carrier_freq_hz: FREQ_GPS_L1_HZ,
            pseudorange_m: 20_000_000.0,
            doppler_hz: 0.0,
            cn0_dbhz: 57.0,
            elevation_deg: 50.0,
            azimuth_deg: 180.0,
        }],
    };
    let rep = GnssPhysicsAnalyzer::analyze_epoch_sequence(&[ep]);
    let table = Exporter::format_epoch_analysis_table(&rep);
    assert!(table.contains("CRITICAL SPOOFING DETECTED"));
    assert!(table.contains("ANOM-CN0-SURGE"));
}

#[test]
fn test_exporter_nmea_table() {
    let stream = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47";
    let rep = analyze_nmea_stream(stream);
    let table = Exporter::format_nmea_table(&rep);
    assert!(table.contains("NMEA-0183 STREAM & XOR CHECKSUM INTEGRITY REPORT"));
    assert!(table.contains("AUTHENTIC & VERIFIED"));
}

#[test]
fn test_exporter_ephemeris_table() {
    let eph = KeplerianEphemeris {
        sat_id: "G01".to_string(),
        constellation: Constellation::Gps,
        epoch_toe_sec: 432000.0,
        sqrt_a: 5153.65,
        eccentricity: 0.005,
        inclination_rad: 0.9599,
        omega_rad: 1.0,
        omega_dot_rad_s: -8.0e-9,
        mean_anomaly_rad: 0.5,
        delta_n_rad_s: 3.5e-9,
        af0_s: 0.0,
        af1_s_s: 0.0,
        af2_s_s2: 0.0,
    };
    let res = verify_ephemeris(&eph);
    let table = Exporter::format_ephemeris_table(&[res]);
    assert!(table.contains("KEPLERIAN BROADCAST EPHEMERIS ORBITAL PHYSICS VERIFIER"));
    assert!(table.contains("VALID"));
}

#[test]
fn test_exporter_sarif_schema_and_version() {
    let cfg = GnssPostureConfig::default();
    let rep = GnssAuditor::audit_posture(&cfg);
    let sarif = Exporter::format_sarif(&rep);
    assert!(sarif.contains("sarif-schema-2.1.0.json"));
    assert!(sarif.contains("\"version\": \"2.1.0\""));
    assert!(sarif.contains("lh-gps-spoof"));
}

#[test]
fn test_exporter_sarif_vulnerable_results() {
    let cfg = GnssPostureConfig {
        nma_enabled: false,
        ..Default::default()
    };
    let rep = GnssAuditor::audit_posture(&cfg);
    let sarif = Exporter::format_sarif(&rep);
    assert!(sarif.contains("\"ruleId\": \"LH-GNSS-002\""));
    assert!(sarif.contains("\"level\": \"error\""));
}

#[test]
fn test_exporter_posture_json() {
    let cfg = GnssPostureConfig::default();
    let rep = GnssAuditor::audit_posture(&cfg);
    let json_str = Exporter::format_posture_json(&rep, true);
    assert!(json_str.contains("\"score\": 100"));
}

#[test]
fn test_exporter_epoch_json() {
    let rep = GnssPhysicsAnalyzer::analyze_epoch_sequence(&[]);
    let json_str = Exporter::format_epoch_json(&rep, false);
    assert!(json_str.contains("\"is_spoofed\": false"));
}

#[test]
fn test_exporter_ephemeris_json() {
    let eph = KeplerianEphemeris {
        sat_id: "I01".to_string(),
        constellation: Constellation::NavIc,
        epoch_toe_sec: 432000.0,
        sqrt_a: 6493.4,
        eccentricity: 0.002,
        inclination_rad: 0.5061,
        omega_rad: 0.8,
        omega_dot_rad_s: 0.0,
        mean_anomaly_rad: 0.0,
        delta_n_rad_s: 0.0,
        af0_s: 0.0,
        af1_s_s: 0.0,
        af2_s_s2: 0.0,
    };
    let res = verify_ephemeris(&eph);
    let json_str = Exporter::format_ephemeris_json(&[res], true);
    assert!(json_str.contains("\"sat_id\": \"I01\""));
    assert!(json_str.contains("\"is_valid\": true"));
}

#[test]
fn test_fixtures_end_to_end_evaluation() {
    let hard_content = std::fs::read_to_string("fixtures/hardened_gnss_policy.json").unwrap();
    let hard_cfg = GnssAuditor::parse_config_json(&hard_content).unwrap();
    let hard_rep = GnssAuditor::audit_posture(&hard_cfg);
    assert_eq!(hard_rep.score, 100);

    let vuln_content = std::fs::read_to_string("fixtures/vulnerable_gnss_policy.json").unwrap();
    let vuln_cfg = GnssAuditor::parse_config_json(&vuln_content).unwrap();
    let vuln_rep = GnssAuditor::audit_posture(&vuln_cfg);
    assert_eq!(vuln_rep.score, 0);

    let epochs_content = std::fs::read_to_string("fixtures/sample_gnss_epochs.json").unwrap();
    let epochs = GnssPhysicsAnalyzer::parse_epochs_json(&epochs_content).unwrap();
    let epoch_rep = GnssPhysicsAnalyzer::analyze_epoch_sequence(&epochs);
    assert!(epoch_rep.is_spoofed);

    let nmea_content = std::fs::read_to_string("fixtures/sample_nmea_stream.txt").unwrap();
    let nmea_rep = analyze_nmea_stream(&nmea_content);
    assert!(nmea_rep.is_authentic);

    let eph_content = std::fs::read_to_string("fixtures/sample_ephemeris.json").unwrap();
    let eph_list = parse_ephemeris_json(&eph_content).unwrap();
    assert_eq!(eph_list.len(), 3);
    assert!(verify_ephemeris(&eph_list[0]).is_valid);
    assert!(verify_ephemeris(&eph_list[1]).is_valid);
    assert!(!verify_ephemeris(&eph_list[2]).is_valid);
}
