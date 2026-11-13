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

//! NMEA-0183 8-bit XOR checksum calculator, sentence parser ($GPGGA, $GPRMC,
//! $GPGSV, $GNGSA, $PIRNS), and Keplerian broadcast ephemeris orbital physics verifier.

use crate::gnss_physics::Constellation;
use crate::json::{parse_json, JsonValue};
use std::collections::BTreeMap;

/// Calculates the standard NMEA-0183 8-bit XOR checksum of a sentence.
/// Computes the bitwise XOR of all characters between '$' (or '!') and '*' (exclusive).
pub fn calculate_nmea_checksum(sentence: &str) -> u8 {
    let mut xor_sum: u8 = 0;
    let mut started = false;

    for b in sentence.bytes() {
        if b == b'$' || b == b'!' {
            started = true;
            xor_sum = 0;
            continue;
        }
        if b == b'*' {
            break;
        }
        if started {
            xor_sum ^= b;
        }
    }

    xor_sum
}

/// Verifies whether an NMEA-0183 sentence possesses a valid checksum.
pub fn verify_nmea_checksum(sentence: &str) -> Result<bool, String> {
    let trimmed = sentence.trim();
    if !trimmed.starts_with('$') && !trimmed.starts_with('!') {
        return Err("NMEA sentence must begin with '$' or '!'".to_string());
    }

    let star_idx = match trimmed.rfind('*') {
        Some(idx) => idx,
        None => return Err("NMEA sentence missing '*' checksum delimiter".to_string()),
    };

    if star_idx + 3 > trimmed.len() {
        return Err("NMEA sentence has incomplete 2-hex-digit checksum after '*'".to_string());
    }

    let checksum_str = &trimmed[star_idx + 1..star_idx + 3];
    let expected = match u8::from_str_radix(checksum_str, 16) {
        Ok(val) => val,
        Err(_) => return Err(format!("Invalid hex checksum: '{}'", checksum_str)),
    };

    let computed = calculate_nmea_checksum(&trimmed[..star_idx]);
    Ok(computed == expected)
}

/// Parsed NMEA-0183 sentence summary.
#[derive(Debug, Clone, PartialEq)]
pub struct NmeaSentenceRecord {
    pub raw: String,
    pub talker: String,
    pub sentence_type: String,
    pub is_valid_checksum: bool,
    pub utc_time: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub fix_quality: Option<u8>,
    pub num_satellites: Option<usize>,
    pub hdop: Option<f64>,
    pub altitude_m: Option<f64>,
    pub speed_knots: Option<f64>,
}

/// Comprehensive report on an evaluated NMEA-0183 stream.
#[derive(Debug, Clone, PartialEq)]
pub struct NmeaStreamReport {
    pub total_sentences: usize,
    pub valid_checksums: usize,
    pub invalid_checksums: usize,
    pub talkers_detected: Vec<String>,
    pub sentence_types_detected: Vec<String>,
    pub records: Vec<NmeaSentenceRecord>,
    pub anomalies: Vec<String>,
    pub is_authentic: bool,
}

/// Parses an NMEA-0183 coordinate string in "ddmm.mmmm" format into decimal degrees.
fn parse_nmea_lat(coord_str: &str, hemisphere: &str) -> Option<f64> {
    if coord_str.len() < 4 {
        return None;
    }
    let deg: f64 = coord_str[..2].parse().ok()?;
    let min: f64 = coord_str[2..].parse().ok()?;
    let mut dec = deg + (min / 60.0);
    if hemisphere.eq_ignore_ascii_case("S") {
        dec = -dec;
    }
    Some(dec)
}

/// Parses an NMEA-0183 coordinate string in "dddmm.mmmm" format into decimal degrees.
fn parse_nmea_lon(coord_str: &str, hemisphere: &str) -> Option<f64> {
    if coord_str.len() < 5 {
        return None;
    }
    let deg: f64 = coord_str[..3].parse().ok()?;
    let min: f64 = coord_str[3..].parse().ok()?;
    let mut dec = deg + (min / 60.0);
    if hemisphere.eq_ignore_ascii_case("W") {
        dec = -dec;
    }
    Some(dec)
}

/// Parses a single NMEA sentence.
pub fn parse_nmea_sentence(raw_line: &str) -> Option<NmeaSentenceRecord> {
    let trimmed = raw_line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let is_valid_checksum = verify_nmea_checksum(trimmed).unwrap_or(false);

    // Strip starting '$' / '!' and trailing '*XX'
    let payload = if let Some(star_pos) = trimmed.rfind('*') {
        &trimmed[1..star_pos]
    } else {
        &trimmed[1..]
    };

    let parts: Vec<&str> = payload.split(',').collect();
    if parts.is_empty() {
        return None;
    }

    let header = parts[0];
    let (talker, sentence_type) = if header.len() >= 5 {
        if let Some(stripped) = header.strip_prefix('P') {
            // Proprietary sentence e.g. PIRNS
            ("P".to_string(), stripped.to_string())
        } else {
            (header[..2].to_string(), header[2..].to_string())
        }
    } else {
        ("GN".to_string(), header.to_string())
    };

    let mut record = NmeaSentenceRecord {
        raw: trimmed.to_string(),
        talker,
        sentence_type: sentence_type.clone(),
        is_valid_checksum,
        utc_time: None,
        latitude: None,
        longitude: None,
        fix_quality: None,
        num_satellites: None,
        hdop: None,
        altitude_m: None,
        speed_knots: None,
    };

    match sentence_type.as_str() {
        "GGA" => {
            // $--GGA,hhmmss.ss,llll.ll,a,yyyyy.yy,a,x,xx,x.x,x.x,M,x.x,M,x.x,xxxx
            if parts.len() > 1 && !parts[1].is_empty() {
                record.utc_time = Some(parts[1].to_string());
            }
            if parts.len() > 3 && !parts[2].is_empty() && !parts[3].is_empty() {
                record.latitude = parse_nmea_lat(parts[2], parts[3]);
            }
            if parts.len() > 5 && !parts[4].is_empty() && !parts[5].is_empty() {
                record.longitude = parse_nmea_lon(parts[4], parts[5]);
            }
            if parts.len() > 6 && !parts[6].is_empty() {
                record.fix_quality = parts[6].parse().ok();
            }
            if parts.len() > 7 && !parts[7].is_empty() {
                record.num_satellites = parts[7].parse().ok();
            }
            if parts.len() > 8 && !parts[8].is_empty() {
                record.hdop = parts[8].parse().ok();
            }
            if parts.len() > 9 && !parts[9].is_empty() {
                record.altitude_m = parts[9].parse().ok();
            }
        }
        "RMC" => {
            // $--RMC,hhmmss.ss,A,llll.ll,a,yyyyy.yy,a,x.x,x.x,ddmmyy,,,a
            if parts.len() > 1 && !parts[1].is_empty() {
                record.utc_time = Some(parts[1].to_string());
            }
            if parts.len() > 4 && !parts[3].is_empty() && !parts[4].is_empty() {
                record.latitude = parse_nmea_lat(parts[3], parts[4]);
            }
            if parts.len() > 6 && !parts[5].is_empty() && !parts[6].is_empty() {
                record.longitude = parse_nmea_lon(parts[5], parts[6]);
            }
            if parts.len() > 7 && !parts[7].is_empty() {
                record.speed_knots = parts[7].parse().ok();
            }
        }
        _ => {}
    }

    Some(record)
}

/// Analyzes an entire stream of NMEA sentences.
pub fn analyze_nmea_stream(stream: &str) -> NmeaStreamReport {
    let mut total_sentences = 0;
    let mut valid_checksums = 0;
    let mut invalid_checksums = 0;
    let mut talkers_set = std::collections::BTreeSet::new();
    let mut types_set = std::collections::BTreeSet::new();
    let mut records = Vec::new();
    let mut anomalies = Vec::new();

    for line in stream.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        total_sentences += 1;
        if let Some(rec) = parse_nmea_sentence(trimmed) {
            talkers_set.insert(rec.talker.clone());
            types_set.insert(rec.sentence_type.clone());
            if rec.is_valid_checksum {
                valid_checksums += 1;
            } else {
                invalid_checksums += 1;
                anomalies.push(format!(
                    "Corrupt/forged NMEA checksum in sentence: {}",
                    rec.raw
                ));
            }
            records.push(rec);
        } else {
            invalid_checksums += 1;
            anomalies.push(format!("Malformed NMEA sentence: {}", trimmed));
        }
    }

    let is_authentic = invalid_checksums == 0 && total_sentences > 0;

    NmeaStreamReport {
        total_sentences,
        valid_checksums,
        invalid_checksums,
        talkers_detected: talkers_set.into_iter().collect(),
        sentence_types_detected: types_set.into_iter().collect(),
        records,
        anomalies,
        is_authentic,
    }
}

/// Keplerian broadcast ephemeris orbital parameter set.
#[derive(Debug, Clone, PartialEq)]
pub struct KeplerianEphemeris {
    pub sat_id: String,
    pub constellation: Constellation,
    pub epoch_toe_sec: f64,
    pub sqrt_a: f64,
    pub eccentricity: f64,
    pub inclination_rad: f64,
    pub omega_rad: f64,
    pub omega_dot_rad_s: f64,
    pub mean_anomaly_rad: f64,
    pub delta_n_rad_s: f64,
    pub af0_s: f64,
    pub af1_s_s: f64,
    pub af2_s_s2: f64,
}

/// Ephemeris verification results and physical orbital bounds checking.
#[derive(Debug, Clone, PartialEq)]
pub struct EphemerisVerificationResult {
    pub sat_id: String,
    pub constellation: Constellation,
    pub is_valid: bool,
    pub orbit_type: String,
    pub semi_major_axis_m: f64,
    pub violations: Vec<String>,
}

/// Verifies whether Keplerian orbital parameters adhere to real-world physical bounds.
pub fn verify_ephemeris(eph: &KeplerianEphemeris) -> EphemerisVerificationResult {
    let mut violations = Vec::new();
    let semi_major_axis_m = eph.sqrt_a * eph.sqrt_a;

    let mut orbit_type = "Unknown".to_string();

    match eph.constellation {
        Constellation::Gps => {
            orbit_type = "GPS MEO (Medium Earth Orbit)".to_string();

            // GPS Semi-major axis bounds: nominal 26,560 km. Bounds: [26,400 km, 26,700 km]
            if semi_major_axis_m < 26_400_000.0 || semi_major_axis_m > 26_700_000.0 {
                violations.push(format!(
                    "Semi-major axis {:.1} m violates physical GPS MEO bounds [26,400,000, 26,700,000] m",
                    semi_major_axis_m
                ));
            }

            // GPS Eccentricity bounds: e <= 0.03
            if eph.eccentricity < 0.0 || eph.eccentricity > 0.03 {
                violations.push(format!(
                    "Eccentricity {:.6} violates quasi-circular GPS MEO limit (e <= 0.03)",
                    eph.eccentricity
                ));
            }

            // GPS Inclination bounds: nominal 55 deg = 0.9599 rad. Bounds: [0.85, 1.10] rad (~48.7° to 63.0°)
            if eph.inclination_rad < 0.85 || eph.inclination_rad > 1.10 {
                violations.push(format!(
                    "Inclination {:.4} rad ({:.1}°) violates nominal GPS orbital inclination [0.85, 1.10] rad",
                    eph.inclination_rad,
                    eph.inclination_rad.to_degrees()
                ));
            }

            // Delta n bounds: |Δn| <= 1.0e-8 rad/s
            if eph.delta_n_rad_s.abs() > 1.0e-8 {
                violations.push(format!(
                    "Mean motion difference |Δn| = {:.3e} rad/s exceeds bound 1.0e-8 rad/s",
                    eph.delta_n_rad_s.abs()
                ));
            }
        }
        Constellation::NavIc => {
            orbit_type = "India NavIC (IRNSS) GSO/GEO".to_string();

            // NavIC Semi-major axis bounds: nominal 42,164 km. Bounds: [41,900 km, 42,400 km]
            if semi_major_axis_m < 41_900_000.0 || semi_major_axis_m > 42_400_000.0 {
                violations.push(format!(
                    "Semi-major axis {:.1} m violates physical NavIC GEO/GSO bounds [41,900,000, 42,400,000] m",
                    semi_major_axis_m
                ));
            }

            // NavIC Eccentricity bounds: e <= 0.03
            if eph.eccentricity < 0.0 || eph.eccentricity > 0.03 {
                violations.push(format!(
                    "Eccentricity {:.6} violates NavIC orbit limit (e <= 0.03)",
                    eph.eccentricity
                ));
            }

            // NavIC Inclination bounds:
            // GEO sats (e.g. 1C, 1F, 1G) ~0 deg (i <= 0.1 rad).
            // GSO sats (e.g. 1A, 1B, 1D, 1E, 1I) ~29 deg (0.45 <= i <= 0.58 rad).
            // Combined valid bound: i <= 0.65 rad (~37.2 deg).
            if eph.inclination_rad < 0.0 || eph.inclination_rad > 0.65 {
                violations.push(format!(
                    "Inclination {:.4} rad ({:.1}°) violates physical NavIC GSO/GEO maximum bound <= 0.65 rad",
                    eph.inclination_rad,
                    eph.inclination_rad.to_degrees()
                ));
            }
        }
        _ => {
            // General orbital physics: semi-major axis must be greater than Earth equatorial radius (6,378,137 m)
            if semi_major_axis_m < 6_378_137.0 {
                violations.push(format!(
                    "Semi-major axis {:.1} m is inside the Earth's radius (6,378,137 m)",
                    semi_major_axis_m
                ));
            }
            if eph.eccentricity < 0.0 || eph.eccentricity >= 1.0 {
                violations.push(format!(
                    "Eccentricity {:.6} is not an elliptical bound orbit (must be 0 <= e < 1)",
                    eph.eccentricity
                ));
            }
        }
    }

    let is_valid = violations.is_empty();

    EphemerisVerificationResult {
        sat_id: eph.sat_id.clone(),
        constellation: eph.constellation,
        is_valid,
        orbit_type,
        semi_major_axis_m,
        violations,
    }
}

/// Parses an ephemeris file in JSON format.
pub fn parse_ephemeris_json(json_str: &str) -> Result<Vec<KeplerianEphemeris>, String> {
    let root = parse_json(json_str)?;
    let items = match root {
        JsonValue::Array(arr) => arr,
        JsonValue::Object(map) => {
            if let Some(JsonValue::Array(arr)) = map.get("ephemeris") {
                arr.clone()
            } else {
                return Err("Expected top-level array or object with 'ephemeris' array".to_string());
            }
        }
        _ => return Err("Invalid JSON structure for ephemeris".to_string()),
    };

    let mut result = Vec::new();

    for (idx, item) in items.iter().enumerate() {
        let obj = match item {
            JsonValue::Object(m) => m,
            _ => return Err(format!("Ephemeris at index {} is not an object", idx)),
        };

        let sat_id = obj
            .get("sat_id")
            .and_then(|v| v.as_str())
            .unwrap_or("G01")
            .to_string();

        let const_str = obj
            .get("constellation")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let constellation = if !const_str.is_empty() {
            Constellation::from_str(const_str)
        } else if sat_id.starts_with('G') {
            Constellation::Gps
        } else if sat_id.starts_with('I') || sat_id.starts_with('N') {
            Constellation::NavIc
        } else {
            Constellation::Unknown
        };

        let epoch_toe_sec = obj
            .get("epoch_toe_sec")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let sqrt_a = obj.get("sqrt_a").and_then(|v| v.as_f64()).unwrap_or(5153.6);
        let eccentricity = obj
            .get("eccentricity")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.005);
        let inclination_rad = obj
            .get("inclination_rad")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.96);
        let omega_rad = obj.get("omega_rad").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let omega_dot_rad_s = obj
            .get("omega_dot_rad_s")
            .and_then(|v| v.as_f64())
            .unwrap_or(-8.0e-9);
        let mean_anomaly_rad = obj
            .get("mean_anomaly_rad")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let delta_n_rad_s = obj
            .get("delta_n_rad_s")
            .and_then(|v| v.as_f64())
            .unwrap_or(4.0e-9);
        let af0_s = obj.get("af0_s").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let af1_s_s = obj.get("af1_s_s").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let af2_s_s2 = obj.get("af2_s_s2").and_then(|v| v.as_f64()).unwrap_or(0.0);

        result.push(KeplerianEphemeris {
            sat_id,
            constellation,
            epoch_toe_sec,
            sqrt_a,
            eccentricity,
            inclination_rad,
            omega_rad,
            omega_dot_rad_s,
            mean_anomaly_rad,
            delta_n_rad_s,
            af0_s,
            af1_s_s,
            af2_s_s2,
        });
    }

    Ok(result)
}

/// Serializes ephemeris verification results to JSON.
pub fn ephemeris_report_to_json(results: &[EphemerisVerificationResult]) -> JsonValue {
    let mut arr = Vec::new();
    for r in results {
        let mut obj = BTreeMap::new();
        obj.insert("sat_id".to_string(), JsonValue::String(r.sat_id.clone()));
        obj.insert(
            "constellation".to_string(),
            JsonValue::String(r.constellation.as_str().to_string()),
        );
        obj.insert("is_valid".to_string(), JsonValue::Bool(r.is_valid));
        obj.insert(
            "orbit_type".to_string(),
            JsonValue::String(r.orbit_type.clone()),
        );
        obj.insert(
            "semi_major_axis_m".to_string(),
            JsonValue::Number(r.semi_major_axis_m),
        );
        let viol_arr: Vec<JsonValue> = r
            .violations
            .iter()
            .map(|v| JsonValue::String(v.clone()))
            .collect();
        obj.insert("violations".to_string(), JsonValue::Array(viol_arr));
        arr.push(JsonValue::Object(obj));
    }
    JsonValue::Array(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nmea_checksum() {
        let sentence = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47";
        let computed = calculate_nmea_checksum(sentence);
        assert_eq!(computed, 0x47);
        assert!(verify_nmea_checksum(sentence).unwrap());
    }

    #[test]
    fn test_nmea_checksum_invalid() {
        let bad_sentence = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*48";
        assert!(!verify_nmea_checksum(bad_sentence).unwrap());
    }

    #[test]
    fn test_parse_nmea_sentence() {
        let sentence = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47";
        let rec = parse_nmea_sentence(sentence).unwrap();
        assert_eq!(rec.talker, "GP");
        assert_eq!(rec.sentence_type, "GGA");
        assert_eq!(rec.num_satellites, Some(8));
        assert_eq!(rec.hdop, Some(0.9));
        assert_eq!(rec.altitude_m, Some(545.4));
        assert!(rec.latitude.is_some());
        assert!(rec.longitude.is_some());
    }

    #[test]
    fn test_valid_gps_ephemeris() {
        let eph = KeplerianEphemeris {
            sat_id: "G01".to_string(),
            constellation: Constellation::Gps,
            epoch_toe_sec: 1000.0,
            sqrt_a: 5153.65, // a = 26,560,108.3 m
            eccentricity: 0.005,
            inclination_rad: 0.9599, // ~55 deg
            omega_rad: 0.5,
            omega_dot_rad_s: -8.0e-9,
            mean_anomaly_rad: 1.0,
            delta_n_rad_s: 4.0e-9,
            af0_s: 0.0,
            af1_s_s: 0.0,
            af2_s_s2: 0.0,
        };

        let res = verify_ephemeris(&eph);
        assert!(res.is_valid);
        assert!(res.violations.is_empty());
    }

    #[test]
    fn test_invalid_gps_ephemeris_spoofer() {
        let eph = KeplerianEphemeris {
            sat_id: "G01".to_string(),
            constellation: Constellation::Gps,
            epoch_toe_sec: 1000.0,
            sqrt_a: 4000.0, // a = 16,000,000 m (impossible LEO altitude for GPS MEO)
            eccentricity: 0.15, // huge eccentricity
            inclination_rad: 0.10, // ~5.7 deg instead of 55 deg
            omega_rad: 0.0,
            omega_dot_rad_s: 0.0,
            mean_anomaly_rad: 0.0,
            delta_n_rad_s: 0.0,
            af0_s: 0.0,
            af1_s_s: 0.0,
            af2_s_s2: 0.0,
        };

        let res = verify_ephemeris(&eph);
        assert!(!res.is_valid);
        assert_eq!(res.violations.len(), 3);
    }

    #[test]
    fn test_valid_navic_ephemeris() {
        let eph = KeplerianEphemeris {
            sat_id: "I01".to_string(),
            constellation: Constellation::NavIc,
            epoch_toe_sec: 500.0,
            sqrt_a: 6493.4, // a = 42,164,243 m (nominal GEO)
            eccentricity: 0.002,
            inclination_rad: 0.506, // ~29 deg (nominal NavIC GSO)
            omega_rad: 0.1,
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
}
