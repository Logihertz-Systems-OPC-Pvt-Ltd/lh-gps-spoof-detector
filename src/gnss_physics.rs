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

//! Multi-band GNSS & NavIC physics engine, carrier Doppler vs pseudorange-rate
//! consistency tracking, C/N0 power jump & AGC compression analysis, spatial
//! variance collapse detection, and clock drift monitoring.

use crate::json::{parse_json, JsonValue};
use std::collections::{BTreeMap, HashMap};

/// Speed of light in vacuum (m/s) per BIPM / CODATA.
pub const SPEED_OF_LIGHT_M_S: f64 = 299_792_458.0;

/// Carrier frequencies (Hz).
pub const FREQ_GPS_L1_HZ: f64 = 1_575_420_000.0;
pub const FREQ_GPS_L2_HZ: f64 = 1_227_600_000.0;
pub const FREQ_GPS_NAVIC_L5_HZ: f64 = 1_176_450_000.0;
pub const FREQ_NAVIC_S_BAND_HZ: f64 = 2_492_028_000.0;

/// Anomaly thresholds.
pub const CN0_SURGE_THRESHOLD_DBHZ: f64 = 54.0;
pub const CN0_STEP_JUMP_THRESHOLD_DB: f64 = 6.0;
pub const AGC_DROP_THRESHOLD_PCT: f64 = 8.0;
pub const AGC_COINCIDENT_CN0_RISE_DB: f64 = 3.0;
pub const SPATIAL_VARIANCE_COLLAPSE_THRESHOLD_DB2: f64 = 0.5;
pub const SPATIAL_VARIANCE_MIN_SATS: usize = 4;
pub const SPATIAL_VARIANCE_MIN_ELEVATION_SPREAD_DEG: f64 = 25.0;
pub const DOPPLER_PSEUDORANGE_RATE_MAX_ERROR_M_S: f64 = 2.5;
pub const CLOCK_BIAS_DRIFT_MAX_RATE_NS_S: f64 = 50.0;
pub const CLOCK_BIAS_STEP_JUMP_MAX_NS: f64 = 100.0;
pub const MULTI_CONSTELLATION_SPLIT_THRESHOLD_M: f64 = 35.0;

/// GNSS Constellation identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Constellation {
    Gps,
    NavIc,
    Galileo,
    Glonass,
    Unknown,
}

impl std::str::FromStr for Constellation {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "GPS" | "GP" => Ok(Constellation::Gps),
            "NAVIC" | "IRNSS" | "IR" | "GI" => Ok(Constellation::NavIc),
            "GALILEO" | "GA" => Ok(Constellation::Galileo),
            "GLONASS" | "GL" => Ok(Constellation::Glonass),
            _ => Ok(Constellation::Unknown),
        }
    }
}

impl Constellation {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GPS" | "GP" => Constellation::Gps,
            "NAVIC" | "IRNSS" | "IR" | "GI" => Constellation::NavIc,
            "GALILEO" | "GA" => Constellation::Galileo,
            "GLONASS" | "GL" => Constellation::Glonass,
            _ => Constellation::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Constellation::Gps => "GPS",
            Constellation::NavIc => "NavIC",
            Constellation::Galileo => "Galileo",
            Constellation::Glonass => "GLONASS",
            Constellation::Unknown => "Unknown",
        }
    }
}

/// GNSS Frequency Band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrequencyBand {
    L1,
    L2,
    L5,
    SBand,
    Unknown,
}

impl std::str::FromStr for FrequencyBand {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "L1" => Ok(FrequencyBand::L1),
            "L2" => Ok(FrequencyBand::L2),
            "L5" => Ok(FrequencyBand::L5),
            "S" | "SBAND" | "S-BAND" => Ok(FrequencyBand::SBand),
            _ => Ok(FrequencyBand::Unknown),
        }
    }
}

impl FrequencyBand {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "L1" => FrequencyBand::L1,
            "L2" => FrequencyBand::L2,
            "L5" => FrequencyBand::L5,
            "S" | "SBAND" | "S-BAND" => FrequencyBand::SBand,
            _ => FrequencyBand::Unknown,
        }
    }

    pub fn nominal_frequency_hz(&self, constellation: Constellation) -> f64 {
        match (self, constellation) {
            (FrequencyBand::L1, _) => FREQ_GPS_L1_HZ,
            (FrequencyBand::L2, _) => FREQ_GPS_L2_HZ,
            (FrequencyBand::L5, _) => FREQ_GPS_NAVIC_L5_HZ,
            (FrequencyBand::SBand, Constellation::NavIc) => FREQ_NAVIC_S_BAND_HZ,
            (FrequencyBand::SBand, _) => FREQ_NAVIC_S_BAND_HZ,
            (FrequencyBand::Unknown, _) => FREQ_GPS_L1_HZ,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            FrequencyBand::L1 => "L1",
            FrequencyBand::L2 => "L2",
            FrequencyBand::L5 => "L5",
            FrequencyBand::SBand => "S-band",
            FrequencyBand::Unknown => "Unknown",
        }
    }
}

/// 3D Position vector (ECEF or Local ENU coordinates in meters).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Position3D {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Position3D {
    pub fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    pub fn distance_to(&self, other: &Position3D) -> f64 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        let dz = self.z - other.z;
        (dx * dx + dy * dy + dz * dz).sqrt()
    }

    pub fn norm(&self) -> f64 {
        (self.x * self.x + self.y * self.y + self.z * self.z).sqrt()
    }
}

/// Individual satellite measurement within an epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct SatelliteMeasurement {
    pub sat_id: String,
    pub constellation: Constellation,
    pub band: FrequencyBand,
    pub carrier_freq_hz: f64,
    pub pseudorange_m: f64,
    pub doppler_hz: f64,
    pub cn0_dbhz: f64,
    pub elevation_deg: f64,
    pub azimuth_deg: f64,
}

impl SatelliteMeasurement {
    pub fn carrier_wavelength_m(&self) -> f64 {
        if self.carrier_freq_hz > 0.0 {
            SPEED_OF_LIGHT_M_S / self.carrier_freq_hz
        } else {
            SPEED_OF_LIGHT_M_S / self.band.nominal_frequency_hz(self.constellation)
        }
    }

    /// Range rate implied by carrier Doppler shift: v_doppler = - lambda * f_doppler (m/s).
    pub fn doppler_range_rate_m_s(&self) -> f64 {
        -self.carrier_wavelength_m() * self.doppler_hz
    }
}

/// Telemetry epoch containing simultaneous measurements from multiple satellites.
#[derive(Debug, Clone, PartialEq)]
pub struct GnssEpoch {
    pub timestamp_sec: f64,
    pub receiver_clock_bias_ns: f64,
    pub agc_level_pct: f64,
    pub measurements: Vec<SatelliteMeasurement>,
    pub pv_solution: Option<Position3D>,
    pub navic_solution: Option<Position3D>,
}

/// Severity classification for detected GNSS anomalies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AnomalySeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalySeverity::Low => "LOW",
            AnomalySeverity::Medium => "MEDIUM",
            AnomalySeverity::High => "HIGH",
            AnomalySeverity::Critical => "CRITICAL",
        }
    }
}

/// Detailed classification of spoofing anomaly indicators.
#[derive(Debug, Clone, PartialEq)]
pub enum SpoofingAnomalyKind {
    Cn0Surge,
    Cn0StepJump,
    AgcCompression,
    SpatialVarianceCollapse,
    DopplerPseudorangeRateMismatch,
    ClockBiasDriftRate,
    ClockBiasStepJump,
    MultiConstellationPositionSplit,
}

impl SpoofingAnomalyKind {
    pub fn code(&self) -> &'static str {
        match self {
            SpoofingAnomalyKind::Cn0Surge => "ANOM-CN0-SURGE",
            SpoofingAnomalyKind::Cn0StepJump => "ANOM-CN0-STEP",
            SpoofingAnomalyKind::AgcCompression => "ANOM-AGC-COMPRESSION",
            SpoofingAnomalyKind::SpatialVarianceCollapse => "ANOM-SPATIAL-COLLAPSE",
            SpoofingAnomalyKind::DopplerPseudorangeRateMismatch => "ANOM-DOPPLER-MISMATCH",
            SpoofingAnomalyKind::ClockBiasDriftRate => "ANOM-CLOCK-DRIFT",
            SpoofingAnomalyKind::ClockBiasStepJump => "ANOM-CLOCK-JUMP",
            SpoofingAnomalyKind::MultiConstellationPositionSplit => "ANOM-CONSTELLATION-SPLIT",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            SpoofingAnomalyKind::Cn0Surge => "Carrier-to-Noise C/N0 Overpower Surge",
            SpoofingAnomalyKind::Cn0StepJump => "Carrier-to-Noise C/N0 Step Jump",
            SpoofingAnomalyKind::AgcCompression => "Automatic Gain Control (AGC) Compression Drop",
            SpoofingAnomalyKind::SpatialVarianceCollapse => {
                "Single-Antenna Spatial C/N0 Variance Collapse"
            }
            SpoofingAnomalyKind::DopplerPseudorangeRateMismatch => {
                "Carrier Doppler vs Pseudorange Rate Mismatch"
            }
            SpoofingAnomalyKind::ClockBiasDriftRate => "Excessive Receiver Clock Bias Slew Rate",
            SpoofingAnomalyKind::ClockBiasStepJump => "Discontinuous Receiver Clock Bias Step Jump",
            SpoofingAnomalyKind::MultiConstellationPositionSplit => {
                "GPS vs NavIC PVT 3D Position Split"
            }
        }
    }
}

/// Individual recorded anomaly instance.
#[derive(Debug, Clone, PartialEq)]
pub struct SpoofingAnomaly {
    pub epoch_time: f64,
    pub kind: SpoofingAnomalyKind,
    pub severity: AnomalySeverity,
    pub sat_id: Option<String>,
    pub observed_value: f64,
    pub threshold_value: f64,
    pub unit: &'static str,
    pub description: String,
}

/// Comprehensive analysis report of a sequence of GNSS epochs.
#[derive(Debug, Clone, PartialEq)]
pub struct EpochAnalysisReport {
    pub total_epochs: usize,
    pub evaluated_satellites: usize,
    pub anomalies: Vec<SpoofingAnomaly>,
    pub spoofing_probability: f64,
    pub is_spoofed: bool,
    pub summary: String,
}

/// Core multi-band GNSS spoofing detector and physics analyzer.
pub struct GnssPhysicsAnalyzer;

impl GnssPhysicsAnalyzer {
    /// Evaluates a chronological sequence of GNSS epochs and returns an in-depth analysis report.
    pub fn analyze_epoch_sequence(epochs: &[GnssEpoch]) -> EpochAnalysisReport {
        if epochs.is_empty() {
            return EpochAnalysisReport {
                total_epochs: 0,
                evaluated_satellites: 0,
                anomalies: Vec::new(),
                spoofing_probability: 0.0,
                is_spoofed: false,
                summary: "Empty epoch stream; no GNSS telemetry evaluated.".to_string(),
            };
        }

        let mut anomalies = Vec::new();
        let mut sat_ids = std::collections::HashSet::new();

        // Track previous satellite measurements for rate calculation: sat_key -> (timestamp, pseudorange, cn0)
        let mut prev_sat_state: HashMap<String, (f64, f64, f64)> = HashMap::new();

        for i in 0..epochs.len() {
            let current_epoch = &epochs[i];

            for m in &current_epoch.measurements {
                sat_ids.insert(m.sat_id.clone());
            }

            // 1. Check C/N0 absolute surge on current measurements (> 54 dB-Hz)
            for m in &current_epoch.measurements {
                if m.cn0_dbhz > CN0_SURGE_THRESHOLD_DBHZ {
                    anomalies.push(SpoofingAnomaly {
                        epoch_time: current_epoch.timestamp_sec,
                        kind: SpoofingAnomalyKind::Cn0Surge,
                        severity: AnomalySeverity::Critical,
                        sat_id: Some(m.sat_id.clone()),
                        observed_value: m.cn0_dbhz,
                        threshold_value: CN0_SURGE_THRESHOLD_DBHZ,
                        unit: "dB-Hz",
                        description: format!(
                            "Satellite {} power {} dB-Hz exceeds maximum physical Earth-surface limit of {} dB-Hz",
                            m.sat_id, m.cn0_dbhz, CN0_SURGE_THRESHOLD_DBHZ
                        ),
                    });
                }
            }

            // 2. Spatial variance collapse across visible satellites
            // When multiple satellites with wide elevation angles have near-identical C/N0 (variance < 0.5 dB^2)
            let elev_sats: Vec<&SatelliteMeasurement> = current_epoch
                .measurements
                .iter()
                .filter(|m| m.elevation_deg >= 10.0)
                .collect();

            if elev_sats.len() >= SPATIAL_VARIANCE_MIN_SATS {
                let mut min_elev = 90.0_f64;
                let mut max_elev = 0.0_f64;
                for s in &elev_sats {
                    if s.elevation_deg < min_elev {
                        min_elev = s.elevation_deg;
                    }
                    if s.elevation_deg > max_elev {
                        max_elev = s.elevation_deg;
                    }
                }
                let elev_spread = max_elev - min_elev;

                if elev_spread >= SPATIAL_VARIANCE_MIN_ELEVATION_SPREAD_DEG {
                    let n = elev_sats.len() as f64;
                    let mean_cn0 = elev_sats.iter().map(|s| s.cn0_dbhz).sum::<f64>() / n;
                    let variance = elev_sats
                        .iter()
                        .map(|s| {
                            let diff = s.cn0_dbhz - mean_cn0;
                            diff * diff
                        })
                        .sum::<f64>()
                        / n;

                    if variance < SPATIAL_VARIANCE_COLLAPSE_THRESHOLD_DB2 {
                        anomalies.push(SpoofingAnomaly {
                            epoch_time: current_epoch.timestamp_sec,
                            kind: SpoofingAnomalyKind::SpatialVarianceCollapse,
                            severity: AnomalySeverity::High,
                            sat_id: None,
                            observed_value: variance,
                            threshold_value: SPATIAL_VARIANCE_COLLAPSE_THRESHOLD_DB2,
                            unit: "dB²",
                            description: format!(
                                "Inter-satellite C/N0 spatial variance collapsed to {:.3} dB² across {} satellites (elevation spread {:.1}°); indicates single RF horn simulator transmitter",
                                variance, elev_sats.len(), elev_spread
                            ),
                        });
                    }
                }
            }

            // 3. Multi-constellation 3D position split (GPS L1 vs NavIC L5/S-band)
            if let (Some(gps_pv), Some(navic_pv)) =
                (&current_epoch.pv_solution, &current_epoch.navic_solution)
            {
                let split_dist_m = gps_pv.distance_to(navic_pv);
                if split_dist_m > MULTI_CONSTELLATION_SPLIT_THRESHOLD_M {
                    anomalies.push(SpoofingAnomaly {
                        epoch_time: current_epoch.timestamp_sec,
                        kind: SpoofingAnomalyKind::MultiConstellationPositionSplit,
                        severity: AnomalySeverity::Critical,
                        sat_id: None,
                        observed_value: split_dist_m,
                        threshold_value: MULTI_CONSTELLATION_SPLIT_THRESHOLD_M,
                        unit: "m",
                        description: format!(
                            "GPS PVT solution and India NavIC solution diverge by {:.2} m (exceeds threshold {:.1} m); selective constellation spoofing detected",
                            split_dist_m, MULTI_CONSTELLATION_SPLIT_THRESHOLD_M
                        ),
                    });
                }
            }

            // Temporal inter-epoch checks (requires previous epoch i > 0)
            if i > 0 {
                let prev_epoch = &epochs[i - 1];
                let dt = current_epoch.timestamp_sec - prev_epoch.timestamp_sec;

                if dt > 0.001 {
                    // 4. AGC compression drop with concurrent mean C/N0 rise
                    let agc_drop = prev_epoch.agc_level_pct - current_epoch.agc_level_pct;
                    let curr_mean_cn0 = if !current_epoch.measurements.is_empty() {
                        current_epoch
                            .measurements
                            .iter()
                            .map(|m| m.cn0_dbhz)
                            .sum::<f64>()
                            / current_epoch.measurements.len() as f64
                    } else {
                        0.0
                    };
                    let prev_mean_cn0 = if !prev_epoch.measurements.is_empty() {
                        prev_epoch
                            .measurements
                            .iter()
                            .map(|m| m.cn0_dbhz)
                            .sum::<f64>()
                            / prev_epoch.measurements.len() as f64
                    } else {
                        0.0
                    };
                    let cn0_rise = curr_mean_cn0 - prev_mean_cn0;

                    if agc_drop >= AGC_DROP_THRESHOLD_PCT && cn0_rise >= AGC_COINCIDENT_CN0_RISE_DB
                    {
                        anomalies.push(SpoofingAnomaly {
                            epoch_time: current_epoch.timestamp_sec,
                            kind: SpoofingAnomalyKind::AgcCompression,
                            severity: AnomalySeverity::Critical,
                            sat_id: None,
                            observed_value: agc_drop,
                            threshold_value: AGC_DROP_THRESHOLD_PCT,
                            unit: "%",
                            description: format!(
                                "Receiver AGC attenuated by {:.1}% while mean constellation C/N0 jumped by +{:.1} dB; characteristic RF front-end compression by hostile transmitter",
                                agc_drop, cn0_rise
                            ),
                        });
                    }

                    // 5. Receiver clock bias drift rate and step jump
                    let clk_diff_ns =
                        current_epoch.receiver_clock_bias_ns - prev_epoch.receiver_clock_bias_ns;
                    let clk_drift_rate = (clk_diff_ns / dt).abs();
                    let clk_jump_abs = clk_diff_ns.abs();

                    if clk_drift_rate > CLOCK_BIAS_DRIFT_MAX_RATE_NS_S {
                        anomalies.push(SpoofingAnomaly {
                            epoch_time: current_epoch.timestamp_sec,
                            kind: SpoofingAnomalyKind::ClockBiasDriftRate,
                            severity: AnomalySeverity::High,
                            sat_id: None,
                            observed_value: clk_drift_rate,
                            threshold_value: CLOCK_BIAS_DRIFT_MAX_RATE_NS_S,
                            unit: "ns/s",
                            description: format!(
                                "Receiver clock bias slew rate |db/dt| = {:.2} ns/s exceeds physical TCXO/OCXO limit of {} ns/s; indicates intentional spoofer clock dragging",
                                clk_drift_rate, CLOCK_BIAS_DRIFT_MAX_RATE_NS_S
                            ),
                        });
                    }

                    if clk_jump_abs > CLOCK_BIAS_STEP_JUMP_MAX_NS {
                        anomalies.push(SpoofingAnomaly {
                            epoch_time: current_epoch.timestamp_sec,
                            kind: SpoofingAnomalyKind::ClockBiasStepJump,
                            severity: AnomalySeverity::High,
                            sat_id: None,
                            observed_value: clk_jump_abs,
                            threshold_value: CLOCK_BIAS_STEP_JUMP_MAX_NS,
                            unit: "ns",
                            description: format!(
                                "Receiver clock bias discontinuous jump |Δb| = {:.2} ns exceeds maximum continuity limit of {} ns",
                                clk_jump_abs, CLOCK_BIAS_STEP_JUMP_MAX_NS
                            ),
                        });
                    }
                }
            }

            // 6. Carrier Doppler vs Pseudorange-rate consistency & per-sat C/N0 step jump
            for m in &current_epoch.measurements {
                let sat_key = format!("{}:{}", m.sat_id, m.band.as_str());

                if let Some(&(prev_t, prev_pr, prev_cn0)) = prev_sat_state.get(&sat_key) {
                    let dt = current_epoch.timestamp_sec - prev_t;
                    if dt > 0.001 {
                        // Pseudorange rate: (rho_k - rho_{k-1}) / dt
                        let pr_rate_m_s = (m.pseudorange_m - prev_pr) / dt;
                        let doppler_rate_m_s = m.doppler_range_rate_m_s();
                        let rate_error_m_s = (pr_rate_m_s - doppler_rate_m_s).abs();

                        if rate_error_m_s > DOPPLER_PSEUDORANGE_RATE_MAX_ERROR_M_S {
                            anomalies.push(SpoofingAnomaly {
                                epoch_time: current_epoch.timestamp_sec,
                                kind: SpoofingAnomalyKind::DopplerPseudorangeRateMismatch,
                                severity: AnomalySeverity::High,
                                sat_id: Some(m.sat_id.clone()),
                                observed_value: rate_error_m_s,
                                threshold_value: DOPPLER_PSEUDORANGE_RATE_MAX_ERROR_M_S,
                                unit: "m/s",
                                description: format!(
                                    "Satellite {} pseudorange rate ({:.2} m/s) diverges from carrier Doppler velocity ({:.2} m/s) by {:.2} m/s; violates physical phase-code coherence",
                                    m.sat_id, pr_rate_m_s, doppler_rate_m_s, rate_error_m_s
                                ),
                            });
                        }

                        // C/N0 step jump
                        let cn0_step = m.cn0_dbhz - prev_cn0;
                        if cn0_step > CN0_STEP_JUMP_THRESHOLD_DB {
                            anomalies.push(SpoofingAnomaly {
                                epoch_time: current_epoch.timestamp_sec,
                                kind: SpoofingAnomalyKind::Cn0StepJump,
                                severity: AnomalySeverity::Medium,
                                sat_id: Some(m.sat_id.clone()),
                                observed_value: cn0_step,
                                threshold_value: CN0_STEP_JUMP_THRESHOLD_DB,
                                unit: "dB",
                                description: format!(
                                    "Satellite {} C/N0 stepped up by +{:.2} dB in {:.2}s (exceeds threshold {} dB)",
                                    m.sat_id, cn0_step, dt, CN0_STEP_JUMP_THRESHOLD_DB
                                ),
                            });
                        }
                    }
                }

                prev_sat_state.insert(
                    sat_key,
                    (current_epoch.timestamp_sec, m.pseudorange_m, m.cn0_dbhz),
                );
            }
        }

        // Compute Spoofing Probability score:
        // Weight anomalies: Critical = 0.35, High = 0.20, Medium = 0.10, Low = 0.05
        let mut score = 0.0_f64;
        for a in &anomalies {
            match a.severity {
                AnomalySeverity::Critical => score += 0.35,
                AnomalySeverity::High => score += 0.20,
                AnomalySeverity::Medium => score += 0.10,
                AnomalySeverity::Low => score += 0.05,
            }
        }
        let spoofing_probability = score.min(1.0);
        let is_spoofed = spoofing_probability >= 0.50
            || anomalies
                .iter()
                .any(|a| a.severity == AnomalySeverity::Critical);

        let summary = if is_spoofed {
            format!(
                "CRITICAL SPOOFING DETECTED: Encountered {} anomalies across {} epochs (Probability: {:.1}%).",
                anomalies.len(),
                epochs.len(),
                spoofing_probability * 100.0
            )
        } else if !anomalies.is_empty() {
            format!(
                "WARNING: Detected {} low/medium anomalies across {} epochs; signals exhibit nominal multipath or minor interference.",
                anomalies.len(),
                epochs.len()
            )
        } else {
            format!(
                "AUTHENTIC: All {} epochs verified clean across {} monitored satellites with zero anomalies.",
                epochs.len(),
                sat_ids.len()
            )
        };

        EpochAnalysisReport {
            total_epochs: epochs.len(),
            evaluated_satellites: sat_ids.len(),
            anomalies,
            spoofing_probability,
            is_spoofed,
            summary,
        }
    }

    /// Deserializes a list of GNSS epochs from a JSON string.
    pub fn parse_epochs_json(json_str: &str) -> Result<Vec<GnssEpoch>, String> {
        let root = parse_json(json_str)?;
        let items = match root {
            JsonValue::Array(arr) => arr,
            JsonValue::Object(map) => {
                if let Some(JsonValue::Array(arr)) = map.get("epochs") {
                    arr.clone()
                } else {
                    return Err(
                        "Expected top-level array or object with 'epochs' array".to_string()
                    );
                }
            }
            _ => return Err("Invalid JSON structure for epochs".to_string()),
        };

        let mut epochs = Vec::new();

        for (idx, item) in items.iter().enumerate() {
            let obj = match item {
                JsonValue::Object(m) => m,
                _ => return Err(format!("Epoch at index {} is not an object", idx)),
            };

            let timestamp_sec = obj
                .get("timestamp_sec")
                .and_then(|v| v.as_f64())
                .unwrap_or(idx as f64);

            let receiver_clock_bias_ns = obj
                .get("receiver_clock_bias_ns")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);

            let agc_level_pct = obj
                .get("agc_level_pct")
                .and_then(|v| v.as_f64())
                .unwrap_or(50.0);

            let mut measurements = Vec::new();
            if let Some(JsonValue::Array(meas_arr)) = obj.get("measurements") {
                for m_item in meas_arr {
                    if let JsonValue::Object(m_obj) = m_item {
                        let sat_id = m_obj
                            .get("sat_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("UNKNOWN")
                            .to_string();

                        let const_str = m_obj
                            .get("constellation")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let constellation = if !const_str.is_empty() {
                            Constellation::from_str(const_str)
                        } else if sat_id.starts_with('G') {
                            Constellation::Gps
                        } else if sat_id.starts_with('I') || sat_id.starts_with('N') {
                            Constellation::NavIc
                        } else if sat_id.starts_with('E') {
                            Constellation::Galileo
                        } else if sat_id.starts_with('R') {
                            Constellation::Glonass
                        } else {
                            Constellation::Unknown
                        };

                        let band_str = m_obj.get("band").and_then(|v| v.as_str()).unwrap_or("L1");
                        let band = FrequencyBand::from_str(band_str);

                        let carrier_freq_hz = m_obj
                            .get("carrier_freq_hz")
                            .and_then(|v| v.as_f64())
                            .unwrap_or_else(|| band.nominal_frequency_hz(constellation));

                        let pseudorange_m = m_obj
                            .get("pseudorange_m")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(20_000_000.0);

                        let doppler_hz = m_obj
                            .get("doppler_hz")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0);

                        let cn0_dbhz = m_obj
                            .get("cn0_dbhz")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(42.0);

                        let elevation_deg = m_obj
                            .get("elevation_deg")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(45.0);

                        let azimuth_deg = m_obj
                            .get("azimuth_deg")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(180.0);

                        measurements.push(SatelliteMeasurement {
                            sat_id,
                            constellation,
                            band,
                            carrier_freq_hz,
                            pseudorange_m,
                            doppler_hz,
                            cn0_dbhz,
                            elevation_deg,
                            azimuth_deg,
                        });
                    }
                }
            }

            let pv_solution = obj.get("pv_solution").and_then(|v| match v {
                JsonValue::Object(pv) => {
                    let x = pv.get("x").and_then(|n| n.as_f64()).unwrap_or(0.0);
                    let y = pv.get("y").and_then(|n| n.as_f64()).unwrap_or(0.0);
                    let z = pv.get("z").and_then(|n| n.as_f64()).unwrap_or(0.0);
                    Some(Position3D::new(x, y, z))
                }
                _ => None,
            });

            let navic_solution = obj.get("navic_solution").and_then(|v| match v {
                JsonValue::Object(pv) => {
                    let x = pv.get("x").and_then(|n| n.as_f64()).unwrap_or(0.0);
                    let y = pv.get("y").and_then(|n| n.as_f64()).unwrap_or(0.0);
                    let z = pv.get("z").and_then(|n| n.as_f64()).unwrap_or(0.0);
                    Some(Position3D::new(x, y, z))
                }
                _ => None,
            });

            epochs.push(GnssEpoch {
                timestamp_sec,
                receiver_clock_bias_ns,
                agc_level_pct,
                measurements,
                pv_solution,
                navic_solution,
            });
        }

        Ok(epochs)
    }

    /// Serializes an analysis report to a JSON structure.
    pub fn report_to_json(report: &EpochAnalysisReport) -> JsonValue {
        let mut root = BTreeMap::new();
        root.insert(
            "total_epochs".to_string(),
            JsonValue::Number(report.total_epochs as f64),
        );
        root.insert(
            "evaluated_satellites".to_string(),
            JsonValue::Number(report.evaluated_satellites as f64),
        );
        root.insert(
            "spoofing_probability".to_string(),
            JsonValue::Number(report.spoofing_probability),
        );
        root.insert("is_spoofed".to_string(), JsonValue::Bool(report.is_spoofed));
        root.insert(
            "summary".to_string(),
            JsonValue::String(report.summary.clone()),
        );

        let mut anomalies_arr = Vec::new();
        for a in &report.anomalies {
            let mut a_obj = BTreeMap::new();
            a_obj.insert("epoch_time".to_string(), JsonValue::Number(a.epoch_time));
            a_obj.insert(
                "code".to_string(),
                JsonValue::String(a.kind.code().to_string()),
            );
            a_obj.insert(
                "title".to_string(),
                JsonValue::String(a.kind.title().to_string()),
            );
            a_obj.insert(
                "severity".to_string(),
                JsonValue::String(a.severity.as_str().to_string()),
            );
            if let Some(ref sat) = a.sat_id {
                a_obj.insert("sat_id".to_string(), JsonValue::String(sat.clone()));
            } else {
                a_obj.insert("sat_id".to_string(), JsonValue::Null);
            }
            a_obj.insert(
                "observed_value".to_string(),
                JsonValue::Number(a.observed_value),
            );
            a_obj.insert(
                "threshold_value".to_string(),
                JsonValue::Number(a.threshold_value),
            );
            a_obj.insert("unit".to_string(), JsonValue::String(a.unit.to_string()));
            a_obj.insert(
                "description".to_string(),
                JsonValue::String(a.description.clone()),
            );
            anomalies_arr.push(JsonValue::Object(a_obj));
        }

        root.insert("anomalies".to_string(), JsonValue::Array(anomalies_arr));
        JsonValue::Object(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cn0_surge_detection() {
        let epoch = GnssEpoch {
            timestamp_sec: 100.0,
            receiver_clock_bias_ns: 0.0,
            agc_level_pct: 60.0,
            measurements: vec![SatelliteMeasurement {
                sat_id: "G01".to_string(),
                constellation: Constellation::Gps,
                band: FrequencyBand::L1,
                carrier_freq_hz: FREQ_GPS_L1_HZ,
                pseudorange_m: 20_000_000.0,
                doppler_hz: 0.0,
                cn0_dbhz: 58.5, // Exceeds 54.0 dB-Hz!
                elevation_deg: 40.0,
                azimuth_deg: 120.0,
            }],
            pv_solution: None,
            navic_solution: None,
        };

        let report = GnssPhysicsAnalyzer::analyze_epoch_sequence(&[epoch]);
        assert!(report.is_spoofed);
        assert_eq!(report.anomalies.len(), 1);
        assert_eq!(report.anomalies[0].kind, SpoofingAnomalyKind::Cn0Surge);
    }

    #[test]
    fn test_spatial_variance_collapse() {
        let measurements = vec![
            SatelliteMeasurement {
                sat_id: "G01".to_string(),
                constellation: Constellation::Gps,
                band: FrequencyBand::L1,
                carrier_freq_hz: FREQ_GPS_L1_HZ,
                pseudorange_m: 20_000_000.0,
                doppler_hz: 0.0,
                cn0_dbhz: 45.0,
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
                cn0_dbhz: 45.1,
                elevation_deg: 45.0,
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
                cn0_dbhz: 44.9,
                elevation_deg: 80.0,
                azimuth_deg: 300.0,
            },
        ];

        let epoch = GnssEpoch {
            timestamp_sec: 1.0,
            receiver_clock_bias_ns: 0.0,
            agc_level_pct: 50.0,
            measurements,
            pv_solution: None,
            navic_solution: None,
        };

        let report = GnssPhysicsAnalyzer::analyze_epoch_sequence(&[epoch]);
        assert_eq!(report.anomalies.len(), 1);
        assert_eq!(
            report.anomalies[0].kind,
            SpoofingAnomalyKind::SpatialVarianceCollapse
        );
    }

    #[test]
    fn test_doppler_pseudorange_rate_error() {
        let wavelength = SPEED_OF_LIGHT_M_S / FREQ_GPS_L1_HZ;
        // True velocity = -500.0 m/s -> doppler_hz = -(-500.0) / wavelength = 500.0 / wavelength
        let expected_doppler = 500.0 / wavelength;

        let ep1 = GnssEpoch {
            timestamp_sec: 10.0,
            receiver_clock_bias_ns: 0.0,
            agc_level_pct: 50.0,
            measurements: vec![SatelliteMeasurement {
                sat_id: "G07".to_string(),
                constellation: Constellation::Gps,
                band: FrequencyBand::L1,
                carrier_freq_hz: FREQ_GPS_L1_HZ,
                pseudorange_m: 21_000_000.0,
                doppler_hz: expected_doppler,
                cn0_dbhz: 42.0,
                elevation_deg: 30.0,
                azimuth_deg: 90.0,
            }],
            pv_solution: None,
            navic_solution: None,
        };

        // In epoch 2, 1 second later:
        // Pseudorange moves by -550.0 m (pr_rate = -550.0 m/s), but Doppler claims -500.0 m/s (rate error 50.0 m/s > 2.5 m/s)
        let ep2 = GnssEpoch {
            timestamp_sec: 11.0,
            receiver_clock_bias_ns: 0.0,
            agc_level_pct: 50.0,
            measurements: vec![SatelliteMeasurement {
                sat_id: "G07".to_string(),
                constellation: Constellation::Gps,
                band: FrequencyBand::L1,
                carrier_freq_hz: FREQ_GPS_L1_HZ,
                pseudorange_m: 21_000_000.0 - 550.0,
                doppler_hz: expected_doppler, // Claims -500 m/s
                cn0_dbhz: 42.0,
                elevation_deg: 30.1,
                azimuth_deg: 90.1,
            }],
            pv_solution: None,
            navic_solution: None,
        };

        let report = GnssPhysicsAnalyzer::analyze_epoch_sequence(&[ep1, ep2]);
        assert!(report
            .anomalies
            .iter()
            .any(|a| a.kind == SpoofingAnomalyKind::DopplerPseudorangeRateMismatch));
    }

    #[test]
    fn test_multiconstellation_split() {
        let ep = GnssEpoch {
            timestamp_sec: 200.0,
            receiver_clock_bias_ns: 0.0,
            agc_level_pct: 50.0,
            measurements: vec![],
            pv_solution: Some(Position3D::new(100.0, 200.0, 300.0)),
            navic_solution: Some(Position3D::new(100.0, 200.0, 350.0)), // dz = 50m > 35m
        };

        let report = GnssPhysicsAnalyzer::analyze_epoch_sequence(&[ep]);
        assert!(report.is_spoofed);
        assert!(report
            .anomalies
            .iter()
            .any(|a| a.kind == SpoofingAnomalyKind::MultiConstellationPositionSplit));
    }
}
