# Security Policy: lh-gps-spoof-detector

## Threat Model & Resilient PNT Guarantees

`lh-gps-spoof-detector` provides real-time physical-layer and orbital mechanics anomaly detection against multi-band GNSS spoofing, meaconing (record-and-replay), and time-pushing attacks for autonomous robotics, avionics, maritime, and defense infrastructure.

The security architecture mitigates the following threat classes:
1. **SDR Overpower / Capture Spoofing**: Commercial off-the-shelf Software-Defined Radios (HackRF, USRP, BladeRF) emitting high-power counterfeit signals are detected via $C/N_0$ power surge thresholds ($> 54.0\text{ dB-Hz}$) and receiver Front-End AGC gain compression drops ($\Delta\text{AGC} \ge 8\%$).
2. **Single-Antenna Spatial Variance Collapse**: All counterfeit signals radiated from a single ground emitter antenna share identical path loss, collapsing inter-satellite $C/N_0$ variance ($\sigma_{C/N_0}^2 < 0.5\text{ dB}^2$).
3. **Doppler vs. Pseudorange Rate Inconsistency**: Physical orbital motion dictates that carrier Doppler shift and pseudorange rate must be coherent ($|\dot{\rho} - v_{\text{doppler}}| \le 2.5\text{ m/s}$). Inconsistent simulated Doppler profiles are immediately flagged.
4. **Clock Bias Dragging & Time-Pushing**: Adversaries gradually manipulating receiver internal time are flagged via clock drift rate thresholds ($|\dot{b}_{\text{clk}}| > 50\text{ ns/s}$).
5. **Constellation Position Splits**: Comparing GPS L1 position solutions against India NavIC (L5 / S-band) geostationary signals detects constellation-selective spoofing when 3D separation exceeds $35\text{ m}$.
6. **Forged Keplerian Ephemerides**: Counterfeit navigation frames broadcasting unphysical orbital parameters (eccentricity, semi-major axis, inclination) are flagged via Keplerian orbital mechanics.

## Reporting a Vulnerability

Please report security vulnerabilities or detector bypass mechanisms to `security@logihertz.com` with a copy to `ops@logihertz.com`. We coordinate disclosure and issue patches promptly.
