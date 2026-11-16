Name:           lh-gps-spoof-detector
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-gps-spoof - Doppler-Pseudorange Residual Divergence Invariant
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-gps-spoof-detector
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      %{_arch}

%description
Pure-Rust multi-band GPS (L1/L2/L5) & India NavIC (IRNSS L5/S-band) spoofing detector analyzing C/N0 surges, AGC compression, spatial variance collapse, Doppler-pseudorange divergence, and Keplerian ephemeris bounds.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-gps-spoof ]; then
    install -m 0755 bin/lh-gps-spoof %{buildroot}%{_bindir}/lh-gps-spoof
elif [ -f lh-gps-spoof ]; then
    install -m 0755 lh-gps-spoof %{buildroot}%{_bindir}/lh-gps-spoof
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for lh-gps-spoof-detector.
