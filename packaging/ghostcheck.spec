# RPM de GhostCheck: instala el script único como /usr/bin/ghostcheck.
# Construcción (desde la raíz del repositorio):
#   rpmbuild -bb --define "_sourcedir $PWD" packaging/ghostcheck.spec

Name:           ghostcheck
Version:        1.0.0
Release:        1%{?dist}
Summary:        Security audit for RHEL servers in DRY-RUN mode
License:        Unlicense
URL:            https://github.com/jaimefgdev/ghostcheck
Source0:        ghostcheck.py
Source1:        LICENSE
Source2:        README.md
BuildArch:      noarch
Requires:       python3 >= 3.9

%description
GhostCheck audits SELinux, the firewall (firewalld/ufw), local accounts,
the effective sshd configuration and pending security updates (dnf), and
writes TXT, HTML and JSON reports. It only runs a whitelist of read-only
commands and never changes the system.

%prep
cp -p %{SOURCE1} %{SOURCE2} .

%build
# Nada que compilar: es un único script de Python sin dependencias.

%install
install -Dpm 0755 %{SOURCE0} %{buildroot}%{_bindir}/ghostcheck
sed -i '1s|^#!.*|#!%{__python3} -s|' %{buildroot}%{_bindir}/ghostcheck

%check
%{__python3} %{buildroot}%{_bindir}/ghostcheck --version

%files
%license LICENSE
%doc README.md
%{_bindir}/ghostcheck

%changelog
* Wed Sep 30 2026 jaimefg1888 - 1.0.0-1
- Primera versión empaquetada.
