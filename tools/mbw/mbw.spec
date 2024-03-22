Summary: Memory bandwidth benchmark
Name: mbw
Version: 2.0
Release: 1%{?dist}
License: GPL-3.0-or-later
Buildroot: %{_tmppath}/%{name}-buildroot
Group: System Environment/Base
Source: %{name}.tar.gz
Packager: andras.horvath@gmail.com

%description
Test memory copy bandwidth (single thread). Switch off swap or make sure array size does not exceed available free RAM.

%prep
%setup -n %{name}

%build
make

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}%{_mandir}/man1
install mbw %{buildroot}/usr/bin/mbw
install mbw.1 %{buildroot}%{_mandir}/man1/mbw.1

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%attr(755,-,-) /usr/bin/mbw
%doc
%attr(644,-,-) %{_mandir}/man1/mbw.1.gz

%changelog
* Mon Apr 17 2023 Andras Horvath <andras.horvath@gmail.com> 2.0-1
- Migrated to GPLv3 license
- Small build fixes and cleanups

* Tue Apr 26 2022 Andras Horvath <andras.horvath@gmail.com> 1.5-1
- New platform support (Mac)

* Fri May 04 2018 Andras Horvath <andras.horvath@gmail.com> 1.4-2
- Explicitly specify licence version

* Fri Jan 17 2014  Andras Horvath <andras.horvath@gmail.com> 1.4-1
- Fix labeling of the displayed results

* Thu Oct 03 2013 James Slocum <j.m.slocum@gmail.com> 1.3-1
- Fix MCBLOCK test: copy from the full source buffer, not just its first $blocksize.
- Fix MCBLOCK test: fixed segfault caused by for() going out of bounds

* Sun Mar 11 2012 Andras Horvath <andras.horvath@gmail.com> 1.2-1
- Fix MCBLOCK test: actually copy to the full buffer, not just its first $blocksize.

* Fri Jul 07 2006 Andras Horvath <Andras.Horvath@cern.ch> 1.1-1
- separate array initialization from work -> faster execution
- getopt() options parsing: suppress average, specific tests only, no. runs 
- added quiet mode
- added a new test: memcpy() with given block size

* Wed Apr 26 2006 Andras Horvath <Andras.Horvath@cern.ch> 1.0-1
- initial release
