Name:		elliptics-fastcgi
Version:	1.4-1-ell2.20
Release:	1%{?dist}
Summary:	Daemon

Group:		System Environment/Libraries
License:	GPLv2+
URL:		http://www.ioremap.net/projects/elliptics
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:	fastcgi-daemon2-libs-devel, curl, elliptics-devel, elliptics-c++-devel, libgeobase3-devel, autoconf, automake, libtool, pkgconfig, openssl-devel, boost-devel, curl-devel, eblob-devel elliptics-regional-module libyandex-user-settings-devel
BuildRequires:  fcgi-devel, openssl-devel, libxml2-devel

%description
Elliptics is one of the best prodution enterprise high scalability and
availability system, wrote by one of the most genius software developers
of the whole World. This is just a shitty FastCGI proxy for Elliptics, wrote
by the dick from the mountain.


%prep
%setup -q


%build
ACLOCAL_OPTIONS="-I config" ./autogen.sh
%configure
make %{?_smp_mflags}

%check
make check

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%{_libdir}/*
%{_includedir}/*


%changelog
* Mon Dec 10 2012 Evgeniy Polyakov <zbr@ioremap.net> - 1.4-1-ell2.20
- Ported to elliptics 2.20

* Mon Dec 03 2012 Evgeniy Polyakov <zbr@ioremap.net> - 1.3-3-ell2.19
- Update elliptics deps

* Mon Dec 03 2012 Evgeniy Polyakov <zbr@ioremap.net> - 1.3-2-ell2.19
- Rebuild proxy to match cpp binding update

* Wed Oct  5 2011 Arkady L. Shane <ashejn@yandex-team.ru> - 1.1.23-1
- initial build
