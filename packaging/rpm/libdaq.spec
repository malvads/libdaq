%global upstream_name libdaq
%define _unpackaged_files_terminate_build 0

%if 0%{?el7}
# el7/{ppc64,ppc64le} Error: No Package found for libdnet-devel
ExclusiveArch:	x86_64 aarch64
%endif

Summary:	Data Acquisition Library
Name:		libdaq
Version:	%{__version}
Release:	1%{?dist}
# sfbpf is BSD (various versions)
License:	GPLv2 and BSD
URL:		https://www.snort.org
Source0:	https://www.snort.org/downloads/snort/%{upstream_name}-%{version}.tar.gz

BuildRequires:	autoconf
BuildRequires:	automake
BuildRequires:	bison
BuildRequires:	flex
BuildRequires:	libtool
BuildRequires:	libdnet-devel
BuildRequires:	libpcap-devel
BuildRequires:	make
BuildRequires:	gcc-c++
BuildRequires:  pfring

# handle license on el{6,7}: global must be defined after the License field above
%{!?_licensedir: %global license %doc}

%description
Snort 3 libdaq

%package modules
Summary:	Dynamic DAQ modules

%description modules
Dynamic DAQ modules.

%package devel
Summary:	Development libraries and headers for %{name}
Requires:	%{name}%{?_isa} = %{version}-%{release}

%description devel
Development libraries and headers for %{name}.

%prep
%autosetup -n %{upstream_name}-%{version}
autoreconf -ivf -Wobsolete

%build
%{configure} --includedir=%{_includedir}/daq
# get rid of rpath
%{__sed} -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
%{__sed} -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool
VERSION=3.0.16 %{__make} V=1

%install
%{make_install}
# get rid of la files
#find $RPM_BUILD_ROOT -type f -name "*.la" -delete -print
# get rid of static libraries
#find $RPM_BUILD_ROOT -type f -name "*.a" -delete -print

%ldconfig_scriptlets

%files
%{_bindir}/daqtest
%{_bindir}/daqtest-static
%{_libdir}/libdaq.so.3
%{_libdir}/libdaq.so.3.0.0
%{_libdir}/daq/daq_afpacket.la
%{_libdir}/daq/daq_pfring.la
%{_libdir}/daq/daq_dump.la
%{_libdir}/daq/daq_pcap.la
%{_libdir}/libdaq.a
%{_libdir}/libdaq.la
%{_libdir}/libdaq_static_afpacket.a
%{_libdir}/libdaq_static_pfring.a
%{_libdir}/libdaq_static_bpf.a
%{_libdir}/libdaq_static_dump.a
%{_libdir}/libdaq_static_fst.a
%{_libdir}/libdaq_static_gwlb.a
%{_libdir}/libdaq_static_pcap.a
%{_libdir}/libdaq_static_savefile.a
%{_libdir}/libdaq_static_trace.a
%license COPYING

%files devel
%{_includedir}/daq/daq.h
%{_includedir}/daq/daq_common.h
%{_includedir}/daq/daq_dlt.h
%{_includedir}/daq/daq_module_api.h
%{_includedir}/daq/daq_version.h
%{_libdir}/libdaq.so

%files modules
%dir %{_libdir}/daq
%{_libdir}/daq/daq_dump.so
%{_libdir}/daq/daq_pcap.so
%{_libdir}/daq/daq_afpacket.so
%{_libdir}/daq/daq_pfring.so
%{_libdir}/daq/daq_bpf.la
%{_libdir}/daq/daq_bpf.so
%{_libdir}/daq/daq_fst.la
%{_libdir}/daq/daq_fst.so
%{_libdir}/daq/daq_gwlb.la
%{_libdir}/daq/daq_gwlb.so
%{_libdir}/daq/daq_savefile.la
%{_libdir}/daq/daq_savefile.so
%{_libdir}/daq/daq_trace.la
%{_libdir}/daq/daq_trace.so
%license COPYING

%changelog
