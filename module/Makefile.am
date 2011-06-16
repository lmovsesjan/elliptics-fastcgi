pkglibdir = $(libdir)/fastcgi2/

pkglib_LTLIBRARIES = elliptics-fastcgi.la

elliptics_fastcgi_la_SOURCES = elliptics_fastcgi.cpp refresher.cpp
elliptics_fastcgi_la_LDFLAGS = -module @VERSION_INFO@ @FASTCGIDAEMON_LIBS@

if HAVE_GEOBASE
elliptics_fastcgi_la_LDFLAGS += /usr/lib/fastcgi2/elliptics-regional-module.la
endif

AM_CXXFLAGS = -W -Wall -g -O2 -fPIC
AM_CPPFLAGS = -I @top_srcdir@/config/ @BOOST_CPPFLAGS@ @FASTCGIDAEMON_CFLAGS@
AM_LDFLAGS  = @BOOST_THREAD_LDFLAGS@

noinst_HEADERS = elliptics_fastcgi.hpp refresher.hpp

