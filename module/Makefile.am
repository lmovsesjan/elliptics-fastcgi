pkglibdir = $(libdir)/fastcgi2/

pkglib_LTLIBRARIES = elliptics-fastcgi.la

headerdir = $(includedir)/fastcgi-elliptics/

elliptics_fastcgi_la_SOURCES = elliptics_fastcgi.cpp embed_processor.cpp
elliptics_fastcgi_la_LDFLAGS = -module @VERSION_INFO@ @FASTCGIDAEMON_LIBS@ @ELLIPTICS_LIBS@

if HAVE_REGIONAL
elliptics_fastcgi_la_LDFLAGS += $(libdir)/fastcgi2/elliptics-regional-module.la
endif

AM_CXXFLAGS = -W -Wall -g -O2 -fPIC
AM_CPPFLAGS = -I @top_srcdir@/config/ @BOOST_CPPFLAGS@ @FASTCGIDAEMON_CFLAGS@ @ELLIPTICS_CFLAGS@
AM_LDFLAGS  = @BOOST_THREAD_LDFLAGS@

noinst_HEADERS = boost_threaded.hpp curl_wrapper.hpp elliptics_fastcgi.hpp writer.hpp
header_HEADERS = embed_processor.hpp

