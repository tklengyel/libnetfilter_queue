AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

EXTRA_DIST = $(man_MANS) 

SUBDIRS = include src utils

man_MANS = #nfnetlink_queue.3 nfnetlink_queue.7

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnetfilter_queue.pc

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
