AUTOMAKE_OPTIONS = no-dependencies foreign

EXTRA_DIST = $(man_MANS) acinclude.m4

SUBDIRS = include include/libnfnetlink_queue src utils

man_MANS = #nfnetlink_queue.3 nfnetlink_queue.7

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
