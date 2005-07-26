AUTOMAKE_OPTIONS = no-dependencies foreign

EXTRA_DIST = $(man_MANS) acinclude.m4

man_MANS =

INCLUDES=-I../include -I/lib/modules/$(shell (uname -r))/build/include
CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libnfnetlink_queue

libnfqnetlink_la_LDFLAGS = -Wc,-nostartfiles
libnfqnetlink_la_SOURCES = libnfnetlink_queue.c

include_HEADERS = libnfnetlink_queue.h 

man_MANS = #nfnetlink_queue.3 nfnetlink_queue.7

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
