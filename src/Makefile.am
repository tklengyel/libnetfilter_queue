
INCLUDES = $(all_includes) -I$(top_srcdir)/include -I${KERNELDIR}
AM_CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libnfnetlink_queue.la libnfnetlink_queue_libipq.la

libnfnetlink_queue_la_LDFLAGS = -Wc,-nostartfiles
libnfnetlink_queue_la_SOURCES = libnfnetlink_queue.c 

libnfnetlink_queue_libipq_la_LDFLAGS = -Wc,-nostartfiles
libnfnetlink_queue_libipq_la_SOURCES = libipq_compat.c

