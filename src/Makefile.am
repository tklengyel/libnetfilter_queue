
INCLUDES = $(all_includes) -I$(top_srcdir)/include -I${KERNELDIR}
AM_CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libnetfilter_queue.la libnetfilter_queue_libipq.la

libnetfilter_queue_la_LDFLAGS = -Wc,-nostartfiles
libnetfilter_queue_la_SOURCES = libnetfilter_queue.c 

libnetfilter_queue_libipq_la_LDFLAGS = -Wc,-nostartfiles
libnetfilter_queue_libipq_la_SOURCES = libipq_compat.c

