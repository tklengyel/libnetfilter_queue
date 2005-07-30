bin_PROGRAMS = nfqnl_test
nfqnl_test_SOURCES = nfqnl_test.c


INCLUDES = $(all_includes) -I$(top_srcdir)/include -I${KERNELDIR} 

nfqnl_test_LDFLAGS = $(all_libraries) -lnfnetlink_queue -lnfnetlink

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
