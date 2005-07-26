
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#include "libnfqnetlink.h"

int main(int argc, char **argv)
{
	struct nfqnl_handle h;
	int rv;
	char buf[4096];

	rv = nfqnl_open(&h, 0);
	if (rv < 0)
		exit(rv);

	nfqnl_bind_pf(&h, AF_INET);
	nfqnl_bind(&h, 0);
	nfqnl_set_mode(&h, 0, NFQNL_COPY_PACKET, 0xffff);

	while (recv(h.nfnlh.fd, buf, sizeof(buf), 0) > 0) {
		printf("pkt received\n");
	}

	nfqnl_unbind(&h, 0);
	nfqnl_unbind_pf(&h, AF_INET);

	nfqnl_close(&h);

	exit(0);
}
