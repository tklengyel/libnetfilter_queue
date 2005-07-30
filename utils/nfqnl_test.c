
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#include <libnfnetlink_queue/libnfnetlink_queue.h>

int main(int argc, char **argv)
{
	struct nfqnl_handle h;
	struct nfqnl_q_handle qh;
	int rv;
	char buf[4096];

	rv = nfqnl_open(&h);
	if (rv < 0)
		exit(rv);

	nfqnl_bind_pf(&h, AF_INET);
	nfqnl_create_queue(&h, &qh, 0);
	nfqnl_set_mode(&qh, NFQNL_COPY_PACKET, 0xffff);

	while (recv(h.nfnlh.fd, buf, sizeof(buf), 0) > 0) {
		printf("pkt received\n");
	}

	nfqnl_destroy_queue(&qh);
	nfqnl_unbind_pf(&h, AF_INET);

	nfqnl_close(&h);

	exit(0);
}
