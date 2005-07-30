/* libnfqnetlink.h: Header file for the Netfilter Queue library.
 *
 * (C) 2005 by Harald Welte <laforge@gnumonks.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#ifndef __LIBCTNETLINK_H
#define __LIBCTNETLINK_H

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnfnetlink.h>


#define NFQN
struct nfqnl_handle
{
	struct nfnl_handle nfnlh;
};

struct nfqnl_q_handle
{
	struct nfqnl_handle *h;
	u_int16_t id;
};

struct ctnl_msg_handler {
	int type;
	int (*handler)(struct sockaddr_nl *, struct nlmsghdr *, void *arg);
};

struct ctnl_handle {
	struct nfnl_handle nfnlh;
	struct ctnl_msg_handler *handler[NFQNL_MSG_MAX];
};

extern int nfqnl_open(struct nfqnl_handle *h);
extern int nfqnl_close(struct nfqnl_handle *h);

extern int nfqnl_bind_pf(struct nfqnl_handle *h, u_int16_t pf);
extern int nfqnl_unbind_pf(struct nfqnl_handle *h, u_int16_t pf);

extern int nfqnl_create_queue(struct nfqnl_handle *h,
			      struct nfqnl_q_handle *qh, u_int16_t num);
extern int nfqnl_destroy_queue(struct nfqnl_q_handle *qh);

extern int nfqnl_set_mode(struct nfqnl_q_handle *qh,
			  u_int8_t mode, unsigned int len);

extern int nfqnl_set_verdict(struct nfqnl_q_handle *qh,
			     u_int32_t id,
			     u_int32_t verdict,
			     u_int32_t data_len,
			     unsigned char *buf);

extern int nfqnl_set_verdict_mark(struct nfqnl_q_handle *qh, u_int32_t id,
			   u_int32_t verdict, u_int32_t mark,
			   u_int32_t datalen, unsigned char *buf);
#endif	/* __LIBNFQNETLINK_H */
