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
#include <libnfnetlink/libnfnetlink.h>

struct nfqnl_handle;
struct nfqnl_q_handle;

extern int nfqnl_errno;

extern struct nfnl_handle *nfqnl_nfnlh(struct nfqnl_handle *h);
extern int nfqnl_fd(struct nfqnl_handle *h);

typedef nfqnl_callback(struct nfqnl_q_handle *gh, struct nfgenmsg *nfmsg,
		       struct nfattr *nfa[], void *data);


extern struct nfqnl_handle *nfqnl_open(void);
extern int nfqnl_close(struct nfqnl_handle *h);

extern int nfqnl_bind_pf(struct nfqnl_handle *h, u_int16_t pf);
extern int nfqnl_unbind_pf(struct nfqnl_handle *h, u_int16_t pf);

extern struct nfqnl_q_handle *nfqnl_create_queue(struct nfqnl_handle *h,
			      			 u_int16_t num,
						 nfqnl_callback *cb,
						 void *data);
extern int nfqnl_destroy_queue(struct nfqnl_q_handle *qh);

extern int nfqnl_handle_packet(struct nfqnl_handle *h, char *buf, int len);

extern int nfqnl_set_mode(struct nfqnl_q_handle *qh,
			  u_int8_t mode, unsigned int len);

extern int nfqnl_set_verdict(struct nfqnl_q_handle *qh,
			     u_int32_t id,
			     u_int32_t verdict,
			     u_int32_t data_len,
			     unsigned char *buf);
extern int nfqnl_set_verdict_mark(struct nfqnl_q_handle *qh, 
				  u_int32_t id,
			   	  u_int32_t verdict, 
				  u_int32_t mark,
			   	  u_int32_t datalen,
				  unsigned char *buf);
#endif	/* __LIBNFQNETLINK_H */
