/* libnfqnetlink.c: generic library for access to nf_queue
 *
 * (C) 2005 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <libnfnetlink/libnfnetlink.h>
#include <libnfnetlink_queue/libnfnetlink_queue.h>

/***********************************************************************
 * low level stuff 
 ***********************************************************************/

int nfqnl_open(struct nfqnl_handle *h)
{
	int err;

	memset(h, 0, sizeof(*h));

	err = nfnl_open(&h->nfnlh, NFNL_SUBSYS_QUEUE, 0);
	if (err < 0)
		return err;

	return 0;
}

int nfqnl_close(struct nfqnl_handle *h)
{
	return nfnl_close(&h->nfnlh);
}

/* build a NFQNL_MSG_CONFIG message */
static int
__build_send_cfg_msg(struct nfqnl_handle *h, u_int8_t command,
		     u_int16_t queuenum, u_int16_t pf)
{
	char buf[NLMSG_LENGTH(sizeof(struct nlmsghdr))
		+NLMSG_LENGTH(sizeof(struct nfgenmsg))
		+NFA_LENGTH(sizeof(struct nfqnl_msg_config_cmd))];
	struct nfqnl_msg_config_cmd cmd;
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(&h->nfnlh, nmh, 0, AF_UNSPEC, queuenum,
		      NFQNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	cmd.command = command;
	cmd.pf = htons(pf);
	nfnl_addattr_l(nmh, sizeof(buf), NFQA_CFG_CMD, &cmd, sizeof(cmd));

	return nfnl_send(&h->nfnlh, nmh);
}

/* bind nf_queue from a specific protocol family */
int nfqnl_bind_pf(struct nfqnl_handle *h, u_int16_t pf)
{
	return __build_send_cfg_msg(h, NFQNL_CFG_CMD_PF_BIND, 0, pf);
}

/* unbind nf_queue from a specific protocol family */
int nfqnl_unbind_pf(struct nfqnl_handle *h, u_int16_t pf)
{
	return __build_send_cfg_msg(h, NFQNL_CFG_CMD_PF_UNBIND, 0, pf);
}

/* bind this socket to a specific queue number */
int nfqnl_create_queue(struct nfqnl_handle *h,
		       struct nfqnl_q_handle *qh, u_int16_t num)
{
	qh->h = h;
	qh->id = num;

	return __build_send_cfg_msg(h, NFQNL_CFG_CMD_BIND, num, 0);
}

/* unbind this socket from a specific queue number */
int nfqnl_destroy_queue(struct nfqnl_q_handle *qh)
{
	int ret = __build_send_cfg_msg(qh->h, NFQNL_CFG_CMD_UNBIND, qh->id, 0);
	if (ret == 0)
		qh->h = NULL;

	return ret;
}

int nfqnl_set_mode(struct nfqnl_q_handle *qh,
		   u_int8_t mode, u_int32_t range)
{
	char buf[NLMSG_LENGTH(sizeof(struct nlmsghdr))
		+NLMSG_LENGTH(sizeof(struct nfgenmsg))
		+NFA_LENGTH(sizeof(struct nfqnl_msg_config_params))];
	struct nfqnl_msg_config_params params;
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(&qh->h->nfnlh, nmh, 0, AF_UNSPEC, qh->id,
		      NFQNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	params.copy_range = htonl(range);
	params.copy_mode = mode;
	nfnl_addattr_l(nmh, sizeof(buf), NFQA_CFG_PARAMS, &params,
		       sizeof(params));

	return nfnl_send(&qh->h->nfnlh, nmh);
}

static int __set_verdict(struct nfqnl_q_handle *qh, u_int32_t id,
			 u_int32_t verdict, u_int32_t mark, int set_mark,
			 u_int32_t data_len, unsigned char *data)
{
	struct nfqnl_msg_verdict_hdr vh;
	char buf[NLMSG_LENGTH(sizeof(struct nlmsghdr))
		+NLMSG_LENGTH(sizeof(struct nfgenmsg))
		+NFA_LENGTH(sizeof(mark))
		+NFA_LENGTH(sizeof(vh))];
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	struct iovec iov[3];
	int nvecs;

	vh.verdict = htonl(verdict);
	vh.id = htonl(id);

	nfnl_fill_hdr(&qh->h->nfnlh, nmh, 0, AF_UNSPEC, qh->id,
		      NFQNL_MSG_VERDICT, NLM_F_REQUEST);
			
	/* add verdict header */
	nfnl_addattr_l(nmh, sizeof(buf), NFQA_VERDICT_HDR, &vh, sizeof(vh));

	if (set_mark)
		nfnl_addattr32(nmh, sizeof(buf), NFQA_MARK, mark);

	iov[0].iov_base = nmh;
	iov[0].iov_len = NLMSG_TAIL(nmh) - (void *)nmh;
	nvecs = 1;

	if (data_len) {
		struct nfattr data_attr;

		nfnl_build_nfa_iovec(&iov[1], &data_attr, NFQA_PAYLOAD,
				     data_len, data);
		nvecs += 2;
	}

	return nfnl_sendiov(&qh->h->nfnlh, iov, nvecs, 0);
}

int nfqnl_set_verdict(struct nfqnl_q_handle *qh, u_int32_t id,
		      u_int32_t verdict, u_int32_t data_len, 
		      unsigned char *buf)
{
	return __set_verdict(qh, id, verdict, 0, 0, data_len, buf);
}	

int nfqnl_set_verdict_mark(struct nfqnl_q_handle *qh, u_int32_t id,
			   u_int32_t verdict, u_int32_t mark,
			   u_int32_t datalen, unsigned char *buf)
{
	return __set_verdict(qh, id, verdict, mark, 1, datalen, buf);
}
