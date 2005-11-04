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

#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

struct nfqnl_handle
{
	struct nfnl_handle nfnlh;
	struct nfqnl_q_handle *qh_list;
};

struct nfqnl_q_handle
{
	struct nfqnl_q_handle *next;
	struct nfqnl_handle *h;
	u_int16_t id;

	nfqnl_callback *cb;
	void *data;
};


int nfqnl_errno;

/***********************************************************************
 * low level stuff 
 ***********************************************************************/

static void del_qh(struct nfqnl_q_handle *qh)
{
	struct nfqnl_q_handle *cur_qh, *prev_qh = NULL;

	for (cur_qh = qh->h->qh_list; cur_qh; cur_qh = cur_qh->next) {
		if (cur_qh == qh) {
			if (prev_qh)
				prev_qh->next = qh->next;
			else
				qh->h->qh_list = qh->next;
			return;
		}
		prev_qh = cur_qh;
	}
}

static void add_qh(struct nfqnl_q_handle *qh)
{
	qh->next = qh->h->qh_list;
	qh->h->qh_list = qh;
}

static struct nfqnl_q_handle *find_qh(struct nfqnl_handle *h, u_int16_t id)
{
	struct nfqnl_q_handle *qh;

	for (qh = h->qh_list; qh; qh = qh->next) {
		if (qh->id == id)
			return qh;
	}
	return NULL;
}

/* build a NFQNL_MSG_CONFIG message */
	static int
__build_send_cfg_msg(struct nfqnl_handle *h, u_int8_t command,
		u_int16_t queuenum, u_int16_t pf)
{
	char buf[NFNL_HEADER_LEN
		+NFA_LENGTH(sizeof(struct nfqnl_msg_config_cmd))];
	struct nfqnl_msg_config_cmd cmd;
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(&h->nfnlh, nmh, 0, AF_UNSPEC, queuenum,
			NFQNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	cmd.command = command;
	cmd.pf = htons(pf);
	nfnl_addattr_l(nmh, sizeof(buf), NFQA_CFG_CMD, &cmd, sizeof(cmd));

	return nfnl_talk(&h->nfnlh, nmh, 0, 0, NULL, NULL, NULL);
}

static int __nfqnl_rcv_pkt(struct nlmsghdr *nlh, struct nfattr *nfa[],
		void *data)
{
	struct nfgenmsg *nfmsg = NLMSG_DATA(nlh);
	struct nfqnl_handle *h = data;
	u_int16_t queue_num = ntohs(nfmsg->res_id);
	struct nfqnl_q_handle *qh = find_qh(h, queue_num);

	if (!qh)
		return -ENODEV;

	if (!qh->cb)
		return -ENODEV;

	return qh->cb(qh, nfmsg, nfa, qh->data);
}

static struct nfnl_callback pkt_cb = {
	.call		= &__nfqnl_rcv_pkt,
	.attr_count	= NFQA_MAX,
};

/* public interface */

struct nfnl_handle *nfqnl_nfnlh(struct nfqnl_handle *h)
{
	return &h->nfnlh;
}

int nfqnl_fd(struct nfqnl_handle *h)
{
	return nfnl_fd(nfqnl_nfnlh(h));
}

struct nfqnl_handle *nfqnl_open(void)
{
	struct nfqnl_handle *h;
	int err;

	h = malloc(sizeof(*h));
	if (!h)
		return NULL;

	memset(h, 0, sizeof(*h));

	err = nfnl_open(&h->nfnlh, NFNL_SUBSYS_QUEUE, NFQNL_MSG_MAX, 0);
	if (err < 0) {
		nfqnl_errno = err;
		goto out_free;
	}

	pkt_cb.data = h;
	err = nfnl_callback_register(&h->nfnlh, NFQNL_MSG_PACKET, &pkt_cb);
	if (err < 0) {
		nfqnl_errno = err;
		goto out_close;
	}

	return h;
out_close:
	nfnl_close(&h->nfnlh);
out_free:
	free(h);
	return NULL;
}

int nfqnl_close(struct nfqnl_handle *h)
{
	int ret = nfnl_close(&h->nfnlh);
	if (ret == 0)
		free(h);
	return ret;
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
struct nfqnl_q_handle *nfqnl_create_queue(struct nfqnl_handle *h, 
		u_int16_t num,
		nfqnl_callback *cb,
		void *data)
{
	int ret;
	struct nfqnl_q_handle *qh;

	if (find_qh(h, num))
		return NULL;

	qh = malloc(sizeof(*qh));

	memset(qh, 0, sizeof(*qh));
	qh->h = h;
	qh->id = num;
	qh->cb = cb;
	qh->data = data;

	ret = __build_send_cfg_msg(h, NFQNL_CFG_CMD_BIND, num, 0);
	if (ret < 0) {
		nfqnl_errno = ret;
		free(qh);
		return NULL;
	}

	add_qh(qh);
	return qh;
}

/* unbind this socket from a specific queue number */
int nfqnl_destroy_queue(struct nfqnl_q_handle *qh)
{
	int ret = __build_send_cfg_msg(qh->h, NFQNL_CFG_CMD_UNBIND, qh->id, 0);
	if (ret == 0) {
		del_qh(qh);
		free(qh);
	}

	return ret;
}

int nfqnl_handle_packet(struct nfqnl_handle *h, char *buf, int len)
{
	return nfnl_handle_packet(&h->nfnlh, buf, len);
}

int nfqnl_set_mode(struct nfqnl_q_handle *qh,
		u_int8_t mode, u_int32_t range)
{
	char buf[NFNL_HEADER_LEN
		+NFA_LENGTH(sizeof(struct nfqnl_msg_config_params))];
	struct nfqnl_msg_config_params params;
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(&qh->h->nfnlh, nmh, 0, AF_UNSPEC, qh->id,
			NFQNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	params.copy_range = htonl(range);
	params.copy_mode = mode;
	nfnl_addattr_l(nmh, sizeof(buf), NFQA_CFG_PARAMS, &params,
			sizeof(params));

	return nfnl_talk(&qh->h->nfnlh, nmh, 0, 0, NULL, NULL, NULL);
}

static int __set_verdict(struct nfqnl_q_handle *qh, u_int32_t id,
		u_int32_t verdict, u_int32_t mark, int set_mark,
		u_int32_t data_len, unsigned char *data)
{
	struct nfqnl_msg_verdict_hdr vh;
	char buf[NFNL_HEADER_LEN
		+NFA_LENGTH(sizeof(mark))
		+NFA_LENGTH(sizeof(vh))];
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	struct iovec iov[3];
	int nvecs;

	memset(iov, 0, sizeof(iov));

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

/*************************************************************
 * Message parsing functions 
 *************************************************************/

struct nfqnl_msg_packet_hdr *nfqnl_get_msg_packet_hdr(struct nfattr *nfa[])
{
	return nfnl_get_pointer_to_data(nfa, NFQA_PACKET_HDR,
					struct nfqnl_msg_packet_hdr);
}

uint32_t nfqnl_get_nfmark(struct nfattr *nfa[])
{
	return ntohl(nfnl_get_data(nfa, NFQA_MARK, u_int32_t));
}

struct nfqnl_msg_packet_timestamp *nfqnl_get_timestamp(struct nfattr *nfa[])
{
	return nfnl_get_pointer_to_data(nfa, NFQA_TIMESTAMP,
					struct nfqnl_msg_packet_timestamp);
}

/* all nfqnl_get_*dev() functions return 0 if not set, since linux only allows
 * ifindex >= 1, see net/core/dev.c:2600  (in 2.6.13.1) */
u_int32_t nfqnl_get_indev(struct nfattr *nfa[])
{
	return ntohl(nfnl_get_data(nfa, NFQA_IFINDEX_INDEV, u_int32_t));
}

u_int32_t nfqnl_get_physindev(struct nfattr *nfa[])
{
	return ntohl(nfnl_get_data(nfa, NFQA_IFINDEX_PHYSINDEV, u_int32_t));
}

u_int32_t nfqnl_get_outdev(struct nfattr *nfa[])
{
	return ntohl(nfnl_get_data(nfa, NFQA_IFINDEX_OUTDEV, u_int32_t));
}

u_int32_t nfqnl_get_physoutdev(struct nfattr *nfa[])
{
	return ntohl(nfnl_get_data(nfa, NFQA_IFINDEX_PHYSOUTDEV, u_int32_t));
}

struct nfqnl_msg_packet_hw *nfqnl_get_packet_hw(struct nfattr *nfa[])
{
	return nfnl_get_pointer_to_data(nfa, NFQA_HWADDR,
					struct nfqnl_msg_packet_hw);
}

int nfqnl_get_payload(struct nfattr *nfa[], char **data,
		      unsigned int *datalen)
{
	*data = nfnl_get_pointer_to_data(nfa, NFQA_PAYLOAD, char);
	if (*data) {
		*datalen = NFA_PAYLOAD(nfa[NFQA_PAYLOAD-1]);
		return 1;
	}
	return 0;
}
