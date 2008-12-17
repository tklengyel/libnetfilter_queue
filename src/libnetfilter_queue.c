/* libnetfilter_queue.c: generic library for access to nf_queue
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
 *
 *  2006-01-23 Andreas Florath <andreas@florath.net>
 *	Fix __set_verdict() that it can now handle payload.
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

struct nfq_handle
{
	struct nfnl_handle *nfnlh;
	struct nfnl_subsys_handle *nfnlssh;
	struct nfq_q_handle *qh_list;
};

struct nfq_q_handle
{
	struct nfq_q_handle *next;
	struct nfq_handle *h;
	u_int16_t id;

	nfq_callback *cb;
	void *data;
};

struct nfq_data {
	struct nfattr **data;
};

int nfq_errno;

/***********************************************************************
 * low level stuff 
 ***********************************************************************/

static void del_qh(struct nfq_q_handle *qh)
{
	struct nfq_q_handle *cur_qh, *prev_qh = NULL;

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

static void add_qh(struct nfq_q_handle *qh)
{
	qh->next = qh->h->qh_list;
	qh->h->qh_list = qh;
}

static struct nfq_q_handle *find_qh(struct nfq_handle *h, u_int16_t id)
{
	struct nfq_q_handle *qh;

	for (qh = h->qh_list; qh; qh = qh->next) {
		if (qh->id == id)
			return qh;
	}
	return NULL;
}

/* build a NFQNL_MSG_CONFIG message */
	static int
__build_send_cfg_msg(struct nfq_handle *h, u_int8_t command,
		u_int16_t queuenum, u_int16_t pf)
{
	union {
		char buf[NFNL_HEADER_LEN
			+NFA_LENGTH(sizeof(struct nfqnl_msg_config_cmd))];
		struct nlmsghdr nmh;
	} u;
	struct nfqnl_msg_config_cmd cmd;

	nfnl_fill_hdr(h->nfnlssh, &u.nmh, 0, AF_UNSPEC, queuenum,
			NFQNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	cmd.command = command;
	cmd.pf = htons(pf);
	nfnl_addattr_l(&u.nmh, sizeof(u), NFQA_CFG_CMD, &cmd, sizeof(cmd));

	return nfnl_talk(h->nfnlh, &u.nmh, 0, 0, NULL, NULL, NULL);
}

static int __nfq_rcv_pkt(struct nlmsghdr *nlh, struct nfattr *nfa[],
		void *data)
{
	struct nfgenmsg *nfmsg = NLMSG_DATA(nlh);
	struct nfq_handle *h = data;
	u_int16_t queue_num = ntohs(nfmsg->res_id);
	struct nfq_q_handle *qh = find_qh(h, queue_num);
	struct nfq_data nfqa;

	if (!qh)
		return -ENODEV;

	if (!qh->cb)
		return -ENODEV;

	nfqa.data = nfa;

	return qh->cb(qh, nfmsg, &nfqa, qh->data);
}

static struct nfnl_callback pkt_cb = {
	.call		= &__nfq_rcv_pkt,
	.attr_count	= NFQA_MAX,
};

/* public interface */

struct nfnl_handle *nfq_nfnlh(struct nfq_handle *h)
{
	return h->nfnlh;
}

/**
 * nfq_fd - get the file descriptor associated with the nfqueue handler
 * @h: Netfilter queue connection handle obtained via call to nfq_open()
 *
 * Returns a file descriptor for the netlink connection associated with the
 * given queue connection handle. The file descriptor can then be used for
 * receiving the queued packets for processing.
 *
 * Example:
 *
 *	fd = nfq_fd(h);
 *	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
 * 		printf("pkt received\n");
 * 		nfq_handle_packet(h, buf, rv);
 * 	}
 *
 * This function returns a file descriptor that can be used for communication
 * over the netlink connection associated with the given queue connection
 * handle.
 */
int nfq_fd(struct nfq_handle *h)
{
	return nfnl_fd(nfq_nfnlh(h));
}

/**
 * nfq_open - open a nfqueue handler
 *
 * This function obtains a netfilter queue connection handle. When you are
 * finished with the handle returned by this function, you should destroy
 * it by calling nfq_close(). A new netlink connection is obtained internally
 * and associated with the queue connection handle returned.
 *
 * This function returns a pointer to a new queue handle or NULL on failure.
 */
struct nfq_handle *nfq_open(void)
{
	struct nfnl_handle *nfnlh = nfnl_open();
	struct nfq_handle *qh;

	if (!nfnlh)
		return NULL;

	qh = nfq_open_nfnl(nfnlh);
	if (!qh)
		nfnl_close(nfnlh);

	return qh;
}

/**
 * nfq_open_nfnl - open a nfqueue handler from a existing nfnetlink handler
 * @nfnlh: Netfilter netlink connection handle obtained by calling nfnl_open()
 *
 * This function obtains a netfilter queue connection handle using an existing
 * netlink connection. This function is used internally to implement 
 * nfq_open(), and should typically not be called directly.
 *
 * This function returns a pointer to a new queue handle or NULL on failure.
 */			
struct nfq_handle *nfq_open_nfnl(struct nfnl_handle *nfnlh)
{
	struct nfq_handle *h;
	int err;

	h = malloc(sizeof(*h));
	if (!h)
		return NULL;

	memset(h, 0, sizeof(*h));
	h->nfnlh = nfnlh;

	h->nfnlssh = nfnl_subsys_open(h->nfnlh, NFNL_SUBSYS_QUEUE, 
				      NFQNL_MSG_MAX, 0);
	if (!h->nfnlssh) {
		/* FIXME: nfq_errno */
		goto out_free;
	}

	pkt_cb.data = h;
	err = nfnl_callback_register(h->nfnlssh, NFQNL_MSG_PACKET, &pkt_cb);
	if (err < 0) {
		nfq_errno = err;
		goto out_close;
	}

	return h;
out_close:
	nfnl_subsys_close(h->nfnlssh);
out_free:
	free(h);
	return NULL;
}

/**
 * nfq_close - close a nfqueue handler
 * @h: Netfilter queue connection handle obtained via call to nfq_open()
 *
 * This function closes the nfqueue handler and free associated resources.
 *
 * This function returns 0 on success, non-zero on failure. 
 */
int nfq_close(struct nfq_handle *h)
{
	int ret;
	
	ret = nfnl_close(h->nfnlh);
	if (ret == 0)
		free(h);
	return ret;
}

/**
 * nfq_bind_pf - bind a nfqueue handler to a given protocol family
 * @h: Netfilter queue connection handle obtained via call to nfq_open()
 * @pf: protocol family to bind to nfqueue handler obtained from nfq_open()
 *
 * Binds the given queue connection handle to process packets belonging to 
 * the given protocol family (ie. PF_INET, PF_INET6, etc).
 */
int nfq_bind_pf(struct nfq_handle *h, u_int16_t pf)
{
	return __build_send_cfg_msg(h, NFQNL_CFG_CMD_PF_BIND, 0, pf);
}

/**
 * nfq_unbind_pf - unbind nfqueue handler from a protocol family
 * @h: Netfilter queue connection handle obtained via call to nfq_open()
 * @pf: protocol family to unbind family from
 *
 * Unbinds the given queue connection handle from processing packets belonging
 * to the given protocol family.
 */
int nfq_unbind_pf(struct nfq_handle *h, u_int16_t pf)
{
	return __build_send_cfg_msg(h, NFQNL_CFG_CMD_PF_UNBIND, 0, pf);
}

/**
 * nfq_create_queue - create a new queue handle and return it.
 * @h: Netfilter queue connection handle obtained via call to nfq_open()
 * @num: the number of the queue to bind to
 * @cb: callback function to call for each queued packet
 * @data: custom data to pass to the callback function
 *
 * Creates a new queue handle, and returns it.  The new queue is identified by
 * <num>, and the callback specified by <cb> will be called for each enqueued
 * packet.  The <data> argument will be passed unchanged to the callback.  If
 * a queue entry with id <num> already exists, this function will return failure
 * and the existing entry is unchanged.
 *
 * The nfq_callback type is defined in libnetfilter_queue.h as:
 *
 * typedef int nfq_callback(struct nfq_q_handle *qh,
 * 			    struct nfgenmsg *nfmsg,
 * 			    struct nfq_data *nfad, void *data);
 *
 * Parameters:
 * @qh: The queue handle returned by nfq_create_queue
 * @nfmsg: message objetc that contains the packet
 * @nfq_data: Netlink packet data handle
 * @data: the value passed to the data parameter of nfq_create_queue
 *
 * The callback should return < 0 to stop processing.
 */
struct nfq_q_handle *nfq_create_queue(struct nfq_handle *h, 
		u_int16_t num,
		nfq_callback *cb,
		void *data)
{
	int ret;
	struct nfq_q_handle *qh;

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
		nfq_errno = ret;
		free(qh);
		return NULL;
	}

	add_qh(qh);
	return qh;
}

/**
 * nfq_destroy_queue - destroy a queue handle
 * @qh: queue handle that we want to destroy created via nfq_create_queue
 *
 * Removes the binding for the specified queue handle. This call also unbind
 * from the nfqueue handler, so you don't have to call nfq_unbind_pf.
 */
int nfq_destroy_queue(struct nfq_q_handle *qh)
{
	int ret = __build_send_cfg_msg(qh->h, NFQNL_CFG_CMD_UNBIND, qh->id, 0);
	if (ret == 0) {
		del_qh(qh);
		free(qh);
	}

	return ret;
}

/**
 * nfq_handle_packet - handle a packet received from the nfqueue subsystem
 * @h: Netfilter queue connection handle obtained via call to nfq_open()
 * @buf: data to pass to the callback
 * @len: length of packet data in buffer
 *
 * Triggers an associated callback for the given packet received from the
 * queue. Packets can be read from the queue using nfq_fd() and recv(). See
 * example code for nfq_fd().
 *
 * Returns 0 on success, non-zero on failure.
 */
int nfq_handle_packet(struct nfq_handle *h, char *buf, int len)
{
	return nfnl_handle_packet(h->nfnlh, buf, len);
}

/**
 * nfq_set_mode - set the amount of packet data that nfqueue copies to userspace
 * @qh: Netfilter queue handle obtained by call to nfq_create_queue().
 * @mode: the part of the packet that we are interested in
 * @range: size of the packet that we want to get
 *
 * Sets the amount of data to be copied to userspace for each packet queued
 * to the given queue.
 *
 * - NFQNL_COPY_NONE - do not copy any data
 * - NFQNL_COPY_META - copy only packet metadata
 * - NFQNL_COPY_PACKET - copy entire packet
 */
int nfq_set_mode(struct nfq_q_handle *qh,
		u_int8_t mode, u_int32_t range)
{
	union {
		char buf[NFNL_HEADER_LEN
			+NFA_LENGTH(sizeof(struct nfqnl_msg_config_params))];
		struct nlmsghdr nmh;
	} u;
	struct nfqnl_msg_config_params params;

	nfnl_fill_hdr(qh->h->nfnlssh, &u.nmh, 0, AF_UNSPEC, qh->id,
			NFQNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	params.copy_range = htonl(range);
	params.copy_mode = mode;
	nfnl_addattr_l(&u.nmh, sizeof(u), NFQA_CFG_PARAMS, &params,
			sizeof(params));

	return nfnl_talk(qh->h->nfnlh, &u.nmh, 0, 0, NULL, NULL, NULL);
}

/**
 * nfq_set_queue_maxlen - Set kernel queue maximum length parameter
 * @qh: Netfilter queue handle obtained by call to nfq_create_queue().
 * @queuelen: the length of the queue
 *
 * Sets the size of the queue in kernel. This fixes the maximum number
 * of packets the kernel will store before internally before dropping
 * upcoming packets.
 */
int nfq_set_queue_maxlen(struct nfq_q_handle *qh,
				u_int32_t queuelen)
{
	union {
		char buf[NFNL_HEADER_LEN
			+NFA_LENGTH(sizeof(struct nfqnl_msg_config_params))];
		struct nlmsghdr nmh;
	} u;
	u_int32_t queue_maxlen = htonl(queuelen);

	nfnl_fill_hdr(qh->h->nfnlssh, &u.nmh, 0, AF_UNSPEC, qh->id,
			NFQNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	nfnl_addattr_l(&u.nmh, sizeof(u), NFQA_CFG_QUEUE_MAXLEN, &queue_maxlen,
			sizeof(queue_maxlen));

	return nfnl_talk(qh->h->nfnlh, &u.nmh, 0, 0, NULL, NULL, NULL);
}

static int __set_verdict(struct nfq_q_handle *qh, u_int32_t id,
		u_int32_t verdict, u_int32_t mark, int set_mark,
		u_int32_t data_len, unsigned char *data)
{
	struct nfqnl_msg_verdict_hdr vh;
	union {
		char buf[NFNL_HEADER_LEN
			+NFA_LENGTH(sizeof(mark))
			+NFA_LENGTH(sizeof(vh))];
		struct nlmsghdr nmh;
	} u;

	struct iovec iov[3];
	int nvecs;

	/* This must be declared here (and not inside the data
	 * handling block) because the iovec points to this. */
	struct nfattr data_attr;

	memset(iov, 0, sizeof(iov));

	vh.verdict = htonl(verdict);
	vh.id = htonl(id);

	nfnl_fill_hdr(qh->h->nfnlssh, &u.nmh, 0, AF_UNSPEC, qh->id,
			NFQNL_MSG_VERDICT, NLM_F_REQUEST);

	/* add verdict header */
	nfnl_addattr_l(&u.nmh, sizeof(u), NFQA_VERDICT_HDR, &vh, sizeof(vh));

	if (set_mark)
		nfnl_addattr32(&u.nmh, sizeof(u), NFQA_MARK, mark);

	iov[0].iov_base = &u.nmh;
	iov[0].iov_len = NLMSG_TAIL(&u.nmh) - (void *)&u.nmh;
	nvecs = 1;

	if (data_len) {
		nfnl_build_nfa_iovec(&iov[1], &data_attr, NFQA_PAYLOAD,
				data_len, data);
		nvecs += 2;
		/* Add the length of the appended data to the message
		 * header.  The size of the attribute is given in the
		 * nfa_len field and is set in the nfnl_build_nfa_iovec()
		 * function. */
		u.nmh.nlmsg_len += data_attr.nfa_len;
	}

	return nfnl_sendiov(qh->h->nfnlh, iov, nvecs, 0);
}

/**
 * nfq_set_verdict - issue a verdict on a packet 
 * @qh: Netfilter queue handle obtained by call to nfq_create_queue().
 * @id:	ID assigned to packet by netfilter.
 * @verdict: verdict to return to netfilter (NF_ACCEPT, NF_DROP)
 * @data_len: number of bytes of data pointed to by <buf>
 * @buf: the buffer that contains the packet data
 *
 * Can be obtained by: 
 * 
 * int id;
 * struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
 *
 * if (ph)
 * 	id = ntohl(ph->packet_id);
 *
 * Notifies netfilter of the userspace verdict for the given packet.  Every
 * queued packet _must_ have a verdict specified by userspace, either by
 * calling this function, or by calling the nfq_set_verdict_mark() function.
 */
int nfq_set_verdict(struct nfq_q_handle *qh, u_int32_t id,
		u_int32_t verdict, u_int32_t data_len, 
		unsigned char *buf)
{
	return __set_verdict(qh, id, verdict, 0, 0, data_len, buf);
}	

/**
 * nfq_set_verdict_mark - like nfq_set_verdict, but you can set the mark.
 * @qh: Netfilter queue handle obtained by call to nfq_create_queue().
 * @id:	ID assigned to packet by netfilter.
 * @verdict: verdict to return to netfilter (NF_ACCEPT, NF_DROP)
 * @mark: mark to put on packet
 * @data_len: number of bytes of data pointed to by <buf>
 * @buf: the buffer that contains the packet data
 
 */
int nfq_set_verdict_mark(struct nfq_q_handle *qh, u_int32_t id,
		u_int32_t verdict, u_int32_t mark,
		u_int32_t data_len, unsigned char *buf)
{
	return __set_verdict(qh, id, verdict, mark, 1, data_len, buf);
}

/*************************************************************
 * Message parsing functions 
 *************************************************************/

/**
 * nfqnl_msg_packet_hdr - return the metaheader that wraps the packet
 * @nfad: Netlink packet data handle passed to callback function
 *
 * Returns the netfilter queue netlink packet header for the given
 * nfq_data argument.  Typically, the nfq_data value is passed as the 3rd
 * parameter to the callback function set by a call to nfq_create_queue().
 *
 * The nfqnl_msg_packet_hdr structure is defined in libnetfilter_queue.h as:
 *
 * struct nfqnl_msg_packet_hdr {
 * 	u_int32_t	packet_id;	// unique ID of packet in queue
 * 	u_int16_t	hw_protocol;	// hw protocol (network order)
 * 	u_int8_t	hook;		// netfilter hook
 * } __attribute__ ((packed));
 */
struct nfqnl_msg_packet_hdr *nfq_get_msg_packet_hdr(struct nfq_data *nfad)
{
	return nfnl_get_pointer_to_data(nfad->data, NFQA_PACKET_HDR,
					struct nfqnl_msg_packet_hdr);
}

/**
 * nfq_get_nfmark - get the packet mark
 * @nfad: Netlink packet data handle passed to callback function
 *
 * Returns the netfilter mark currently assigned to the given queued packet.
 */
uint32_t nfq_get_nfmark(struct nfq_data *nfad)
{
	return ntohl(nfnl_get_data(nfad->data, NFQA_MARK, u_int32_t));
}

/**
 * nfq_get_timestamp - get the packet timestamp
 * @nfad: Netlink packet data handle passed to callback function
 * @tv: structure to fill with timestamp info
 *
 * Retrieves the received timestamp when the given queued packet.
 *
 * Returns 0 on success, non-zero on failure.
 */
int nfq_get_timestamp(struct nfq_data *nfad, struct timeval *tv)
{
	struct nfqnl_msg_packet_timestamp *qpt;
	qpt = nfnl_get_pointer_to_data(nfad->data, NFQA_TIMESTAMP,
					struct nfqnl_msg_packet_timestamp);
	if (!qpt)
		return -1;

	tv->tv_sec = __be64_to_cpu(qpt->sec);
	tv->tv_usec = __be64_to_cpu(qpt->usec);

	return 0;
}

/**
 * nfq_get_indev - get the interface that the packet was received through
 * @nfad: Netlink packet data handle passed to callback function
 *
 * The index of the device the queued packet was received via.  If the
 * returned index is 0, the packet was locally generated or the input
 * interface is not known (ie. POSTROUTING?).
 *
 * WARNING: all nfq_get_dev() functions return 0 if not set, since linux
 * only allows ifindex >= 1, see net/core/dev.c:2600  (in 2.6.13.1)
 */
u_int32_t nfq_get_indev(struct nfq_data *nfad)
{
	return ntohl(nfnl_get_data(nfad->data, NFQA_IFINDEX_INDEV, u_int32_t));
}

/**
 * nfq_get_physindev - get the physical interface that the packet was received
 * @nfad: Netlink packet data handle passed to callback function
 *
 * The index of the physical device the queued packet was received via.
 * If the returned index is 0, the packet was locally generated or the
 * physical input interface is no longer known (ie. POSTROUTING?).
 */
u_int32_t nfq_get_physindev(struct nfq_data *nfad)
{
	return ntohl(nfnl_get_data(nfad->data, NFQA_IFINDEX_PHYSINDEV, u_int32_t));
}

/**
 * nfq_get_outdev - gets the interface that the packet will be routed out
 * @nfad: Netlink packet data handle passed to callback function
 *
 * The index of the device the queued packet will be sent out.  If the
 * returned index is 0, the packet is destined for localhost or the output
 * interface is not yet known (ie. PREROUTING?).
 */
u_int32_t nfq_get_outdev(struct nfq_data *nfad)
{
	return ntohl(nfnl_get_data(nfad->data, NFQA_IFINDEX_OUTDEV, u_int32_t));
}

/**
 * nfq_get_physoutdev - get the physical interface that the packet output
 * @nfad: Netlink packet data handle passed to callback function
 *
 * The index of the physical device the queued packet will be sent out.
 * If the returned index is 0, the packet is destined for localhost or the
 * physical output interface is not yet known (ie. PREROUTING?).
 * 
 * Retrieves the physical interface that the packet output will be routed out.
 */
u_int32_t nfq_get_physoutdev(struct nfq_data *nfad)
{
	return ntohl(nfnl_get_data(nfad->data, NFQA_IFINDEX_PHYSOUTDEV, u_int32_t));
}

/**
 * nfq_get_indev_name - get the name of the interface the packet
 * was received through
 * @nlif_handle: pointer to a nlif interface resolving handle
 * @nfad: Netlink packet data handle passed to callback function
 * @name: pointer that will be set to the interface name string 
 *
 * The <name> variable will point to the name of the input interface.
 *
 * To use a nlif_handle, You need first to call nlif_open() and to open
 * an handler. Don't forget to store the result as it will be used 
 * during all your program life:
 * 	h = nlif_open();
 * 	if (h == NULL) {
 * 		perror("nlif_open");
 * 		exit(EXIT_FAILURE);
 * 	}
 * Once the handler is open, you need to fetch the interface table at a
 * whole via a call to nlif_query.
 * 	nlif_query(h);
 * libnfnetlink is able to update the interface mapping when a new interface
 * appears. To do so, you need to call nlif_catch() on the handler after each
 * interface related event. The simplest way to get and treat event is to run
 * a select() or poll() against the nlif file descriptor. To get this file 
 * descriptor, you need to use nlif_fd:
 * 	if_fd = nlif_fd(h);
 * Don't forget to close the handler when you don't need the feature anymore:
 * 	nlif_close(h);
 *
 * Return -1 in case of error, >0 if it succeed. 
 */
int nfq_get_indev_name(struct nlif_handle *nlif_handle,
			struct nfq_data *nfad, char *name)
{
	u_int32_t ifindex = nfq_get_indev(nfad);
	return nlif_index2name(nlif_handle, ifindex, name);
}

/**
 * nfq_get_physindev_name - get the name of the physical interface the
 * packet was received through
 * @nlif_handle: pointer to a nlif interface resolving handle
 * @nfad: Netlink packet data handle passed to callback function
 * @name: pointer that will be set to the interface name string 
 *
 * The <name> variable will point to the name of the input physical
 * interface.
 *
 * See nfq_get_indev_name() documentation for nlif_handle usage.
 *
 * Return -1 in case of error, >0 if it succeed. 
 */
int nfq_get_physindev_name(struct nlif_handle *nlif_handle,
			   struct nfq_data *nfad, char *name)
{
	u_int32_t ifindex = nfq_get_physindev(nfad);
	return nlif_index2name(nlif_handle, ifindex, name);
}

/**
 * nfq_get_outdev_name - get the name of the physical interface the
 * packet will be sent to
 * @nlif_handle: pointer to a nlif interface resolving handle
 * @nfad: Netlink packet data handle passed to callback function
 * @name: pointer that will be set to the interface name string 
 *
 * The <name> variable will point to the name of the output interface.
 *
 * See nfq_get_indev_name() documentation for nlif_handle usage.
 *
 * Return -1 in case of error, >0 if it succeed. 
 */
int nfq_get_outdev_name(struct nlif_handle *nlif_handle,
			struct nfq_data *nfad, char *name)
{
	u_int32_t ifindex = nfq_get_outdev(nfad);
	return nlif_index2name(nlif_handle, ifindex, name);
}

/**
 * nfq_get_physoutdev_name - get the name of the interface the
 * packet will be sent to
 * @nlif_handle: pointer to a nlif interface resolving handle
 * @nfad: Netlink packet data handle passed to callback function
 * @name: pointer that will be set to the interface name string 
 *
 * The <name> variable will point to the name of the physical
 * output interface.
 *
 * See nfq_get_indev_name() documentation for nlif_handle usage.
 *
 * Return -1 in case of error, >0 if it succeed. 
 */

int nfq_get_physoutdev_name(struct nlif_handle *nlif_handle,
			    struct nfq_data *nfad, char *name)
{
	u_int32_t ifindex = nfq_get_physoutdev(nfad);
	return nlif_index2name(nlif_handle, ifindex, name);
}

/**
 * nfq_get_packet_hw - get hardware address 
 * @nfad: Netlink packet data handle passed to callback function
 *
 * Retrieves the hardware address associated with the given queued packet.
 * For ethernet packets, the hardware address returned (if any) will be the
 * MAC address of the packet source host.  The destination MAC address is not
 * known until after POSTROUTING and a successful ARP request, so cannot
 * currently be retrieved.
 *
 * The nfqnl_msg_packet_hw structure is defined in libnetfilter_queue.h as:
 *
 * struct nfqnl_msg_packet_hw {
 * 	u_int16_t	hw_addrlen;
 * 	u_int16_t	_pad;
 * 	u_int8_t	hw_addr[8];
 * } __attribute__ ((packed));
 */
struct nfqnl_msg_packet_hw *nfq_get_packet_hw(struct nfq_data *nfad)
{
	return nfnl_get_pointer_to_data(nfad->data, NFQA_HWADDR,
					struct nfqnl_msg_packet_hw);
}

/**
 * nfq_get_payload - get payload 
 * @nfad: Netlink packet data handle passed to callback function
 * @data: Pointer of pointer that will be pointed to the payload
 *
 * Retrieve the payload for a queued packet. The actual amount and type of
 * data retrieved by this function will depend on the mode set with the
 * nfq_set_mode() function.
 *
 * Returns -1 on error, otherwise > 0.
 */
int nfq_get_payload(struct nfq_data *nfad, char **data)
{
	*data = nfnl_get_pointer_to_data(nfad->data, NFQA_PAYLOAD, char);
	if (*data)
		return NFA_PAYLOAD(nfad->data[NFQA_PAYLOAD-1]);

	return -1;
}
