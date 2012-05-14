/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Vyatta Inc. <http://www.vyatta.com>
 */

#include <stdlib.h>
#include <string.h> /* for memcpy */

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "internal.h"

/**
 * \defgroup pktbuff User-space network packet buffer
 *
 * This library provides the user-space network packet buffer. This abstraction
 * is strongly inspired by Linux kernel network buffer, the so-called sk_buff.
 */

/**
 * pktb_alloc - allocate a new packet buffer
 * \param family Indicate what family, eg. AF_BRIDGE, AF_INET, AF_INET6, ...
 * \param data Pointer to packet data
 * \param len Packet length
 * \param extra Extra memory in the tail to be allocated (for mangling)
 *
 * This function returns a packet buffer that contains the packet data and
 * some extra memory room in the tail (in case of requested).
 *
 * \return a pointer to a new queue handle or NULL on failure.
 */
struct pkt_buff *
pktb_alloc(int family, void *data, size_t len, size_t extra)
{
	struct pkt_buff *pktb;
	void *pkt_data;

	pktb = calloc(1, sizeof(struct pkt_buff) + len + extra);
	if (pktb == NULL)
		return NULL;

	/* Better make sure alignment is correct. */
	pkt_data = (uint8_t *)pktb + sizeof(struct pkt_buff);
	memcpy(pkt_data, data, len);

	pktb->len = len;
	pktb->data_len = len + extra;

	pktb->head = pkt_data;
	pktb->data = pkt_data;
	pktb->tail = pktb->head + len;

	switch(family) {
	case AF_INET:
		pktb->network_header = pktb->data;
		break;
	case AF_BRIDGE: {
		struct ethhdr *ethhdr = (struct ethhdr *)pktb->data;

		pktb->mac_header = pktb->data;

		switch(ethhdr->h_proto) {
		case ETH_P_IP:
			pktb->network_header = pktb->data + ETH_HLEN;
			break;
		default:
			/* This protocol is unsupported. */
			free(pktb);
			return NULL;
		}
		break;
	}
	}
	return pktb;
}

uint8_t *pktb_data(struct pkt_buff *pktb)
{
	return pktb->data;
}

uint32_t pktb_len(struct pkt_buff *pktb)
{
	return pktb->len;
}

void pktb_free(struct pkt_buff *pktb)
{
	free(pktb);
}

void pktb_push(struct pkt_buff *pktb, unsigned int len)
{
	pktb->data += len;
}

void pktb_pull(struct pkt_buff *pktb, unsigned int len)
{
	pktb->data -= len;
}

void pktb_put(struct pkt_buff *pktb, unsigned int len)
{
	pktb->tail += len;
}

void pktb_trim(struct pkt_buff *pktb, unsigned int len)
{
	pktb->len = len;
}

unsigned int pktb_tailroom(struct pkt_buff *pktb)
{
	return pktb->data_len - pktb->len;
}

uint8_t *pktb_mac_header(struct pkt_buff *pktb)
{
	return pktb->mac_header;
}

uint8_t *pktb_network_header(struct pkt_buff *pktb)
{
	return pktb->network_header;
}

uint8_t *pktb_transport_header(struct pkt_buff *pktb)
{
	return pktb->transport_header;
}

/**
 * @}
 */
