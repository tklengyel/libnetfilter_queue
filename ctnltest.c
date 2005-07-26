#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>

       #include <sys/socket.h>
       #include <netinet/in.h>
       #include <arpa/inet.h>


#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>

#include "libctnetlink.h"

static struct ctnl_handle *cth;

char *display_tuple_flat(struct ip_conntrack_tuple *tuple)
{
        static char buff[250];
        char psb[20];
        int len = 0;

        memset(buff, '\0', sizeof(buff));
	len += sprintf(buff + len, "%s:", inet_ntoa((struct in_addr){tuple->src.ip}));
        switch(tuple->dst.protonum) {
                case (IPPROTO_ICMP):
                        len += sprintf(buff + len, "Icmp (id %d)",
                                ntohs(tuple->src.u.icmp.id));
                        break;
                case (IPPROTO_TCP):
                        sprintf(psb, "%d", ntohs(tuple->src.u.tcp.port));
                        len += sprintf(buff + len, "%s", psb);
                        break;
                case (IPPROTO_UDP):
                        sprintf(psb, "%d", ntohs(tuple->src.u.udp.port));
                        len += sprintf(buff + len, "%s", psb);
                        break;
                default:
                        len += sprintf(buff + len, "Unknown");
                        break;
        }

	len += sprintf(buff + len, "->");
        len += sprintf(buff + len, "%s:", inet_ntoa((struct in_addr){tuple->dst.ip}));
        switch(tuple->dst.protonum) {
                case (IPPROTO_ICMP):
                        len += sprintf(buff + len, "Icmp (%d, code %d)",
                                tuple->dst.u.icmp.type,
                                tuple->dst.u.icmp.code);
                        break;
                case (IPPROTO_TCP):
                        sprintf(psb, "%d", ntohs(tuple->dst.u.tcp.port));
                        len += sprintf(buff + len, "%s", psb);
                        break;
                case (IPPROTO_UDP):
                        sprintf(psb, "%d", ntohs(tuple->dst.u.udp.port));
                        len += sprintf(buff + len, "%s", psb);
                        break;
                default:
                        len += sprintf(buff + len, "Unknown");
                        break;
        }

        return (buff);
}

int ctnl_parse_attr(struct nfattr *tb[], int max, struct nfattr *cta, int len)
{
        while(NFA_OK(cta, len)) {
                if(cta->nfa_type <= max)
                        tb[cta->nfa_type] = cta;
                cta = NFA_NEXT(cta,len);
        }
        if (len)
		printf("ctnl_parse_attr: deficit (%d) len (%d).\n",
			len, cta->nfa_len);
        return 0;
}

#if 0
int dump()
{
	struct {
		struct nlmsghdr nlh;
		struct nfgenmsg nfmsg;
	} req;
	struct sockaddr_nl nladdr;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8)|CTNL_MSG_CT_GET;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_DUMP|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = 1;
	req.nfmsg.nfgen_family = AF_INET;

	return (sendto(ctnlfd, &req, sizeof(req), 0,
			(struct sockaddr *) &nladdr, sizeof(nladdr)));

}
#endif

int print_msg(struct nfgenmsg *cm, size_t len)
{
	struct nfattr *cb[CTA_MAX + 1];

	printf("ctm_family=0x%x\n", cm->nfgen_family);

	ctnl_parse_attr(cb, CTA_MAX, NFM_NFA(cm), len);

	if (cb[CTA_ORIG]) {
		printf("orig: %s\n", 
				display_tuple_flat(NFA_DATA(cb[CTA_ORIG])));
		ctnl_del_conntrack(cth, NFA_DATA(cb[CTA_ORIG]), CTA_ORIG);
	}
	if (cb[CTA_RPLY])
		printf("rply: %s\n", 
				display_tuple_flat(NFA_DATA(cb[CTA_RPLY])));


	return 0;
}

struct nlmsghdr *ctnl_get_packet(struct nlmsghdr **last_nlhdr, 
			      char *buf, size_t len)
{
	struct nlmsghdr *nlh;
	size_t remain_len;

	if ((char *)(*last_nlhdr) > (buf + len) ||
	    (char *)(*last_nlhdr) < buf)
		*last_nlhdr = NULL;

	if (!*last_nlhdr) {
		nlh = (struct nlmsghdr *) buf;
		if (!NLMSG_OK(nlh, len)) {
			printf("error parsing nlmsg\n");
			return NULL;
		}
	} else {
		/* we are n-th part of multipart mesasge */
		if ((*last_nlhdr)->nlmsg_type == NLMSG_DONE ||
		    !((*last_nlhdr)->nlmsg_flags & NLM_F_MULTI)) {
			*last_nlhdr = NULL;
			return NULL;
		}

		remain_len = (len - ((char *)(*last_nlhdr) - buf));
		nlh = NLMSG_NEXT(*last_nlhdr, remain_len);
	}

	*last_nlhdr = nlh;
	return nlh;
}

int main(int argc, char **argv)
{
	char buf[20480];
	struct nfgenmsg *last_cm = NULL, *cm;
	struct nlmsghdr *nlh;
	int len;

	cth = malloc(sizeof(*cth));
	if (ctnl_open(cth, 0) < 0) {
		exit(2);
	}

	ctnl_wilddump_request(cth, AF_INET, IPCTNL_MSG_CT_GET);

	while (len = recv(cth->nfnlh.fd, &buf, sizeof(buf), 0)) {
		printf("pkt received\n");
		while (nlh = ctnl_get_packet(&last_cm, (char *)&buf, len)) {
			printf("  decoding msg type 0x%04x\n", nlh->nlmsg_type);
			if (NFNL_SUBSYS_ID(nlh->nlmsg_type) == 
					NFNL_SUBSYS_CTNETLINK) {
				cm = NLMSG_DATA(nlh);
				print_msg(cm, nlh->nlmsg_len);
			}
		}
	}

	return 0;
}

