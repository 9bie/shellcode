#include "dns.h"
const char *DNS_LOOKUP_SERVER = "114.114.114.114";
struct sockaddr_in dest;
/* about socket */
int socketfd;
WSADATA data;
BOOL parse_domain(const char* domain,_Out_ char* ip) {
	WSAStartup(MAKEWORD(2, 2), &data);
	/* create socket */
	socketfd = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	//dest.sin_addr.s_addr = inet_addr(DNS_LOOKUP_SERVER);
	InetPton(AF_INET, DNS_LOOKUP_SERVER, &dest.sin_addr.s_addr);
	if (socketfd < 0) {
		
		return false;
	}
	send_dns_request(domain);
	return parse_dns_response(ip);

}

void send_dns_request(const char *dns_name) {

	/* definations */
	char buf[512];
	u_char question[128];
	int Q_len = 0;

	/* settle question */
	char *pos;
	u_char *p = question;
	int n;
	pos = (char*)dns_name;

	while (1) {

		/* get len */
		if (strstr(pos, ".") != NULL)
			n = strlen(pos) - strlen(strstr(pos, "."));
		else
			n = strlen(pos);

		/* copy */
		*p = (u_char)n;
		p += 1;
		memcpy(p, pos, n);
		p += n;
		Q_len += (n + 1);

		/* end */
		if (strstr(pos, ".") == NULL) {
			*p = (u_char)0;
			p += 1;
			Q_len += 1;
			break;
		}
		pos += n + 1;
	}

	*((u_short *)p) = htons(1);
	p += 2;
	Q_len += 2;
	*((u_short *)p) = htons(1);
	Q_len += 2;

	/* memcpy */
	dns_header DNS;
	DNS.id = htons(0xff00);
	DNS.tag = htons(0x0100);
	DNS.num_question = htons(1);
	DNS.num_answer = 0;
	DNS.num_authority = 0;
	DNS.num_appendix = 0;
	memcpy(buf, &DNS, 12);
	memcpy(buf + 12, &question, Q_len);
	sendto(socketfd, buf, Q_len + 12, 0, (struct sockaddr*)&dest, sizeof(struct sockaddr));
}

BOOL parse_dns_response(char*ip) {

	/* definations */
	char buf[65536];
	dns_header DNS;
	char cname[128], aname[128];
	char netip[4];
	struct sockaddr_in addr;
	int addr_len = sizeof(struct sockaddr_in);
	int count, len, type, ttl, data_len;

	/* receive DNS response */
	recvfrom(socketfd, buf, sizeof(buf), 0, (struct sockaddr*)&addr, &addr_len);

	/* parse head */
	memcpy(&DNS, buf, 12);
	char *p = buf + 12;

	/* move over questions */
	int flag;
	for (count = 0; count < ntohs(DNS.num_question); count++) {
		while (1) {
			flag = (int)p[0];
			p += (flag + 1);
			if (flag == 0)
				break;
		}
		p += 4;
	}

	/* parse answers */
	
	if (ntohs(DNS.num_answer) == 0) {
		
		return false;
	}
	for (count = 0; count < ntohs(DNS.num_answer); count++) {
		memset(aname, 0, sizeof(aname));
		//bzero(aname, sizeof(aname));
		len = 0;
		parse_dns_name(buf, p, aname, &len);
		p += 2;
		type = htons(*((u_short*)p));
		p += 4;
		ttl = htonl(*((u_int*)p));
		p += 4;
		data_len = ntohs(*((u_short*)p));
		p += 2;

		if (type == DNS_A) {
			memset(ip, 0, sizeof(ip));
			//bzero(ip, sizeof(ip));
			if (data_len == 4) {
				memcpy(netip, p, data_len);
				inet_ntop(AF_INET, netip, ip, sizeof(struct sockaddr));

				//printf("Domain name: %s\n", aname);
				//printf("IP address: %s\n", ip);
				//printf("Time to alive: %d\n\n", ttl);
			}
		}
		else if (type == DNS_CNAME) {
			memset(cname, 0, sizeof(cname));
			//bzero(cname, sizeof(cname));
			len = 0;
			parse_dns_name(buf, p, cname, &len);
			//printf("Domain name: %s\n", aname);
			//printf("Alias name: %s\n\n", cname);
		}
		p += data_len;
	}
	return true;
}

void parse_dns_name(char *buf, char *p, char *name, int *len) {

	int flag;
	char *pos = name + *len;

	while (1) {

		/* end */
		flag = (int)p[0];
		if (flag == 0)
			break;

		/* judge pointers */
		if ((flag & 0xc0) == 0xc0) {
			p = buf + (int)p[1];
			parse_dns_name(buf, p, name, len);
			break;
		}
		/* copy */
		else {
			p += 1;
			memcpy(pos, p, flag);
			pos += flag;
			p += flag;
			*len += flag;
			if ((int)p[0] != 0) {
				memcpy(pos, ".", 1);
				pos += 1;
				*len += 1;
			}
		}
	}
}
