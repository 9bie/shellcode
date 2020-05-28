#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<WinSock2.h>
#include <Ws2tcpip.h>
#define bzero(a, b)             memset(a, 0, b);
#define DNS_A  0x01
#define DNS_CNAME 0x05
//#define DNS_AAAA 0x28

/* DNS header */
typedef struct {
	u_short id;
	u_short tag;
	u_short num_question;
	u_short num_answer;
	u_short num_authority;
	u_short num_appendix;
} dns_header;



/* main function */
BOOL parse_domain(const char* domain, _Out_ char* ip);

/* build DNS requset and send */
void send_dns_request(const char *dns_name);

/* receive and parse DNS response */
BOOL parse_dns_response(char* ip);

/* get the domain name from DNS request */
void parse_dns_name(char *buf, char *p, char *name, int *len);

