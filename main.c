#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h> // 상수 IPPROTO_TCP, IPPROTO_UDP 등을 사용하기 위해 선언한 헤더
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h> // 자료형 intN_t, uintN_t를 사용하기 위해 선언한 헤더
#include <arpa/inet.h> // inet.ntoa() 함수를 사용하기 위해 선언한 헤더
#include <string.h>

#define PORT_FROM_HTTP 80


struct DOMAIN 
{
	struct DOMAIN* next;
	char dName[256]; // Domain name
};
struct DOMAIN domainArray[999983] = {0, }; // Hash map에 사용할 구조체 배열


static int is_block(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	int drop = 0; // 패킷을 DROP할지 결정할 변수
	int size = sizeof(domainArray) / sizeof(struct DOMAIN); // domainArray의 구조체 배열 크기

	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);
	int id = 0;
	if (ph) id = ntohl(ph->packet_id);

	struct nfqnl_msg_packet_hw *hwph;
	hwph = nfq_get_packet_hw(nfa);

	u_int32_t mark = nfq_get_nfmark(nfa);
	u_int32_t ifi = nfq_get_indev(nfa);
	ifi = nfq_get_outdev(nfa);
	ifi = nfq_get_physindev(nfa);
	ifi = nfq_get_physoutdev(nfa);

	unsigned char *ipData;
	int ret = nfq_get_payload(nfa, &ipData);

	unsigned char* packet = ipData;
	struct ip *ipHeader;
	ipHeader = (struct ip *)packet;
	uint8_t ipProtocol = ipHeader->ip_p; // Transport layer 프로토콜

	if(ipProtocol == IPPROTO_TCP) // TCP 프로토콜이면
	{
		uint8_t ipHeaderLength = (ipHeader->ip_hl) * 4; // IP 헤더 길이
		packet += ipHeaderLength;
		struct tcphdr *tcpHeader;
		tcpHeader = (struct tcphdr *)packet;

		uint16_t ipTotalLength = ntohs(ipHeader->ip_len); // Ethernet 헤더를 제외한 패킷의 전체 길이
		uint16_t dstPort = ntohs(tcpHeader->th_dport); // 패킷의 목적지 포트

		if(dstPort == PORT_FROM_HTTP) // 패킷의 목적지 포트가 80(HTTP)이면
		{
			uint8_t tcpHeaderLength = (tcpHeader->th_off) * 4; // TCP 헤더 길이
			int dataLength = ipTotalLength - ipHeaderLength - tcpHeaderLength; // Data 길이
			packet += tcpHeaderLength; // Data 부분
			
			if(dataLength == 0) drop = 0;
			else if(dataLength > 0) // Data가 0보다 크면
			{

				int i = 0;
				while(packet[i] != 0x0d && packet[i+1] != 0x0a) i = i + 1; // Data 부분에서 첫 번째 \r\n이 나올 때까지
				i = i + 8; // "Host: "의 뒷 부분으로 이동

				int j = i;
				while(packet[j] != 0x0d && packet[j] != 0x0a) j = j + 1; // Data 부분에서 두 번째 \r\n이 나올 때까지

				int hashFunc = 0;  // hash functions 결과값을 저장할 변수
				int y = 0; // hash functions에 사용할 변수

				/* 입력한 domain에 대한 hash function */
				for(int x = i; x < j; x++) 
				{
					hashFunc = hashFunc + (packet[x] * packet[x]) * y; // hash function
					y = y + 1;
				}

				/* 입력한 domain과 domain 차단 목록을 비교하여 일치하면 차단 */
				if(domainArray[hashFunc % size].dName != NULL)
				{
					if(!strncmp(domainArray[hashFunc % size].dName, packet + i, j - i))
					{
						printf("DROP %s\n", domainArray[hashFunc % size].dName);
						drop = 1;
					}
					else if(domainArray[hashFunc % size].next != NULL)
					{
						struct DOMAIN* node = domainArray[hashFunc % size].next;
						do
						{
							if(strncpy(node->dName, packet + i, j - i))
							{
								printf("DROP %s\n", node->dName);
								drop = 1;
								break;
							}
							node = node->next;
						} while(node != NULL);
					}
					else drop = 0;
				}
				else drop = 0;
			}
		}
		else drop = 0;
	}
	else drop = 0;

	if(drop == 1) return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	else if(drop == 0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char **argv)
{
	int size = sizeof(domainArray) / sizeof(struct DOMAIN); // domainArray의 구조체 배열 크기
	char domainName[256]; // Domain name을 저장할 변수
	int len = 0; // Domain name 길이를 저장할 변수
	int hashFunc = 0; // hash functions 결과값을 저장할 변수

	FILE *pFile = NULL;
	pFile = fopen( "./top-1m.csv", "r");

	/* Using hash collision ratio and count print */ 
	// int count = 0;
	// int x = 0;

	while(fgets(domainName, sizeof(domainName), pFile) != NULL)
	{
		len = strlen(domainName);
		char* strTemp = (char*)malloc(sizeof(char) * len);
		strncpy(strTemp, domainName, (len - 2));
		strTemp[len - 2] = '\0';
		for(int i = 0; i < len - 2; i++) hashFunc = hashFunc + (strTemp[i] * strTemp[i]) * i; // hash function

		if(domainArray[hashFunc % size].dName[0] == '\0') strncpy(domainArray[hashFunc % size].dName, strTemp, len);
		else if(domainArray[hashFunc % size].dName[0] != '\0')
		{
			struct DOMAIN* node = (struct DOMAIN*)malloc(sizeof(struct DOMAIN)); // Node 생성
			memset(node, 0, sizeof(node)); // Node 초기화
			node->next = domainArray[hashFunc % size].next;
			domainArray[hashFunc % size].next = node;
			strncpy(node->dName, strTemp, len - 2);

			/* Hash collision count print */
			// count = count + 1;
			// printf("Count : %d, Hash Collision : %s\n", count, node->dName);
		}

		/* Hash collision domain print */
		// printf("[%d] domainArray[%d] : %s\n", x, hashFunc % size, domainArray[hashFunc % size].dName);
		// x = x + 1;

		hashFunc = 0;
	}
	fclose(pFile);

	/* Hash collision ratio print */
	// printf("Hash Collision Ratio : %f%\n", (double)count / (double)size);

	/*Example code part start*/
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	h = nfq_open();
	if (!h)
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}
	qh = nfq_create_queue(h,  0, &is_block, NULL);
	if (!qh)
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}
	fd = nfq_fd(h);

	printf("Now start.....\n");

	for (;;)
	{
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
		{
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS)
		{
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	nfq_unbind_pf(h, AF_INET);
#endif
	nfq_close(h);

	printf("End\n");

	exit(0);
	/*Example code part end*/
}
