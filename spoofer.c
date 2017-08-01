#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include "infofetcher.h"
#include <arpa/inet.h>

#define CMD_BUF_SIZE 256
#define IP_ADDR_BUF_SIZE 20
#define MAC_ADDR_BUF_SIZE 25
#define GATE_ADDR_BUF_SIZE 20
#define PACK_BUF_SIZE 1024 * 64
#define PCAP_ERR_BUF_SIZE 1024
#define SEND_BUF_SIZE 512

int main(int argc, char* argv[]) {
	pcap_t *handle;
	char opt_verbose = 0;
	struct pcap_pkthdr* header_ptr;
	const u_char *pkt_data;
	struct ether_header* eth_hdr;
	struct ether_arp* arp_hdr;
	// u_char send_buf[SEND_BUF_SIZE];
	char errbuf[PCAP_ERR_BUF_SIZE];
	char my_ip_addr_str[IP_ADDR_BUF_SIZE];
	char my_mac_addr_str[MAC_ADDR_BUF_SIZE];
	char *ifname = NULL; //interface name
	char *sender_ip_addr_str = NULL; //sender ip address string
	char *target_ip_addr_str = NULL;
	u_char sender_mac_addr[6];
	char sender_mac_addr_str[MAC_ADDR_BUF_SIZE];
	if (argc < 4) {
		fprintf(stderr, "Usage: %s [-options] [Interface name] [sender IP] [target IP]\n", argv[0]);
		fprintf(stderr, "\t[options]\n\t\t-v : verbose mode\n");
		return EXIT_FAILURE;
	}
	for(int cnt = 1; cnt < argc; cnt++) {
		if (argv[cnt][0] == '-') {
			switch(argv[cnt][1]) {
				case 'v':
				opt_verbose = 1;
				break;
			}
		} else {
			if (ifname == NULL) {
				ifname = argv[cnt];
			} else if (sender_ip_addr_str == NULL) {
				sender_ip_addr_str = argv[cnt];
			} else {
				target_ip_addr_str = argv[cnt];
			}
		}
	}

	if (opt_verbose) {
		printf("ifname: %s\n", ifname);
		printf("sender_ip_addr_str: %s\n", sender_ip_addr_str);
		printf("target_ip_addr_str: %s\n", target_ip_addr_str);
	}

	// if (get_my_mac_str(ifname, my_ip_addr_str, sizeof(my_ip_addr_str) - 1) == EXIT_FAILURE) {
	if (get_my_ip_str(ifname, my_ip_addr_str, sizeof(my_ip_addr_str) - 1) == EXIT_FAILURE) {
		perror("Fail to fetch IPv4 address\n");
	 	exit(EXIT_FAILURE);
	}
	if (opt_verbose) {
		printf("My IPv4 addr: %s\n", my_ip_addr_str);
	}

	// if (get_my_ip_str(ifname, my_mac_addr_str, sizeof(my_mac_addr_str) - 1) == EXIT_FAILURE) {
	if (get_my_mac_str(ifname, my_mac_addr_str, sizeof(my_mac_addr_str) - 1) == EXIT_FAILURE) {
		perror("Fail to fetch Mac address\n");
		exit(EXIT_FAILURE);
	}
	if (opt_verbose) {
		printf("My Mac addr: %s\n", my_mac_addr_str);
	}

	//open network interface
	handle = pcap_open_live(ifname, PACK_BUF_SIZE, 0, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Cannot open device %s: %s\n", ifname, errbuf);
		exit(EXIT_FAILURE);
	}	
	if (opt_verbose) {
		printf("Open device [%s]\n", ifname);
	}

	//send ARP Request
	send_arp_packet(handle, my_mac_addr_str, NULL, my_ip_addr_str, sender_ip_addr_str, ARPOP_REQUEST);
	//recv ARP reply
	while(1) {
		int status = pcap_next_ex(handle, &header_ptr, &pkt_data);
		if (status == 0) {
			printf("no packet\n");
			continue;
		} else if (status == -1) {
			 fprintf(stderr, "Failed to set buffer size on capture handle : %s\n",
                        pcap_geterr(handle));
			break;
		} else if (status == -2) {
			fprintf(stderr, "Finished reading packet data from packet files\n");
			break;
		}
		eth_hdr = (struct ether_header*)pkt_data;
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			arp_hdr = (struct ether_arp*)(pkt_data + sizeof(struct ether_header));
		} else {
			//not arp proto
			continue;
		}
		if (ntohs(arp_hdr->ea_hdr.ar_pro) != ETHERTYPE_IP) {
			//not IPv4 ARP
			continue;
		}
		if (ntohs(arp_hdr->ea_hdr.ar_op) != ARPOP_REPLY) {
			//not ARP reply
			continue;
		}
		for (int i=0; i < 6; i++) {
			sender_mac_addr[i] = arp_hdr->arp_sha[i];
		}
		sprintf(sender_mac_addr_str, "%02X:%02X:%02X:%02X:%02X:%02X", sender_mac_addr[0], sender_mac_addr[1],
		 sender_mac_addr[2],sender_mac_addr[3],sender_mac_addr[4],sender_mac_addr[5]);
		break;
	}
	//recv ARP reply

	if (opt_verbose) {
		printf("sender Mac addr - ");
		for (int i=0; i < 6; i++) {
			printf("%02X", sender_mac_addr[i]);
			if (i < 5) putchar(':');
		}
		putchar('\n');
	}

	send_arp_packet(handle, my_mac_addr_str, sender_mac_addr_str, target_ip_addr_str, sender_ip_addr_str, ARPOP_REPLY);


	pcap_close(handle);
	return EXIT_SUCCESS;

}