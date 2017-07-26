#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "infofetcher.h"

#define CMD_BUF_SIZE 256
#define IP_ADDR_BUF_SIZE 20
#define MAC_ADDR_BUF_SIZE 25
#define GATE_ADDR_BUF_SIZE 20

int main(int argc, char* argv[]) {
	FILE* fp;
	char opt_verbose = 0;
	char cmdbuf[CMD_BUF_SIZE];
	char my_ip_addr_str[IP_ADDR_BUF_SIZE];
	char my_mac_addr_str[MAC_ADDR_BUF_SIZE];
	char my_defgw_addr_str[GATE_ADDR_BUF_SIZE]; //default gateway str
	char *ifname = NULL; //interface name
	char *victim_ip_addr_str = NULL; //victim ip address string
	char *target_ip_addr_str = NULL;
	if (argc < 4) {
		fprintf(stderr, "Usage: %s [-options] [Interface name] [victim IP] [target IP]\n", argv[0]);
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
			} else if (victim_ip_addr_str == NULL) {
				victim_ip_addr_str = argv[cnt];
			} else {
				target_ip_addr_str = argv[cnt];
			}
		}
	}

	if (opt_verbose) {
		printf("ifname: %s\n", ifname);
		printf("victim_ip_addr_str: %s\n", victim_ip_addr_str);
		printf("target_ip_addr_str: %s\n", target_ip_addr_str);
	}

	if (get_my_mac_str(ifname, my_ip_addr_str, sizeof(my_ip_addr_str) - 1) == EXIT_FAILURE) {
		perror("Fail to fetch IPv4 address\n");
	 	exit(EXIT_FAILURE);
	}
	printf("My IPv4 addr: %s\n", my_ip_addr_str);

	if (get_my_ip_str(ifname, my_mac_addr_str, sizeof(my_mac_addr_str) - 1) == EXIT_FAILURE) {
		perror("Fail to fetch Mac address\n");
		exit(EXIT_FAILURE);
	}
	printf("My Mac addr: %s\n", my_mac_addr_str);

	if (get_my_gateway_str(ifname, my_defgw_addr_str, sizeof(my_defgw_addr_str) - 1) == EXIT_FAILURE) {
		perror("Fail to fetch default gateway\n");
		exit(EXIT_FAILURE);
	}
	printf("My default Gateway addr: %s\n", my_defgw_addr_str);

}