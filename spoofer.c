#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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
	if (argc < 3) {
		fprintf(stderr, "Usage: %s [-options] [Interface name] [Victim IPv4 addr]\n", argv[0]);
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
			} else {
				victim_ip_addr_str = argv[cnt];
			}
		}
	}

	ifname = argv[1];
	if (opt_verbose) {
		printf("ifname: %s\n", ifname);
		printf("victim ip addr: %s\n", victim_ip_addr_str);
	}
	sprintf(cmdbuf, "/bin/bash -c \"ifconfig %s\" | grep \"inet \" | awk '{print $2}'\n", ifname);
	if (opt_verbose) 
	printf("cmdbuf: %s\n", cmdbuf);
	fp = popen(cmdbuf, "r");
	if (fp == NULL) {
		perror("Fail to fetch IPv4 address\n");
		exit(EXIT_FAILURE);
	}
	fgets(my_ip_addr_str, sizeof(my_ip_addr_str) - 1, fp);
	pclose(fp);
	printf("My IPv4 addr: %s\n", my_ip_addr_str);

	sprintf(cmdbuf, "/bin/bash -c \"ifconfig %s\" | grep '[ ][0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]' | awk '{print $2}'", ifname);
	if (opt_verbose) 
	printf("cmdbuf: %s\n", cmdbuf);
	fp = popen(cmdbuf, "r");
	if (fp == NULL) {
		perror("Fail to fetch Mac address\n");
		exit(EXIT_FAILURE);
	}
	fgets(my_mac_addr_str, sizeof(my_mac_addr_str) - 1, fp);
	pclose(fp);
	printf("My Mac addr: %s\n", my_mac_addr_str);

	sprintf(cmdbuf, "/bin/bash -c 'route -n' | grep G | grep %s | awk '{print $2}'", ifname);
	if (opt_verbose) 
	printf("cmdbuf: %s\n", cmdbuf);
	fp = popen(cmdbuf, "r");
	if (fp == NULL) {
		perror("Fail to fetch default gateway\n");
		exit(EXIT_FAILURE);
	}
	fgets(my_defgw_addr_str, sizeof(my_defgw_addr_str) - 1, fp);
	pclose(fp);
	printf("My default Gateway addr: %s\n", my_defgw_addr_str);

}