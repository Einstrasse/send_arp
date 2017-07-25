#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define CMD_BUF_SIZE 256
#define IP_ADDR_BUF_SIZE 20
int main(int argc, char* argv[]) {
	FILE* fp;
	char cmdbuf[CMD_BUF_SIZE];
	char my_ip_addr_str[IP_ADDR_BUF_SIZE];
	char *ifname;
	if (argc < 2) {
		fprintf(stderr, "Usage: %s [Interface name] [Victim IPv4 addr]\n", argv[0]);
		return EXIT_FAILURE;
	}

	ifname = argv[1];
	printf("ifname: %s\n", ifname);
	sprintf(cmdbuf, "/bin/bash -c \"ifconfig %s\" | grep \"inet \" | awk '{print $2}'\n", ifname);
	printf("cmdbuf: %s\n", cmdbuf);
	fp = popen(cmdbuf, "r");
	if (fp == NULL) {
		perror("Fail to fetch IPv4 address\n");
		exit(EXIT_FAILURE);
	}
	fgets(my_ip_addr_str, sizeof(my_ip_addr_str) - 1, fp);
	printf("My IPv4 addr: %s\n", my_ip_addr_str);

}