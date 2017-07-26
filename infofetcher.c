#ifndef __INFOFETCHER_C__
#define __INFOFETCHER_C__

#include "infofetcher.h"
#include <stdlib.h>
#include <stdio.h>

#define CMD_BUF_SIZE 256
int get_my_mac_str(char *ifname, char *str, int len) {
	FILE* fp;
	char cmdbuf[CMD_BUF_SIZE];
	sprintf(cmdbuf, "/bin/bash -c \"ifconfig %s\" | grep \"inet \" | awk '{print $2}'\n", ifname);
	fp = popen(cmdbuf, "r");
	if (fp == NULL) {
		perror("Fail to fetch mac address\n");
		return EXIT_FAILURE;
	}
	fgets(str, len, fp);
	pclose(fp);
	return EXIT_SUCCESS;
}
int get_my_ip_str(char *ifname, char *str, int len) {
	FILE* fp;
	char cmdbuf[CMD_BUF_SIZE];
	sprintf(cmdbuf, "/bin/bash -c \"ifconfig %s\" | grep '[ ][0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]' | awk '{print $2}'", ifname);
	fp = popen(cmdbuf, "r");
	if (fp == NULL) {
		perror("Fail to fetch IPv4 address\n");
		return EXIT_FAILURE;
	}
	fgets(str, len, fp);
	pclose(fp);
	return EXIT_SUCCESS;
}
int get_my_gateway_str(char *ifname, char *str, int len) {
	FILE* fp;
	char cmdbuf[CMD_BUF_SIZE];
	sprintf(cmdbuf, "/bin/bash -c 'route -n' | grep G | grep %s | awk '{print $2}'", ifname);
	fp = popen(cmdbuf, "r");
	if (fp == NULL) {
		perror("Fail to fetch gateway address\n");
		return EXIT_FAILURE;
	}
	fgets(str, len, fp);
	pclose(fp);
	return EXIT_SUCCESS;
}

#endif