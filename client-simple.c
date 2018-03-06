#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define BUF_SIZE 500

int main(int argc, char *argv[]) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s, j;
	size_t len;
	ssize_t nread;
	char buf[BUF_SIZE];

	struct sockaddr_in ip4addr;

	ip4addr.sin_family = AF_INET;
	ip4addr.sin_port = htons(atoi(argv[2]));
	inet_pton(AF_INET, argv[1], &ip4addr.sin_addr);

	sfd = socket(AF_INET, SOCK_STREAM, 0);
	//sfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (connect(sfd, (struct sockaddr *)&ip4addr, sizeof(struct sockaddr_in)) < 0) {
		fprintf(stderr, "Could not connect\n");
		exit(EXIT_FAILURE);
	}

	/* Send remaining command-line arguments as separate
	   datagrams, and read responses from server */

	for (j = 3; j < argc; j++) {
		len = strlen(argv[j]) + 1;
		/* +1 for terminating null byte */

		if (len + 1 > BUF_SIZE) {
			fprintf(stderr,
					"Ignoring long message in argument %d\n", j);
			continue;
		}

		if (write(sfd, argv[j], len) != len) {
			fprintf(stderr, "partial/failed write\n");
			exit(EXIT_FAILURE);
		}

		/*
		nread = read(sfd, buf, BUF_SIZE);
		if (nread == -1) {
			perror("read");
			exit(EXIT_FAILURE);
		}

		printf("Received %zd bytes: %s\n", nread, buf);
		*/
	}

	exit(EXIT_SUCCESS);
}

