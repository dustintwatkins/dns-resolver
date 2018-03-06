#include<stdio.h>

int main() {
	char bytes[] = { 'f', 'o', 'o', 'd', '\0' };
	printf("%s\n", bytes);
	printf("%c%c\n", bytes[0], bytes[1]);
	printf("%i.%i.%i.%i\n", bytes[0], bytes[1], bytes[2], bytes[3]);
	printf("%x.%x.%x.%x\n", bytes[0], bytes[1], bytes[2], bytes[3]);
	printf("%x\n", (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | (bytes[3]));
	printf("%x\n", bytes);
	printf("%x\n", bytes+1);
	printf("%x\n", *bytes);
	printf("%x\n", *(bytes+1));
}
