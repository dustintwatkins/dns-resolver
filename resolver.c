#include<arpa/inet.h>
#include<netinet/in.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<time.h>
#include<unistd.h>
#include<netdb.h>

#define BUF_SIZE 500

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;

typedef struct {
	char *name;
	dns_rr_type type;
	dns_rr_class class;
	dns_rr_ttl ttl;
	dns_rdata_len rdata_len;
	unsigned char *rdata;
} dns_rr;

//able to RR values after building them
void printRR(dns_rr rr){
	printf("Name: %s\n", rr.name);
	printf("type: %04x\n", rr.type);
	printf("class: %04x\n", rr.class);
	printf("ttl: %08x\n", rr.ttl);
	printf("rdatlen: %04x\n", rr.rdata_len);

	int i =0;
	for(; i < rr.rdata_len; i++){
		if((i+1) % 4 == 0){
			printf("\n");
		}
		printf("%02x ", rr.rdata[i]);
	}
	printf("\n");
}

//Finds rdata using rdata_len
unsigned char* get_rdata(dns_rdata_len rdata_len, int* temp, char* response){
	unsigned char* rdata = (unsigned char*)malloc(rdata_len + sizeof(char));

	int count;
	for(count = 0; count < rdata_len; count++){
		rdata[count] = response[(*temp)++];
	}

	return rdata;
}

//checks to see if the char is a dot
int is_dot(char c){
	if(c >= 0x30 && c <= 0x39)
		return 0;
	if(c >= 0x61 && c <= 0x7A)
		return 0;

	return 1;
}

struct dns_answer_entry;
struct dns_answer_entry {
	char *value;
	struct dns_answer_entry *next;
};

typedef struct dns_answer_entry dns_answer_entry;

//Given function that prints the bytes
void print_bytes(unsigned char *bytes, int byteslen) {
	int i, j, byteslen_adjusted;
	unsigned char c;

	if (byteslen % 8) {
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	} else {
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++) {
		if (!(i % 8)) {
			if (i > 0) {
				for (j = i - 8; j < i; j++) {
					if (j >= byteslen_adjusted) {
						printf("  ");
					} else if (j >= byteslen) {
						printf("  ");
					} else if (bytes[j] >= '!' && bytes[j] <= '~') {
						printf(" %c", bytes[j]);
					} else {
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted) {
				printf("\n%02X: ", i);
			}
		} else if (!(i % 4)) {
			printf(" ");
		}
		if (i >= byteslen_adjusted) {
			continue;
		} else if (i >= byteslen) {
			printf("   ");
		} else {
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

//Given function that makes the string all lowercase
void canonicalize_name(char *name) {
	/*
	 * Canonicalize name in place.  Change all upper-case characters to
	 * lower case and remove the trailing dot if there is any.  If the name
	 * passed is a single dot, "." (representing the root zone), then it
	 * should stay the same.
	 *
	 * INPUT:  name: the domain name that should be canonicalized in place
	 */

	int namelen, i;

	// leave the root zone alone
	if (strcmp(name, ".") == 0) {
		return;
	}

	namelen = strlen(name);
	// remove the trailing dot, if any
	if (name[namelen - 1] == '.') {
		name[namelen - 1] = '\0';
	}

	// make all upper-case letters lower case
	for (i = 0; i < namelen; i++) {
		if (name[i] >= 'A' && name[i] <= 'Z') {
			name[i] += 32;
		}
	}
}

char *name_ascii_from_wire(unsigned char *wire, int *indexp) {

		char name[BUF_SIZE];
		int i = 0;

		//advance index to 0x00
		while(wire[*indexp] != 0x00){
			if(wire[*indexp] >= 192){									//if >= 192 it means its a pointer
				*indexp = wire[*indexp + 1];
			}
			else{
				if(is_dot(wire[*indexp]) && i > 0)
					name[i] = '.';
				else
					name[i] = wire[*indexp];
				i++;
				(*indexp)++;
			}
		}

		char* val = (char*)malloc(i);
		int j;
		for(j = 0; j < i; j++)
			val[j] = name[j+1];

		val[j] = '\0';
		canonicalize_name(val);
		return val;
}

dns_rr_type get_RR_type(int* temp, char* response){
	while(response[*temp] != 0x00){							//advance to 0x00, usually just once
		(*temp)++;
	}
	if(response[*temp + 1] == 0x00){
		(*temp)++;
	}
	dns_rr_type rr_type = ((response[*temp] | 0x0000) << 2);
	(*temp)++;
	rr_type = rr_type | response[*temp];

	return rr_type;
}

//creates a random query id
unsigned char get_random_id(){
	return (char)(rand() % 256);
}

//build a dns query
unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire) {

	 int i;
	 //Setting the Identification query_id
	 for(i = 0; i < 2; i++){
		 wire[i] = get_random_id();
	 }

	 wire[i++] = 0x01;													//Flag QR -> RD = 1
	 wire[i++] = 0x00;													//All flags and RCODE are 0
	 wire[i++] = 0x00;
	 wire[i++] = 0x01;													//Total questions (1)
	 wire[i++] = 0x00;
	 wire[i++] = 0x00;													//Answer RR's
	 wire[i++] = 0x00;
	 wire[i++] = 0x00;
	 wire[i++] = 0x00;
	 wire[i++] = 0x00;													//authority and additional RR's

	 canonicalize_name(qname);									//Set to all lowercase
	 int true_size;
	 for(true_size = 0; 1; true_size++){					//find truesize of qname
		 if(qname[true_size] == '\0')
		 	break;
	 }

	 int dot_location = i;
	 int num_letters = 0;
	 int q = 0;
	 i++;
	 int start_qname = i;
	 for(; i < (start_qname + true_size); i++){
		 if(qname[q] == '.'){
			 wire[dot_location] = (char)num_letters;
			 num_letters = 0;
			 dot_location = i;
		 }
		 else{
			 wire[i] = qname[q];
			 num_letters++;
		 }
		 q++;
	 }

	 wire[dot_location] = (char)num_letters;
	 wire[i++] = 0x00;														//Indicates end of qname
	 wire[i++] = 0x00;
	 wire[i++] = 0x01;														//q_type
	 wire[i++] = 0x00;
	 wire[i++] = 0x01;														//q_class
	 return i;
}


int get_answer_RR(unsigned char *response){
	return(((response[6] | 0x0000) << 8) | response[7]);
}

int get_index_first_rr(unsigned char *response, int length){

	int idx = 12;
	for(; 1; idx++){
		if(response[idx] == 0x00)
			break;
	}

	idx++;
	int qtype = (((response[idx++] >> 7) | 0x0000) | response[idx++]);
	//printf("qtype: 0x%04x\n", qtype);
	int qclass = (((response[idx++] >> 7) | 0x000) | response[idx++]);
	//printf("qclass: 0x%04x\n", qclass);

	//Response section begins here
	return idx;
}

//checks to see if name from response and original qname are the same
int matching_name(char* name, char* qname){
	int i = 0;
	while(name[i] != '\0'){
		if(name[i] != qname[i])
			return 0;
		i++;
	}
	return 1;
}

//gets the rr_class
dns_rr_class get_RR_class_type(int* temp, char* response){
	(*temp)++;
	dns_rr_class class = ((response[*temp] | 0x0000) << 2);
	(*temp)++;
	return class | response[*temp];
	//printf("class = %04x\n", response[*temp]);
	//printf("idx into class = %02x\n", response[*temp]);
	//(*temp)++;
	//printf("idx into class = %02x\n", response[*temp]);
	//printf("class = %04x\n", response[*temp]);
	//return class;
}

//return the rr_ttl
dns_rr_ttl get_rr_ttl(int* temp, char* response){
	//printf("idx ttl = %02x\n", response[*temp]);
	//(*temp)++;
	(*temp)++;
	// printf("idx ttl = %08x\n", (response[(*temp)++] | 0x00000000) << 24);
	// printf("idx ttl = %08x\n", (response[(*temp)++] | 0x00000000) << 16);
	// printf("idx ttl = %08x\n", (response[(*temp)++] | 0x00000000) << 8);
	// printf("after = %08x\n", response[*temp]);
	// printf("idx ttl = %08x\n", (response[(*temp)++] | 0x00000000));
	dns_rr_ttl ttl = (((response[(*temp)++] | 0x00000000) << 24) |
							((response[(*temp)++] | 0x00000000) << 16) |
							((response[(*temp)++] | 0x00000000) << 8)  |
							 (response[(*temp)++] | 0x00000000) );
	//printf("ttl = %08x\n", ttl);
	return ttl;
}

//get rr_len so we can get rdata
dns_rdata_len get_rr_data_len(int* temp, char* response){
	dns_rdata_len r_data_len = ( ((response[(*temp)++] | 0x0000) << 8) | response[(*temp)++]);
	return r_data_len;
}

//create the dns_rr struct
dns_rr* dns_rr_builder(int* index_RR_p, char* response){
	int start_idx = *index_RR_p;
	dns_rr* rr = (dns_rr*)malloc(sizeof(dns_rr));
	rr->name = name_ascii_from_wire(response, index_RR_p);
	*index_RR_p = start_idx;
	rr->type = get_RR_type(index_RR_p, response);
	rr->class = get_RR_class_type(index_RR_p, response);
	rr->ttl = get_rr_ttl(index_RR_p, response);
	rr->rdata_len = get_rr_data_len(index_RR_p, response);
	rr->rdata = get_rdata(rr->rdata_len, index_RR_p, response);
	return rr;
}

int get_index_r_data(char* response, unsigned char* rdata, dns_rdata_len rdata_len){
	int i;
	int j = 0;
	int start = 0;
	for(i = 0; 1; i++){
		start = i;
			if(response[i] == rdata[j]){
				if(response[i + 1] == rdata[j + 1])
					return start;
			}
	}
}

dns_answer_entry *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *response, int length) {

	int index_RR_p = get_index_first_rr(response, length);
	int idx = index_RR_p;

	//check to see how many answer rr's we have
	int answer_rr = get_answer_RR(response);

	dns_rr** RRs = (dns_rr**)malloc(sizeof(dns_rr*) * answer_rr);
	//dns_rr* rr = get_RR_type(&index_RR_p, response);
	index_RR_p = idx;

	dns_answer_entry* dae_entry = (dns_answer_entry*)malloc(sizeof(dns_answer_entry));
	dns_answer_entry* first = dae_entry;

	dae_entry = dae_entry->next;

	char owner_rr[BUF_SIZE];

	//if we have 0 answer_rr, it means it was invalid... end here
	if(answer_rr == 0){
		free(dae_entry);
		return NULL;
	}

	int i;
	for(i = 0; i < answer_rr; i++){
		RRs[i] = dns_rr_builder(&index_RR_p, response);				//create the dns_rr for each answer_rr
		//printRR(*RRs[i]);
	}
	int passes = 1;
	dns_answer_entry* next = (dns_answer_entry*)malloc(sizeof(dns_answer_entry));

	for(i = 0; i < answer_rr; i++){
		//check if names
		int match = matching_name(RRs[i]->name, qname);
		if(RRs[i]->type == qtype && match){
			int count = 0;
			struct in_addr addr;
			addr.s_addr = htonl( ((RRs[i]->rdata[count++] | 0x00000000) << 24) |
									((RRs[i]->rdata[count++] | 0x00000000) << 16) |
									((RRs[i]->rdata[count++] | 0x00000000) << 8)  |
									 (RRs[i]->rdata[count++] | 0x00000000) );
			char* s = inet_ntoa(addr);
			if(passes){
				first->value = (char*)malloc(*s);
				strcpy(first->value,s);
				first->next = next;
				next->next = NULL;
				passes = 0;
			}
			else{
				next->value = (char*) malloc(*s);
				strcpy(next->value,s);
				next->next = (dns_answer_entry*)malloc(sizeof(dns_answer_entry));
				next = next->next;
				next->next = NULL;
			}
			next->next = NULL;
		}
		else if(match && RRs[i]->type == 5){
			int start = get_index_r_data(response, RRs[i]->rdata, RRs[i]->rdata_len);
			qname = name_ascii_from_wire(response, &start);

			//printf("%s\n", qname);
			if(passes){
				first->value = (char*)malloc(*qname);
				strcpy(first->value, qname);
				first->next = next;
				passes = 0;
			}
			else{
				next->value = (char*) malloc(*qname);
				strcpy(next->value,qname);
				next->next = (dns_answer_entry*)malloc(sizeof(dns_answer_entry));
				next = next->next;
			}
			next->next = NULL;
			passes = 0;
		}
	}

	return first;
}

int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, unsigned short port) {

	 struct addrinfo hints;
	 struct addrinfo *result, *rp;
	 int sfd, s, j;
	 size_t len;
	 ssize_t nread;
	 char buf[BUF_SIZE];

	 struct sockaddr_in ip4addr;

	 ip4addr.sin_family = AF_INET;
	 ip4addr.sin_port = htons(port);

	 inet_pton(AF_INET, server, &ip4addr.sin_addr);
	 sfd = socket(AF_INET, SOCK_DGRAM, 0);

	 if (connect(sfd, (struct sockaddr *)&ip4addr, sizeof(struct sockaddr_in)) < 0) {
 		fprintf(stderr, "Could not connect\n");
 		exit(EXIT_FAILURE);
 	}

	len = requestlen + 1;

	if (write(sfd, request, len) != len) {
			fprintf(stderr, "partial/failed write\n");
			exit(EXIT_FAILURE);
	}

		nread = read(sfd, response, BUF_SIZE);
		if (nread == -1) {
			perror("read");
			exit(EXIT_FAILURE);
		}
		//print_bytes(response, nread);
		return nread;
}

dns_answer_entry *resolve(char *qname, char *server) {

	unsigned char wire[BUF_SIZE];
	unsigned char response[BUF_SIZE];
	unsigned short query_length;
	dns_rr_type qtype = 1;

	query_length = create_dns_query(qname, qtype, wire);

	int sizeOf_response = send_recv_message(wire, query_length, response, server, 53);
	if(sizeOf_response == 0){
		printf("No response returned\n");
		exit(1);
	}
	return get_answer_address(qname, qtype, response, sizeOf_response);
}

int main(int argc, char *argv[]) {
	dns_answer_entry *ans;
	srand(time(NULL));
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <domain name> <server>\n", argv[0]);
		exit(1);
	}
	ans = resolve(argv[1], argv[2]);

	//If no answer records... Names don't resolve
		while (ans != NULL) {
			if(ans->value != NULL){
				printf("%s\n", ans->value);
			}
			ans = ans->next;
		}
}
