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

unsigned char* get_rdata(dns_rdata_len rdata_len, int* temp, char* response){
	unsigned char* rdata = (unsigned char*)malloc(rdata_len + sizeof(char));

	int count;
	for(count = 0; count < rdata_len; count++){
		rdata[count] = response[(*temp)++];
	}

	return rdata;
}

int is_dot(char c){
	if(c >= 0x30 && c <= 0x39)
		return 0;
	if(c >= 0x61 && c <= 0x7A)
		return 0;

	return 1;
}

dns_rr_class get_RR_class_type(int* temp, char* response){
	(*temp)--;
	dns_rr_class class = ((response[*temp] | 0x0000) << 2);
	(*temp)++;
	class = class | response[*temp];
	(*temp)++;
	return class;
}

struct dns_answer_entry;
struct dns_answer_entry {
	char *value;
	struct dns_answer_entry *next;
};

typedef struct dns_answer_entry dns_answer_entry;

void get_response_values(unsigned char *wire, int length){

	//Used to match request/reply packets.
	/*printf("Identification (query_id): 0x%2x%2x\n", wire[0], wire[1]);

	printf("QR Flag: %x\n", ((wire[2] & 0x80) >> 7));

	//4 bits
	printf("Opcode: %x\n",((wire[2] & 01111000) >> 3));

	//AA: Specifies that the responding name server is an authority for the domain name in question section
	//RD: May be set in a query and is copied into the response. If set, the name server is directed to pursue the query recursively
	printf("Flags: AA: %x TC: %x RD: %x\n",((wire[2] & 00000100) >> 2), ((wire[2] & 00000010) >> 1), (wire[2] & 00000001));
	printf("Flags: RA: %x Z: %x AD: %x CD: %x\n",((wire[3] & 0x80) >> 7),
																							 ((wire[3] & 0x04) >> 6),
																							 ((wire[3] & 0x20) >> 5),
																							 ((wire[3] & 0x10) >> 4));
	printf("RCODE: %x\n", (wire[3] & 0x0A));
	int questions = (((wire[4] | 0x0000) << 8) | wire[5]);
	printf("Total questions: 0x%04x\n", questions);
	int answers = (((wire[6] | 0x0000) << 8) | wire[7]);
	printf("Total answerRRs: 0x%04x\n", answers);
	int auth = (((wire[8] | 0x0000) << 8) | wire[9]);
	printf("Total authorityRRs: 0x%04x\n", auth);
	int additional =(((wire[10] | 0x0000) << 8) | wire[11]);
	printf("Total additionalRRs: 0x%04x\n", additional);

	int idx = 12;
	int end_com = 0;
	for(; 1; idx++){
		if(wire[idx] == 0x6d &&
			 wire[idx - 1] == 0x6f &&
		 	 wire[idx - 2] == 0x63 &&
		 	 wire[idx - 3] == 0x03){
				 end_com = 1;
			 }
		if(wire[idx] == 0x00 && end_com){
			break;
		}
	}

	idx++;

	int qtype = (((wire[idx++] >> 7) | 0x0000) | wire[idx++]);
	printf("qtype: 0x%04x\n", qtype);

	int qclass = (((wire[idx++] >> 7) | 0x000) | wire[idx++]);
	printf("qclass: 0x%04x\n", qclass);

	int comp_owner = (((wire[idx++] | 0x0000) << 8) | wire[idx++]);
	printf("comp_owner: 0x%04x\n", comp_owner);

	int response_type = (((wire[idx++] | 0x0000) << 8) | wire[idx++]);
	printf("response_type: 0x%04x\n", response_type);

	int response_class = (((wire[idx++] | 0x0000) << 8) | wire[idx++]);
	printf("response_class: 0x%04x\n", response_class);

	int TTL = ( ((wire[idx++] | 0x00000000) << 24) |
							((wire[idx++] | 0x00000000) << 16) |
							((wire[idx++] | 0x00000000) << 8)  |
							(wire[idx++] | 0x00000000) );
	printf("TTL: 0x%08x\n", TTL);

	int r_data_len = ( ((wire[idx++] | 0x0000) << 8) | wire[idx++]);
	printf("rdata_len: 0x%04x\n", r_data_len);

	unsigned char r_data[10];
	int count;
	for(count = 0; count < r_data_len; count++){
		r_data[count] = wire[idx++];
	}

	for(int i = 0; i < r_data_len; i++){
		if(i == 0)
			printf("%d\n", r_data[i]);
		else
			printf(".%d\n", r_data[i]);
	}
	printf("\n");*/

}

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

		while(wire[*indexp] != 0x00){
			if(wire[*indexp] >= 192){
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

dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only) {
	/*
	 * Extract the wire-formatted resource record at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return a
	 * dns_rr (struct) populated with its contents. Update the value
	 * pointed to by indexp to the next value beyond the resource record.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp: a pointer to the index in the wire where the
	 *              wire-formatted resource record begins
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are extracting a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the resource record (struct)
	 */

}

int rr_to_wire(dns_rr rr, unsigned char *wire, int query_only) {
	/*
	 * Convert a DNS resource record struct to DNS wire format, using the
	 * provided byte array (wire).  Return the number of bytes used by the
	 * name in wire format.
	 *
	 * INPUT:  rr: the dns_rr struct containing the rr record
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *             wire-formatted resource record should be constructed
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are constructing a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the length of the wire-formatted resource record.
	 *
	 */
}

dns_rr_type* get_RR_type(int* temp, char* response){
	while(response[*temp] != 0x00){
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

unsigned char get_random_id(){
	return (char)(rand() % 256);
}

unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire) {
	/*
	 * Create a wire-formatted DNS (query) message using the provided byte
	 * array (wire).  Create the header and question sections, including
	 * the qname and qtype.
	 *
	 * INPUT:  qname: the string containing the name to be queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes where the DNS wire
	 *               message should be constructed
	 * OUTPUT: the length of the DNS wire message
	 */


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

int get_index_next_rr(int idx, unsigned char *response, int length){/*may not work*/

	int comp_owner = (((response[idx++] | 0x0000) << 8) | response[idx++]);
	//printf("comp_owner: 0x%04x\n", comp_owner);
	int response_type = (((response[idx++] | 0x0000) << 8) | response[idx++]);
	//printf("response_type: 0x%04x\n", response_type);
	int response_class = (((response[idx++] | 0x0000) << 8) | response[idx++]);
	//printf("response_class: 0x%04x\n", response_class);
	int TTL = ( ((response[idx++] | 0x00000000) << 24) |
							((response[idx++] | 0x00000000) << 16) |
							((response[idx++] | 0x00000000) << 8)  |
							(response[idx++] | 0x00000000) );
	//printf("TTL: 0x%08x\n", TTL);
	int r_data_len = ( ((response[idx++] | 0x0000) << 8) | response[idx++]);
	//printf("rdata_len: 0x%04x\n", r_data_len);

	idx += r_data_len;
	idx++;
	return idx;


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

// unsigned short get_owner_rr(unsigned char* owner_rr, int index_curr_rr, unsigned char *response, int length){
// 	//first decompress owner
// 	//then return it in a form that matches the qname
// 	int start_owner_name = 0;
// 	//this is after www, if >= 192 its an alias,
//
// 	if((int)response[index_curr_rr] >= 192){					//Val >= 192 means its a pointer (compressed name)
// 		start_owner_name = (int)response[index_curr_rr + 1];
// 		name_ascii_from_wire(response, &index_curr_rr);
// 	}
// 	else																				//val < 192 means its the real name
// 		start_owner_name = (index_curr_rr + 1);
//
// 	unsigned short i = 0;
// 	start_owner_name++;
// 	while(response[start_owner_name] != 0x00){
// 		if(is_dot(response[start_owner_name]))
// 			owner_rr[i] = '.';
// 		else
// 			owner_rr[i] = response[start_owner_name];
//
// 		start_owner_name++;
// 		i++;
// 	}
//
// 	return i;
// }

int matching_name(char* name, char* qname){
	int i = 0;
	while(name[i] != '\0'){
		if(name[i] != qname[i])
			return 0;
		i++;
	}
	return 1;
}

int get_response_type(int idx, char* response, unsigned short length){
	int comp_owner = (((response[idx++] | 0x0000) << 8) | response[idx++]);
	int response_type = (((response[idx++] | 0x0000) << 8) | response[idx++]);
	return response_type;
}

int get_index_rdata(int index_rr,unsigned char* response, unsigned short length){
	//get location of rdata length
	int comp_owner = (((response[index_rr++] | 0x0000) << 8) | response[index_rr++]);
	int response_type = (((response[index_rr++] | 0x0000) << 8) | response[index_rr++]);
	int TTL = ( ((response[index_rr++] | 0x00000000) << 24) |
							((response[index_rr++] | 0x00000000) << 16) |
							((response[index_rr++] | 0x00000000) << 8)  |
							 (response[index_rr++] | 0x00000000) );

	index_rr += 2;
	return index_rr;
}

dns_rr_ttl get_rr_ttl(int* temp, char* response){
	(*temp)++;
	(*temp)++;
	dns_rr_ttl ttl = ( ((response[(*temp)++] | 0x00000000) << 24) |
							((response[(*temp)++] | 0x00000000) << 16) |
							((response[(*temp)++] | 0x00000000) << 8)  |
							 (response[(*temp)++] | 0x00000000) );
	return ttl;
}

dns_rdata_len get_rr_data_len(int* temp, char* response){
	dns_rdata_len r_data_len = ( ((response[(*temp)++] | 0x0000) << 8) | response[(*temp)++]);

	return r_data_len;
}


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

// unsigned short extract_Rdata(int index_rr, unsigned char* r_data, unsigned char* response, unsigned short length){
// 	//need to know what index r_data begins at
//
// 	int index_length_Rdata = get_index_rdata(index_rr, response, length);
//
// 	int length_Rdata = (((response[index_length_Rdata++] | 0x0000) << 8) | response[index_length_Rdata++]);
//
// 	//prinf("first num of IP addr: %d\n", response[index_length_Rdata++];)
//
// 	unsigned int r_data_bytes[10];
//
// 	int count;
// 	for(count = 0; count < length_Rdata; count++){
// 		r_data_bytes[count] = (unsigned int)response[index_length_Rdata++];
// 		//printf("%d\n", (unsigned int)r_data_bytes[count]);
// 	}
// 	count = 0;
// 	int i;
//
// 	for(i = 0; i < length_Rdata; i++){
// 		if(i == 0){
// 			r_data[count] = (unsigned char)r_data_bytes[i];
// 		}
// 		else{
// 			r_data[count] = '.';
// 			count++;
// 			r_data[count] = (unsigned char)r_data_bytes[i];
// 		}
// 		count++;
// 	}
// 	return count;
// }

int get_index_r_data(char* response, unsigned char* rdata, dns_rdata_len rdata_len){
	int i;
	int j = 0;
	int start = 0;
	for(i = 0; 1; i++){
		start = i;
			if(response[i] == rdata[j]){
				if(response[i] != rdata[j])
					break;
			}
			return start;
	}
}

dns_answer_entry *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *response, int length) {

	int index_RR_p = get_index_first_rr(response, length);
	int idx = index_RR_p;

	int answer_rr = get_answer_RR(response);

	dns_rr** RRs = (dns_rr**)malloc(sizeof(dns_rr*) * answer_rr);
	//dns_rr* rr = get_RR_type(&index_RR_p, response);
	index_RR_p = idx;

	dns_answer_entry* dae_entry = (dns_answer_entry*)malloc(sizeof(dns_answer_entry));
	dns_answer_entry *first = dae_entry;

	dae_entry = dae_entry->next;

	char owner_rr[BUF_SIZE];
	if(answer_rr == 0){
		free(dae_entry);
		return NULL;
	}

	int i;
	for(i = 0; i < answer_rr; i++){
		RRs[i] = dns_rr_builder(&index_RR_p, response);
	}

	int passes = 1;
	dns_answer_entry* next = (dns_answer_entry*)malloc(sizeof(dns_answer_entry));
	for(i = 0; i < answer_rr; i++){
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
				strcpy(first->value,s);
				next->next = (dns_answer_entry*)malloc(sizeof(dns_answer_entry));
				next = next->next;
			}
			next->next = NULL;
		}
		else if(match && RRs[i]->type == 5){
			int start = get_index_r_data(response, RRs[i]->rdata, RRs[i]->rdata_len);
			qname = name_ascii_from_wire(response, &start);
			printf("%s\n", qname);
			if(passes){
				first->value = (char*)malloc(*qname);
				strcpy(first->value, qname);
				first->next = next;
				passes = 0;
			}
			else{
				next->value = (char*) malloc(*qname);
				strcpy(first->value,qname);
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
	/*
	 * Send a message (request) over UDP to a server (server) and port
	 * (port) and wait for a response, which is placed in another byte
	 * array (response).  Create a socket, "connect()" it to the
	 * appropriate destination, and then use send() and recv();
	 *
	 * INPUT:  request: a pointer to an array of bytes that should be sent
	 * INPUT:  requestlen: the length of request, in bytes.
	 * INPUT:  response: a pointer to an array of bytes in which the
	 *             response should be received
	 * OUTPUT: the size (bytes) of the response received
	 */

	 struct addrinfo hints;
	 struct addrinfo *result, *rp;
	 int sfd, s, j;
	 size_t len;
	 ssize_t nread;
	 char buf[BUF_SIZE];

	 struct sockaddr_in ip4addr;

	 ip4addr.sin_family = AF_INET;    /* Allow IPv4 or IPv6 */
	 ip4addr.sin_port = htons(port);

	 inet_pton(AF_INET, server, &ip4addr.sin_addr);
	 sfd = socket(AF_INET, SOCK_DGRAM, 0);

	 if (connect(sfd, (struct sockaddr *)&ip4addr, sizeof(struct sockaddr_in)) < 0) {
 		fprintf(stderr, "Could not connect\n");
 		exit(EXIT_FAILURE);
 	}

	/* Send remaining command-line arguments as separate
	   datagrams, and read responses from server */

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

		return nread;
}

dns_answer_entry *resolve(char *qname, char *server) {
	//Convert all chars to lowercase if necessary
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
			printf("here\n");
			ans = ans->next;
			printf("there\n");

		}
}
