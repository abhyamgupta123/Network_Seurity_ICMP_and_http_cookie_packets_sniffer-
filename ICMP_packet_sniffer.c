#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
#include <unistd.h>
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include <sys/time.h>

typedef struct Node {
    int size;
    u_char *buffer;
    struct timeval  t;
    struct Node* next;
} Node;


// List to maintain ICMP bradcast packets within a minute
Node* head=NULL;
Node* tail=NULL;

int timeval_subtract (struct timeval *x, struct timeval *y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }
  return x->tv_sec - y->tv_sec;
}

// Function to format Ethernet header
void print_ether(u_char *buffer) {
    struct ethhdr *eth = (struct ethhdr *) (buffer);
    printf("Ethernet Header\n");
    printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf("   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

// Function to format IP header
void print_ip(u_char *buffer) {
    struct sockaddr_in source,dest;
    unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	printf("\n");
	printf("IP Header\n");
	printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
	printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	printf("   |-Identification    : %d\n",ntohs(iph->id));
	printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
	printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
	printf("   |-Checksum : %d\n",ntohs(iph->check));
	printf("   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	printf("   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}

// Function to format ICMP header
void print_icmp(u_char *buffer) {
    unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen  + sizeof(struct ethhdr));

    printf("\n");
	printf("ICMP Header\n");
    printf("   |-Code : %d\n",(unsigned int)(icmph->code));
	printf("   |-Checksum : %d\n",ntohs(icmph->checksum));
	printf("\n");
}

void print_packets() {
    Node* temp=head;
    int cnt=1;
    while(temp) {
        printf("%d. \n",cnt);
        print_ether(temp->buffer);
        print_ip(temp->buffer);
        print_icmp(temp->buffer);
        temp=temp->next;
        ++cnt;
    }

}

int p=0;
int threshold=50;  // Threshold
char* d_addr="255.255.255.255";  // Broadcast address

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    if(iph->protocol==1) {  // ICMP packet
        unsigned short iphdrlen;
        iphdrlen = iph->ihl * 4;
        struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen  + sizeof(struct ethhdr));
        if(icmph->type==8 && icmph->code==0) {  // Echo request packet
            struct in_addr ip_addr;
            ip_addr.s_addr = iph->daddr;
            struct timeval x;
            char ip[100];
            if(strcmp(inet_ntoa(ip_addr),d_addr)==0) {  // Broadcast packet
                //printf("Detected\n");
                gettimeofday(&x,NULL);
                Node* temp;
                while(head && timeval_subtract(&x,&head->t)>=60) {
                    temp=head;
                    head=head->next;
                    free(temp);
                    --p;
                }
                temp=(Node*) malloc(sizeof(Node)); // Add packet to list
                temp->t=x;
                temp->next=NULL;
                temp->size=size;
                temp->buffer=(u_char *) malloc(sizeof(u_char) * size);
                strcpy(temp->buffer,buffer);
                if(head==NULL) {
                    head=tail=temp;
                }
                else {
                    tail->next=temp;
                    tail=temp;
                }
                ++p;
                if(p>=threshold) {
                    printf("\n\n********************\nAttack detected\n********************\n\n");
                    sleep(2);
                    print_packets();
                    exit(0);
                }
            }
        }
    }
}

int main()
{
	pcap_if_t *alldevsp , *device;
	pcap_t *handle; //Handle of the device that shall be sniffed

	char errbuf[100] , *devname , devs[100][100];
	int count = 1 , n;
	
	//First get the list of available devices
	printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");
	
	//Print the available devices
	printf("\n\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s\n" , count , device->name);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}
	
	//Ask user which device to sniff
	printf("\nEnter the number of the device ID you want to sniff : ");
	scanf("%d" , &n);
	devname = devs[n];

    printf("Opening device %s for sniffing ... \n" , devname);
	handle = pcap_open_live(devname , 65536 , 1 , 1000 , errbuf);
	
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}

    pcap_loop(handle , -1 , process_packet , NULL);

    return 0;
}