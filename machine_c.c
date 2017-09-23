#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h> 

#define MAC_ARRAY_LEN 18

char pc_mac[MAC_ARRAY_LEN];
char IPS[10000][30];
int frequency[10000], ip_num = 0;

pcap_t *handle; //Handle of the device that shall be sniffed

// function to get this device interface's MAC address
void get_MAC(char *devname)
{
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	char mac[MAC_ARRAY_LEN];
	char *MAC = mac;

	strcpy(s.ifr_name, devname);
	if (0 == ioctl(fd, SIOCGIFHWADDR, &s))
	{
		int i;
		for ( i = 0; i < 6; ++i)
		  MAC += sprintf(MAC, "%02X:", (unsigned char) s.ifr_addr.sa_data[i]);
		mac[MAC_ARRAY_LEN - 1] = '\0';

		strcpy(pc_mac, mac);
		printf("This device's MAC: %s\n", mac);
	}
}

// processes the ICMP packet
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int i, size = header->len; // the size of the packet (essentially, the size of buffer)
	 
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

	if(iph->protocol != 1) // ICMP Protocol for ping - Only for ICMP requests.
		return;

	// source and destination MAC
	char source_mac[MAC_ARRAY_LEN], dest_mac[MAC_ARRAY_LEN];
	char *s = source_mac, *d = dest_mac;

	// extracts the souce and destination mac from the packet. First 6 bytes - destination, next 6 are source
	for ( i = 0; i < 6; ++i)
	{
		d += sprintf(d, "%.2X:", (unsigned char) buffer[i]);
		s += sprintf(s, "%.2X:", (unsigned char) buffer[6 + i]);
	}

	source_mac[MAC_ARRAY_LEN - 1] = '\0';
	dest_mac[MAC_ARRAY_LEN - 1] = '\0';

	// printf("Source: %s\n", source_mac);
	// printf("Destin: %s\n", dest_mac);

	// If the source of this ICMP packet doesn't match this interface's MAC, ignore this packet
	if(strcmp(dest_mac, pc_mac) != 0)
		return;

	unsigned short iphdrlen;
    iphdrlen = iph->ihl * 4;
	struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen  + sizeof(struct ethhdr));

	// check for incoming request and expired TTL
	if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
		return;

	// printf("-------------------\n");
	// printf("Ping Packet Received\n");

	struct sockaddr_in source;
	source.sin_addr.s_addr = iph->saddr;

	for(i = 0; i < ip_num; i++)
	{
		if(!strcmp(inet_ntoa(source.sin_addr), IPS[i]))
		{
			frequency[i]++;
			break;
		}
	}

	if(i == ip_num)
	{
		strcpy(IPS[i], inet_ntoa(source.sin_addr));
		frequency[i] = 1;
		ip_num++;
	}

	for(i = 0; i < ip_num; i++)
		printf("%s: %d ", IPS[i], frequency[i]);

	printf("\n");
}

int main(int argc, char *argv[])
{

	char *dev, errbuf[PCAP_ERRBUF_SIZE];

	// specifies which interface to use
	// dev = pcap_lookupdev(errbuf);
	dev = "eth1\0";
	if (dev == NULL) 
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	//Open the device for sniffing
	printf("Opening device %s for sniffing...\n" , dev);
	handle = pcap_open_live(dev, 65536, 1, 0, errbuf);
	 
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , dev , errbuf);
		exit(1);
	}
	printf("Sniffer set up\n");

	// Get this interface's mac
	get_MAC(dev);

	// Loop and invoke callback for each captured packet
	pcap_loop(handle, -1, process_packet, NULL);

	return 0;
}