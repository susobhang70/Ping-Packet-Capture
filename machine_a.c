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

#define MAC_ARRAY_LEN 18

char pc_mac[MAC_ARRAY_LEN];

uint8_t target_mac[6];

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

// function to convert the destination MAC (separated by colons) to bytecode
void convert_dest_MAC(char *mac)
{
	int values[6];
	int i;

	if( 6 == sscanf( mac, "%X:%X:%X:%X:%X:%X%c",
		&values[0], &values[1], &values[2],
		&values[3], &values[4], &values[5] ) )
	{
		/* convert to uint8_t */
		for( i = 0; i < 6; ++i )
		{
			target_mac[i] = (uint8_t) values[i];
		}
	}
	else
	{
		printf("Invalid Destination MAC\n");
		exit(1);
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

	printf("Source: %s\n", source_mac);
	printf("Destin: %s\n", dest_mac);

	// If the source of this ICMP packet doesn't match this interface's MAC, ignore this packet
	if(strcmp(source_mac, pc_mac) != 0)
		return;

	// part to resend the packet to new machine

	// copy packet contents into a new buffer
	u_char *newbuffer = (u_char*)malloc(size * sizeof(u_char));

	for( i = 0; i < size; i++)
		newbuffer[i] = buffer[i];

	// change the destination MAC address to the one specified
	for( i = 0; i < 6; i++)
		newbuffer[i] = target_mac[i];

	// send the new packet back via the interface
	if (pcap_sendpacket(handle, newbuffer, size) == 0)
		printf("One packet captured and sent\n");
	else
		pcap_perror(handle, "Failed to inject packet");
}

int main(int argc, char *argv[])
{
	// Only two arguments supported
	if(argc != 2)
	{
		printf("Invalid Parameters. Usage: ./machine_a <MAC(B) using colons>\n");
		exit(EXIT_FAILURE);
	}

	// Convert destination MAC to bytecode
	convert_dest_MAC(argv[1]);

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