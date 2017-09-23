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
#include <ifaddrs.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#define MAC_ARRAY_LEN 18
#define MAX_LEN 500

char pc_mac[MAC_ARRAY_LEN];
char gateway_mac[MAC_ARRAY_LEN];

// in byte form
uint8_t pc_mac_byte[6];
uint8_t gateway_mac_byte[6];

char A_IP[MAX_LEN];
char B_IP[MAX_LEN];
char C_IP[MAX_LEN];

pcap_t *handle; //Handle of the device that shall be sniffed

int flag; // to set src ip properly

// function to calculate ip checksum
unsigned short checksum(const void *b, int len)
{
	int i;
	// casting is a mess
	// cast from void to u_char, then operate	
	u_char *d = (u_char *)(b);
	// copy to temp array
	u_char c[20];
	for(i=0;i<20;++i)
	{
		c[i] = d[i];
	}
	// interchange elements in temparray
	for(i=0;i<20;i+=2)
	{
		u_char temp = c[i+1];
		c[i+1] = c[i];
		c[i] = temp;
	}

	unsigned short *buf = (unsigned short *)(c);
	unsigned int sum=0;
	unsigned short result;

	// checksum as per Wikipedia
	buf = (unsigned short *)(c);
	for(sum = 0; len > 1; len -= 2)
		sum += *buf++;
	if(len == 1)
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

// function to get this device interface's MAC address
void get_MAC_and_IP(char *devname)
{
	int i;
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	char mac[MAC_ARRAY_LEN];
	char *MAC = mac;

	strcpy(s.ifr_name, devname);
	if(0 == ioctl(fd, SIOCGIFHWADDR, &s))
	{
		for(i = 0; i < 6; ++i)
			MAC += sprintf(MAC, "%02X:", (unsigned char) s.ifr_addr.sa_data[i]);
		mac[MAC_ARRAY_LEN - 1] = '\0';

		strcpy(pc_mac, mac);
		printf("This device MAC: %s\n", pc_mac);
	}

	struct ifaddrs *addrs;
	getifaddrs(&addrs);
	struct ifaddrs *tmp = addrs;

	while(tmp)
	{
	    if(tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
	    {
	        struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
	     	// if it is the desired interface
	        if(!strcmp(tmp->ifa_name, devname)){
	        	strcpy(B_IP, inet_ntoa(pAddr->sin_addr));
	        	break;
	        }
	    }
	    tmp = tmp->ifa_next;
	}
	printf("The device IP is %s\n", B_IP);
	freeifaddrs(addrs);
}

// function to get the MAC of the gateway
void get_gatewayMAC()
{
	char line[MAX_LEN]; // Read with fgets().
	char ip_address[MAX_LEN], gateway_ip_address[MAX_LEN]; // Obviously more space than necessary, just illustrating here.
	int hw_type;
	int flags;
	char mac_address[MAX_LEN];
	char mask[MAX_LEN];
	char device[MAX_LEN];

	FILE *newfp = popen("/bin/netstat -rn", "r");
	char dest[MAX_LEN], gateway[MAX_LEN], genmask[MAX_LEN], flags_n[MAX_LEN];
	char mss[MAX_LEN], window[MAX_LEN], irttt[MAX_LEN], iface[MAX_LEN];
	fgets(line, sizeof(line), newfp); // skip 1st kernel line
	fgets(line, sizeof(line), newfp); // skip 2nd header lines

	while(fgets(line, sizeof(line)-1, newfp) != NULL)
	{
		sscanf(line, "%s %s %s %s %s %s %s %s\n",
			dest, gateway, genmask, flags_n, mss, window, irttt, iface);
		if(strcmp(gateway, "0.0.0.0") != 0 && strcmp(iface, "eth1") == 0)
		{
			break;
		}
	}

	pclose(newfp);

	FILE *fp = fopen("/proc/net/arp", "r");
	fgets(line, sizeof(line), fp);    // Skip the first line (column headers).

	while(fgets(line, sizeof(line), fp))
	{
	    // Read the data.
	    sscanf(line, "%s 0x%x 0x%x %s %s %s\n",
          	ip_address,
          	&hw_type,
          	&flags,
          	mac_address,
          	mask,
          	device);
    	// if it is a gateway
    	if(flags == 2 && strcmp(device, iface) == 0 && strcmp(ip_address, gateway) == 0)
    		break;
	}
	strcpy(gateway_mac, mac_address);
	printf("The gateway MAC is %s\n", gateway_mac);

	fclose(fp);
}

// function to convert the destination MAC (separated by colons) to bytecode
void convert_MAC()
{
	int values[6];
	int i;

	if(6 == sscanf(pc_mac, "%X:%X:%X:%X:%X:%X%c",
		&values[0], &values[1], &values[2],
		&values[3], &values[4], &values[5] ) )
	{
		/* convert to uint8_t */
		for(i = 0; i<6; ++i)
			pc_mac_byte[i] = (uint8_t) values[i];
	}
	else
	{
		printf("Invalid Destination MAC\n");
		exit(1);
	}
	if(6 == sscanf(gateway_mac, "%X:%X:%X:%X:%X:%X%c",
		&values[0], &values[1], &values[2],
		&values[3], &values[4], &values[5] ) )
	{
		/* convert to uint8_t */
		for( i = 0; i < 6; ++i )
			gateway_mac_byte[i] = (uint8_t) values[i];
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
	int i;
	int size = header->len; // the size of the packet (essentially, the size of buffer)
	 
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

	if(iph->protocol != 1) // ICMP Protocol for ping - Only for ICMP requests.
		return;

	// source and destination MAC
	char source_mac[MAC_ARRAY_LEN], dest_mac[MAC_ARRAY_LEN];
	char *s = source_mac, *d = dest_mac;

	// extracts the souce and destination mac from the packet. First 6 bytes - destination, next 6 are source
	for(i = 0; i < 6; ++i)
	{
		d += sprintf(d, "%.2X:", (unsigned char) buffer[i]);
		s += sprintf(s, "%.2X:", (unsigned char) buffer[6 + i]);
	}

	source_mac[MAC_ARRAY_LEN - 1] = '\0';
	dest_mac[MAC_ARRAY_LEN - 1] = '\0';

	// If the dest of this ICMP packet doesn't match this interface's MAC, ignore this packet
	if(strcmp(dest_mac, pc_mac) != 0)
		return;

	// get the source and destination IP address
	struct sockaddr_in source, dest;
	memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    
    // if it is coming from A
    if(!strcmp(inet_ntoa(source.sin_addr), A_IP))
    {
    	// Only when packet is coming from A
    	if(!flag)
    	{
    		memset(&dest, 0, sizeof(dest));
    		dest.sin_addr.s_addr = iph->daddr;
    		flag = 1;
    	}

		// SENDING TO C
		// copy packet contents into a new buffer
		u_char *newbuffer = (u_char*)malloc(size * sizeof(u_char));

		for(i = 0; i < size; i++)
			newbuffer[i] = buffer[i];

		// change the destination MAC address to the one specified
		for(i = 0; i < 6; i++)
			newbuffer[i] = gateway_mac_byte[i];

		// change the source MAC address to the one specified
		for(i = 6; i < 12; i++)
			newbuffer[i] = pc_mac_byte[i-6];

		iph = (struct iphdr*)(newbuffer + sizeof(struct ethhdr));
		unsigned short iphdrlen = iph->ihl*4;

		// set the destination IP
		struct in_addr temp;
		inet_aton(C_IP, &temp);
		iph->daddr = temp.s_addr;

		// set the source IP
		inet_aton(B_IP, &temp);
		iph->saddr = temp.s_addr;

		// checksum part
		// set the checksum bits to 0x0000 before calculating the checksum
		// important
		newbuffer[24] = 0x0;
		newbuffer[25] = 0x0;
		u_char tempbuffer[20];
		// extract the bits over which checksum will be calculated
		for(i=0;i<20;++i){
			tempbuffer[i] = newbuffer[i+14];
		}
		// call to calculate checksum and set
		iph->check = checksum(tempbuffer,20);
		// switch 24 and 25
		u_char tempchar = newbuffer[24];
		newbuffer[24] = newbuffer[25];
		newbuffer[25] = tempchar;

		// send the new packet back via the interface
		if (pcap_sendpacket(handle, newbuffer, size) == 0)
			printf("One packet captured and sent to C\n");
		else
			pcap_perror(handle, "Failed to inject packet");
    }

    // if it is coming from C
    if(!strcmp(inet_ntoa(source.sin_addr), C_IP)){
		// SENDING TO A
		// copy packet contents into a new buffer
		u_char *newbuffer = (u_char*)malloc(size * sizeof(u_char));

		for(i = 0; i < size; i++)
			newbuffer[i] = buffer[i];

		// change the destination MAC address to gateway
		for(i = 0; i < 6; i++)
			newbuffer[i] = gateway_mac_byte[i];

		// change the source MAC address to B
		for(i = 6; i < 12; i++)
			newbuffer[i] = pc_mac_byte[i-6];

		iph = (struct iphdr*)(newbuffer + sizeof(struct ethhdr));
		unsigned short iphdrlen = iph->ihl*4;

		// set the destination IP
		struct in_addr temp;
		inet_aton(A_IP, &temp);
		iph->daddr = temp.s_addr;

		// set the source IP - from A's dest address
		if(flag)
		{
			iph->saddr = dest.sin_addr.s_addr;
			flag = 0;

			// checksum part
			// set the checksum bits to 0x0000 before calculating the checksum
			// important
			newbuffer[24] = 0x0;
			newbuffer[25] = 0x0;
			u_char tempbuffer[20];
			// extract the bits over which checksum will be calculated
			for(i=0;i<20;++i){
				tempbuffer[i] = newbuffer[i+14];
			}
			// call to calculate checksum and set
			iph->check = checksum(tempbuffer,20);
			// switch 24 and 25
			u_char tempchar = newbuffer[24];
			newbuffer[24] = newbuffer[25];
			newbuffer[25] = tempchar;
		}
		else
		{
			return;
		}

		// send the new packet back via the interface
		if (pcap_sendpacket(handle, newbuffer, size) == 0)
			printf("One packet captured and sent to A\n");
		else
			pcap_perror(handle, "Failed to inject packet");
	}
}

int main(int argc, char *argv[])
{
	// Only two arguments supported
	if(argc != 3)
	{
		printf("Invalid Parameters. Usage: ./machine_b <details​ of​ machine​ ​a - ​IP>​ ​<details​ ​of​ ​machine​ ​c - ​IP>\n");
		exit(EXIT_FAILURE);
	}

	flag = 0;

	strcpy(A_IP, argv[1]);
	strcpy(C_IP, argv[2]);

	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	// specifies which interface to use
	// dev = pcap_lookupdev(errbuf);
	dev = "eth1\0";
	if (dev == NULL) 
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	// Get this interface's mac
	get_MAC_and_IP(dev);

	// get the MAC of the gateway
	get_gatewayMAC();
	
	// Convert interface MAC and gateway MAC to bytecode
	convert_MAC();

	//Open the device for sniffing
	printf("Opening device %s for sniffing...\n" , dev);
	handle = pcap_open_live(dev, 65536, 1, 0, errbuf);
	 
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , dev , errbuf);
		exit(1);
	}
	printf("Sniffer set up\n");

	// Loop and invoke callback for each captured packet
	pcap_loop(handle, -1, process_packet, NULL);

	return 0;
}