# Ping Packet Capture
This repo contains code on playing around and tinkering with ICMP Ping packets.  

## Run

*In all the three files, change the interface from `eth0` to the one on the machine that will run the executable*

- `make`
- On machine A: `# ./machine_a <details of machine b - MAC in ab:4f.. form>`
- On machine B: `# ./machine_b <details of machine a - IP> <details of machine c - IP>`
- On machine C:	`# ./machine_c`

**Notes**
- Run as `root` or `sudo`
- Make sure you have PCAP installed. Else use `sudo apt install libpcap-dev` on Ubuntu/Debain systems to install the library first
- This works on a network of three machines `Machine A` <--> `Machine B` <--> `Machine C`  
- Code on machine A captures ping packets going from current machine (machine A) to any destination and sends a copy of these packets to machine B. While sending to machine B, only the `destination MAC` address of the ping packet is changed to `machine B's MAC ID` and everything else is kept the same. (Assume machine B is on the same subnet)  
- Code on machine B captures incoming ping packets from machine A and forwards them to machine C. While forwarding, the `destination IP` of ping is changed to `machine C's IP`. To ensure that machine C feels that the ping is coming from machine B, we also change the `source IP` to `machine B` and the `source MAC` to `machine B's interface MAC` and `destinaton MAC` to the `gateway's MAC`.  
Further the code on machine B captures **replies** (a reply is differentiated from a request by setting a flag in the ICMP packet) from machine C and sends them back to machine A. But it modifies `source IP` to the one to which `machine A was initially sending`. It modifies other fields suitably. So machine A feels like it is getting ping replies from the original addressee, though it is machine B which is sending the replies.  
- Code on machine C captures incoming ping requests and counts number of ping requests received from various source IPs. It provides statistics related to ping with respect to the various source IPs.  

**Example flow**  
1. Machine A sends ping to 10.10.10.10 (which may or may not be alive)  
2. Program on machine A captures ping request for 10.10.10.10 and sends it to machine B.  
3. Machine B receives ping request for 10.10.10.10 from machine A. It changes various details and forwards the request to machine C, such that machine C feels that it is a ping request from machine B to machine C.  
4. Machine C program captures ping request and adjusts various counters for statistics. So far, machine C has received one ping request from machine B's IP.  
5. Machine C's OS would reply to machine B's ping request without us having to do anything if the incoming ping request is valid.  
6. Program on machine B when it receives reply from machine C, should capture it. The same reply should be modified to make it look like a reply coming from 10.10.10.10 to machine A. This reply should be sent to machine A.  
7. Program on machine A should receive ping reply from 10.10.10.10 even though no such machine may exist on the network. If such a machine exists, it will get two replies  
8. Program on machine C gives statistics on how many such false replies have been sent by this mechanism.  

Step 5 is important - the incoming request needs to be valid, hence checksum of the IP header needs to be recalculated. Use Wireshark for helping with debugging.  

**Links:**  
<http://www.antionline.com/showthread.php?237944-PING-What-happens>  
<http://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/>  
<https://www.cs.utah.edu/~swalton/listings/sockets/programs/part4/chap18/myping.c>  
<https://austinmarton.wordpress.com/2011/09/14/sending-raw-ethernet-packets-from-a-specific-interface-in-c-on-linux/>  
<https://en.wikipedia.org/wiki/IPv4_header_checksum>  
