all:
	gcc Q1.c -lpcap -o machine_a
	gcc Q2.c -lpcap -o machine_b
	gcc Q3.c -lpcap -o machine_c