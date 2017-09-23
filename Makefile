all:
	gcc machine_a.c -lpcap -o machine_a
	gcc machine_b.c -lpcap -o machine_b
	gcc machine_c.c -lpcap -o machine_c