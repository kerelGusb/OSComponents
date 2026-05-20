lsm_firewall_loader: lsm_firewall.bpf.o lsm_firewall_loader.c event.h
	gcc -O2 -Wall -Wextra -lbpf lsm_firewall_loader.c -o lsm_firewall_loader

lsm_firewall.bpf.o: lsm_firewall.bpf.c vmlinux.h event.h
	clang -g -O2 -Wall -Wextra -target bpf -c lsm_firewall.bpf.c -o lsm_firewall.bpf.o

clean:
	rm *.o lsm_firewall_loader vmlinux.h

vmlinux.h: /sys/kernel/btf/vmlinux
	# bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

run: lsm_firewall_loader
	sudo ./lsm_firewall_loader
