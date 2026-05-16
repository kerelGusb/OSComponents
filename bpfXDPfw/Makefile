xdp_firewall_loader: xdp_firewall.bpf.o xdp_firewall_loader.c
	gcc -O2 -Wall -Wextra -lbpf xdp_firewall_loader.c -o xdp_firewall_loader

xdp_firewall.bpf.o: xdp_firewall.bpf.c
	clang -O2 -Wall -Wextra -g -target bpf -c xdp_firewall.bpf.c -o xdp_firewall.bpf.o

clean:
	rm *.o xdp_firewall_loader

run:
	sudo ./xdp_firewall_loader &

run_bg: xdp_firewall_loader
	sudo echo prepare sudo
	sudo ./xdp_firewall_loader &

watch:	run_bg
	sudo cat /sys/kernel/debug/tracing/trace_pipe
