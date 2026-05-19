xdp_synflood_loader: xdp_synflood.bpf.o xdp_synflood_loader.c
	gcc -O2 -Wall -Wextra -lbpf xdp_synflood_loader.c -o xdp_synflood_loader

xdp_synflood.bpf.o: xdp_synflood.bpf.c
	clang -O2 -Wall -Wextra -g -target bpf -c xdp_synflood.bpf.c -o xdp_synflood.bpf.o

clean:
	rm *.o xdp_synflood_loader

run:
	sudo ./xdp_synflood_loader &

run_bg: xdp_synflood_loader
	sudo echo prepare sudo
	sudo ./xdp_synflood_loader &

watch:	run_bg
	sudo cat /sys/kernel/debug/tracing/trace_pipe
