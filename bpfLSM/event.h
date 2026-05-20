#ifndef _EVENT_H
#define _EVENT_H

struct event
{
    __u32 pid;
    char comm[16];
    __u32 dest_ip;
    __u16 dest_port;
};

struct block_key {
    __u32 ip;
    __u64 ino;
};

#endif // _EVENT_H