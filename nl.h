#ifndef _TEST_NT_H_
#define _TEST_HT_H_

#define NL_U_PID 0
#define NL_K_MSG 1
#define NL_CLOSE 2

#define NL_IMP2 31

struct packet_info {
    __u32 src;
    __u32 dst;
};

#endif
