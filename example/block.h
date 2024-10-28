#ifndef BLOCK_H
#define BLOCK_H

typedef struct Block Block;
struct Block {
    char *command;
    int interval;
    unsigned int signal;
};

typedef struct Config Config;
struct Config {
    char delimeter[3];
    unsigned int blocks_len;
    Block *blocks;
};

#endif
