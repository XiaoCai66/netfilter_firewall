#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[]){
    unsigned int saddr1;
    unsigned int saddr2;
    unsigned int daddr1;
    unsigned int daddr2;

    unsigned int taget_addr;

    inet_aton("192.168.233.8", (struct in_addr*)&taget_addr);

    inet_aton(argv[1], (struct in_addr* )&saddr1);
    inet_aton(argv[2], (struct in_addr* )&saddr2);
    inet_aton(argv[3], (struct in_addr* )&daddr1);
    inet_aton(argv[4], (struct in_addr* )&daddr2);
    
    printf("%u,%u,%u,%u\n", saddr1, saddr2, daddr1, daddr2);
    if(taget_addr<saddr2 && saddr1<taget_addr) printf("hi\n");
    return 0;
}