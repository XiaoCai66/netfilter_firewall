#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[]){
    char controlinfo[64];
	int controlinfo_len = 0;
	int fd;
	struct stat buf;
	
    unsigned int saddr1;
    unsigned int saddr2;
    unsigned int daddr1;
    unsigned int daddr2;
    unsigned int sport1;
    unsigned int sport2;
    unsigned int dport1;
    unsigned int dport2;
    unsigned int protocol;

    inet_aton(argv[1], (struct in_addr* )&saddr1);
    inet_aton(argv[2], (struct in_addr* )&saddr2);
    inet_aton(argv[3], (struct in_addr* )&daddr1);
    inet_aton(argv[4], (struct in_addr* )&daddr2);
    sport1 = atoi(argv[5]);
    sport2 = atoi(argv[6]);
    dport1 = atoi(argv[7]);
    dport2 = atoi(argv[8]);
    protocol = atoi(argv[9]);
    
	printf("rule:\nsaddr %d-%d\ndaddr:%d-%d\nsport:%d-%d\ndport:%d-%d\n",saddr1,saddr2,daddr1,daddr2,sport1,sport2,dport1,dport2);

    *(int *)(controlinfo) = protocol;// protocol type 1tcp 2udp 3ping
    *(int *)(controlinfo+4) = saddr1;
    *(int *)(controlinfo+8) = saddr2;
    *(int *)(controlinfo+12) = daddr1;
    *(int *)(controlinfo+16) = daddr2;
    *(int *)(controlinfo+20) = sport1;
    *(int *)(controlinfo+24) = sport2;
    *(int *)(controlinfo+28) = dport1;
    *(int *)(controlinfo+32) = dport2;

    controlinfo_len = 36;

	if (stat("/dev/controlinfo",&buf) != 0){
		if (system("mknod /dev/controlinfo c 124 0") == -1){
			printf("Cann't create the devive file ! \n");
			printf("Please check and try again! \n");
			exit(1);
		}
	}

	// write:pass the control info to the kernel space
	fd = open("/dev/controlinfo",O_RDWR,S_IRUSR|S_IWUSR);
	if (fd > 0)
	{
		write(fd,controlinfo,controlinfo_len);
	}
	else {
		perror("can't open /dev/controlinfo \n");
	 	exit(1);
	}
	close(fd);
    return 0;
}