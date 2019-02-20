#include <fcntl.h>
#include <stdio.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h> 

#define  AT88SC_CMD_MAX_NR 		10 
#define  AT88SC_CMD_MAGIC 		'x'
#define  COMMUNICATION_TEST  	_IOWR(AT88SC_CMD_MAGIC,0x01, struct at88sc_ioctl_data_t)
#define  READ_CONFIG_ZONE		_IOWR(AT88SC_CMD_MAGIC,0x02, struct at88sc_ioctl_data_t)
#define  WRITE_CONFIG_ZONE		_IOWR(AT88SC_CMD_MAGIC,0x03, struct at88sc_ioctl_data_t)
#define  READ_FUSES				_IOWR(AT88SC_CMD_MAGIC,0x04, struct at88sc_ioctl_data_t)
#define  WRITE_FUSE				_IOWR(AT88SC_CMD_MAGIC,0x05, struct at88sc_ioctl_data_t)
#define  SELECT_USER_ZONE		_IOWR(AT88SC_CMD_MAGIC,0x06, struct at88sc_ioctl_data_t)
#define  VERIFY_CRYPTO			_IOWR(AT88SC_CMD_MAGIC,0x07, struct at88sc_ioctl_data_t)
#define  VERIFY_PASSWED			_IOWR(AT88SC_CMD_MAGIC,0x08, struct at88sc_ioctl_data_t)
#define  SEND_CHECKSUM			_IOWR(AT88SC_CMD_MAGIC,0x09, struct at88sc_ioctl_data_t)
#define  READ_CHECKSUM			_IOWR(AT88SC_CMD_MAGIC,0x0A, struct at88sc_ioctl_data_t)





struct at88sc_ioctl_data_t{
	unsigned char zone;
	unsigned char* ioctl_buff;
	unsigned char ioctl_buff_len;
	unsigned char anti_tearing;
	unsigned char key_index;
};

int main(int argc, char **argv)
{
	unsigned char test_data[2] = {0x55, 0xAA};
	int fd, ret;

	struct at88sc_ioctl_data_t at88sc_ioctl_data;
	at88sc_ioctl_data.zone = 0x03;
	at88sc_ioctl_data.ioctl_buff = test_data;
	at88sc_ioctl_data.ioctl_buff_len = 2;
	at88sc_ioctl_data.anti_tearing = 1;
	at88sc_ioctl_data.key_index = 5;
	
	fd = open("/dev/at88sc", O_RDWR);
	if (fd < 0)
	{
		printf("can't open!\n");
		return -1;
	}

	while (1)
	{
		ret = ioctl(fd, COMMUNICATION_TEST, &at88sc_ioctl_data);
		printf("result = %d\n", ret);
		sleep(5);
		ret = ioctl(fd, READ_CONFIG_ZONE, &at88sc_ioctl_data);
		printf("result = %d\n", ret);
		sleep(5);
		at88sc_ioctl_data.zone = 0x48;
		ret = ioctl(fd, WRITE_CONFIG_ZONE, &at88sc_ioctl_data);
		printf("result = %d\n", ret);
		sleep(5);
		ret = ioctl(fd, READ_FUSES, &at88sc_ioctl_data);
		printf("result = %d\n", ret);
		sleep(5);
	}
	
	return 0;
}


