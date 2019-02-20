
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h> 

// Basic Datatypes
typedef unsigned char  uchar;
typedef unsigned char *puchar;  
typedef signed char    schar;
typedef signed char   *pschar;  
typedef unsigned int   uint;
typedef unsigned int  *puint;  
typedef signed int     sint;
typedef signed int    *psint;  

/*****************************************************************
  					ioctl 部分命令定义
  ****************************************************************/
#define  AT88SC_CMD_MAX_NR 			20 
#define  AT88SC_CMD_MAGIC 			'x'
#define  COMMUNICATION_TEST  		_IO(AT88SC_CMD_MAGIC,0x01)
#define  AUTHENTICATION				_IO(AT88SC_CMD_MAGIC,0x02)
#define  VERIFY_WRITE_PASSWORD		_IO(AT88SC_CMD_MAGIC,0x03)
#define  SET_USER_ZONE				_IO(AT88SC_CMD_MAGIC,0x04)
#define  READ_USER_ZONE				_IO(AT88SC_CMD_MAGIC,0x05)
#define  WRITE_USER_ZONE			_IO(AT88SC_CMD_MAGIC,0x06)
#define  WRITE_CONFIG_ZONE			_IO(AT88SC_CMD_MAGIC,0x07)
#define  READ_CONFIG_ZONE			_IO(AT88SC_CMD_MAGIC,0x08)
#define  SEND_CHECKSUM				_IO(AT88SC_CMD_MAGIC,0x09)
#define  READ_CHECKSUM				_IO(AT88SC_CMD_MAGIC,0x0A)
#define  READ_FUSE_BYTE     			_IO(AT88SC_CMD_MAGIC,0x0B)
#define  BURN_FUSE                                  _IO(AT88SC_CMD_MAGIC,0x0C)


struct ioctl_data {
    unsigned char common1;
    unsigned char common2;
    unsigned char write_buffer1[8];
    unsigned char write_buffer2[8];
    unsigned char read_buffer[16];
    unsigned char buffer_len;
};

#define CM_PWREAD     (1)
#define CM_PWWRITE    (0)
int fd;


uchar authentication(uchar ucKeySet, puchar pucKey, puchar pucRandom, uchar ucEncrypt)
{
    struct ioctl_data data;
    uchar ret;
    data.common1 = ucKeySet;
    memcpy(data.write_buffer1, pucKey, 8);
    if(pucRandom){
        memcpy(data.write_buffer2, pucRandom, 8);
    }else{
       memset(data.write_buffer2, 0, 8);
    }
    data.common2 = ucEncrypt;
    ret = ioctl(fd, AUTHENTICATION, &data);
    return ret;
}

uchar verify_password(puchar pucPassword, uchar ucSet, uchar ucRW)
{
    struct ioctl_data data;
    uchar ret;
    data.common1 = ucSet;
    memcpy(data.write_buffer1, pucPassword, 3);
    data.common2 = ucRW;
    ret = ioctl(fd, VERIFY_WRITE_PASSWORD, &data);
    return ret;
}


uchar set_user_zone(uchar ucZoneNumber, uchar ucAntiTearing)
{
    struct ioctl_data data;
    uchar ret;
    data.common1 = ucZoneNumber;
    data.common2 = ucAntiTearing;
    ret = ioctl(fd, SET_USER_ZONE, &data);
    return ret;
}

uchar read_user_zone(uchar ucCryptoAddr, puchar pucBuffer, uchar ucCount)
{
    struct ioctl_data data;
    uchar ret;
    data.common1 = ucCryptoAddr;
    data.buffer_len = ucCount;
    ret = ioctl(fd, READ_USER_ZONE, &data);
    memcpy(pucBuffer, data.read_buffer, ucCount);
    return ret;
}


uchar write_user_zone(uchar  ucCryptoAddr, puchar pucBuffer, uchar ucCount)
{
    struct ioctl_data data;
    uchar ret;
    data.common1 = ucCryptoAddr;
    data.buffer_len = ucCount;
    memcpy(data.write_buffer1, pucBuffer, ucCount);
    ret = ioctl(fd, WRITE_USER_ZONE, &data);
    return ret;
}


uchar write_config_zone(uchar ucCryptoAddr, puchar pucBuffer, uchar ucCount, uchar ucAntiTearing)
{
    struct ioctl_data data;
    uchar ret;
    data.common1 = ucCryptoAddr;
    data.buffer_len = ucCount;
    memcpy(data.write_buffer1, pucBuffer, ucCount);
    data.common2 = ucAntiTearing;
    ret = ioctl(fd, WRITE_CONFIG_ZONE, &data);
    return ret;
}


uchar read_config_zone(uchar ucCryptoAddr, puchar pucBuffer, uchar ucCount)
{
    uchar ret;
    struct ioctl_data data;
    data.common1 = ucCryptoAddr;
    data.buffer_len = ucCount;
    ret = ioctl(fd, READ_CONFIG_ZONE, &data);
    memcpy(pucBuffer, data.read_buffer, ucCount);
    return ret;
}


uchar send_checksum(puchar pucChkSum)
{
    uchar ret;
    struct ioctl_data data;
    memcpy(data.write_buffer1, pucChkSum, 2);
    ret = ioctl(fd, SEND_CHECKSUM, &data);
    return ret;
}

uchar read_checksum(puchar pucChkSum)
{
    uchar ret;
    struct ioctl_data data;
    ret = ioctl(fd, READ_CHECKSUM, &data);
    memcpy(pucChkSum, data.read_buffer, 2);
    return ret;
}

uchar read_fuse_byte(puchar pucFuze)
{
    struct ioctl_data data;
    uchar ret;
    ret = ioctl(fd, READ_FUSE_BYTE, &data);
    memcpy(pucFuze, data.read_buffer, 1);
    return ret;
}

uchar burn_fuse(uchar ucFuze)
{
    struct ioctl_data data;    
    uchar ret;
    data.common1 = ucFuze;
    ret = ioctl(fd, BURN_FUSE, &data);
    return ret;

}

uchar communication_test(void)
{
    struct ioctl_data data;
    uchar ret;
    ret = ioctl(fd, COMMUNICATION_TEST, &data);
    return ret;
}



int main()
{
    int ret,i;
    uchar read_buf[8] = {0};
    uchar test_data[8];
    uchar user_data[16] = {0x77, 0x77, 0x77, 0x2E, 0x67, 0x7A, 0x73, 0x65, 0x65, 0x69, 0x6E, 0x67, 0x2E, 0x63, 0x6F, 0x6d};//www.gzseeing.com
    uchar read_user_data[16];
    fd = open("/dev/at88sc",O_RDWR);  
    if (fd <= 0){
        printf("open erro ,the erro num is %d \n",fd);
        exit(1);
    }
    /* 1. 测试通信  */
    ret = communication_test();
    if(ret){
        printf("communication error.\n");
        return -1;
    }else{
        printf("communication successful.\n");
    }


    /* 校验安全密码 */
    //test_data[0] = 0xdd;
    //test_data[1] = 0x42;
    //test_data[2] = 0x97;
    //ret = verify_password(test_data, 7, 0);
    //if(ret){
    //    printf("Secure Code verify error.\n");
    //    return -1;
    //}else{
    //    printf("Secure Code verify successful.\n");
    //}

    
    //test_data[0] = 0x5f;
    //test_data[1] = 0x38;
    //ret = write_config_zone(0x20, test_data, 2, 0);
    //if(ret){
    //    printf("write_config_zone error.\n");
    //    return -1;
    //}else{
    //    printf("write_config_zone successful.\n");
    //}

    /* 设置用户区0 */
    ret = set_user_zone(0, 0);
    if(ret){
        printf("set_user_zone error\n");
        return -1;
    }else{
        printf("set_user_zone 0 successful.\n");
    }

    /* 用户区0  需要 认证Gc0 */
    test_data[0] = 0x00;
    test_data[1] = 0x00;
    test_data[2] = 0x00;
    test_data[3] = 0x00;
    test_data[4] = 0x00;
    test_data[5] = 0x00;
    test_data[6] = 0x00;
    test_data[7] = 0x00;

    ret = authentication(0, test_data, NULL, 1);
    if(ret){
        printf("authentication error\n");
        return -1;
    }else{
        printf("authentication Gc0 successful.\n");
    }

    /* 检验写访问密码0 */ 
    test_data[0] = 0x11;
    test_data[1] = 0x22;
    test_data[2] = 0x33;
    ret = verify_password(test_data, 0, 0);
    if(ret){
        printf("verify_password write error\n");
        return -1;
    }else{
        printf("verify_password write PWD 0 successful.\n");
    }

    /* 检验读访问密码0 */ 
    test_data[0] = 0x33;
    test_data[1] = 0x22;
    test_data[2] = 0x11;
    ret = verify_password(test_data, 0, 1);
    if(ret){
        printf("verify_password read error\n");
        return -1;
    }else{
        printf("verify_password  read PWD 0 successful.\n");
    }


    /* 读取用户区0   数据并校验数据 */
    ret = read_user_zone(0, read_user_data, 16);
    if(ret){
        printf("read_user_zone error\n");
        return -1;
    }

    ret = memcmp(read_user_data, user_data, 16);
    if(ret){
        printf("user zone data verify error\n");
        return -1;
    }else{
        printf("user zone data verify successful\n");
        printf("data:  %s\n", read_user_data);
    }

    
    
    close(fd);
    return 0;
}
