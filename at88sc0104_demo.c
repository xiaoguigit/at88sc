
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
#define  VERIFY_SC_PASSWD                   _IO(AT88SC_CMD_MAGIC,0x0D)
#define  DEACTIVESECURITY                    _IO(AT88SC_CMD_MAGIC,0x0F)

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


uchar authentication(uchar ucKeySet, puchar pucKey, uchar ucEncrypt)
{
    struct ioctl_data data;
    uchar ret;
    data.common1 = ucKeySet;
    if(pucKey != NULL){
        memcpy(data.write_buffer1, pucKey, 8);
    }else{
        return 1;
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
    if(pucPassword != NULL){
        memcpy(data.write_buffer1, pucPassword, 3);
    }else{
        return 1;
    }
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
    if(ret == 0){
        memcpy(pucBuffer, data.read_buffer, ucCount);
    }else{
        return 1;
    }
    return ret;
}


uchar write_user_zone(uchar  ucCryptoAddr, puchar pucBuffer, uchar ucCount)
{
    struct ioctl_data data;
    uchar ret;
    data.common1 = ucCryptoAddr;
    data.buffer_len = ucCount;
    if(pucBuffer != NULL){
        memcpy(data.write_buffer1, pucBuffer, ucCount);
    }else{
        return 1;
    }
    ret = ioctl(fd, WRITE_USER_ZONE, &data);
    return ret;
}


uchar write_config_zone(uchar ucCryptoAddr, puchar pucBuffer, uchar ucCount, uchar ucAntiTearing)
{
    struct ioctl_data data;
    uchar ret;
    data.common1 = ucCryptoAddr;
    data.buffer_len = ucCount;
    if(pucBuffer != NULL){
        memcpy(data.write_buffer1, pucBuffer, ucCount);
    }else{
        return 1;
    }
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
    if(ret == 0){
        memcpy(pucBuffer, data.read_buffer, ucCount);
    }else{
        return 1;
    }
    return ret;
}


uchar send_checksum(puchar pucChkSum)
{
    uchar ret;
    struct ioctl_data data;
    if(pucChkSum){
        memcpy(data.write_buffer1, pucChkSum, 2);
        ret = ioctl(fd, SEND_CHECKSUM, &data);
    }else{
        ret = ioctl(fd, SEND_CHECKSUM, NULL);
    }
    return ret;
}

uchar read_checksum(puchar pucChkSum)
{
    uchar ret;
    struct ioctl_data data;
    ret = ioctl(fd, READ_CHECKSUM, &data);
    if(ret == 0){
        memcpy(pucChkSum, data.read_buffer, 2);
    }else{
        return 1;
    }
    return ret;
}

uchar read_fuse_byte(puchar pucFuze)
{
    struct ioctl_data data;
    uchar ret;
    ret = ioctl(fd, READ_FUSE_BYTE, &data);
    if(ret == 0){
        memcpy(pucFuze, data.read_buffer, 1);
    }else{
        return 1;
    }
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


uchar verify_sc_passwd(puchar passwd)
{
    struct ioctl_data data;
    uchar ret;
    if(passwd != NULL){
        memcpy(data.write_buffer1, passwd, 3); 
    }else{
        return 1;
    }
    ret = ioctl(fd, VERIFY_SC_PASSWD, &data);
    return ret;
}

uchar deactivesecure(void)
{
    uchar ret;
    ret = ioctl(fd, DEACTIVESECURITY, NULL);
    return ret;
}

int main()
{
    int ret,i,j;
    uchar read_buf[8] = {0};
    uchar test_data[8];
    uchar config_data[240];

    uchar user_0_data[16] = {0x77, 0x77, 0x77, 0x2E, 0x67, 0x7A, 0x73, 0x65, 0x65, 0x69, 0x6E, 0x67, 0x2E, 0x63, 0x6F, 0x6d};//www.gzseeing.com
    uchar user_1_data[16] = {0x63, 0x6F, 0x6d, 0x2E, 0x67, 0x7A, 0x73, 0x65, 0x65, 0x69, 0x6E, 0x67, 0x2E, 0x77, 0x77, 0x77};//com.gzseeing.www
    uchar user_2_data[16] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78};//www.gzseeing.com
    uchar user_3_data[16] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};//www.gzseeing.com

    uchar read_user_zone_0[16] = {0};
    uchar read_user_zone_1[16] = {0};
    uchar read_user_zone_2[16] = {0};
    uchar read_user_zone_3[16] = {0};

    uchar read_user_data[16] = {0};
    j = 0;
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
    test_data[0] = 0xdd;
    test_data[1] = 0x42;
    test_data[2] = 0x97;
    ret = verify_sc_passwd(test_data);
    if(ret){
        printf("Secure Code verify error.\n");
        return -1;
    }else{
        printf("Secure Code verify successful.\n");
    }
 #if 0   
    test_data[0] = 0xd7;    // Gc2  加密  nomal mode   (无密码)
    test_data[1] = 0x9b;

    test_data[2] = 0x46;   //  Gc2  POK(Gc1)  PWD3  加密  dual mode 
    test_data[3] = 0x9b;

    test_data[4] = 0x57;   //  Gc1  pwd1  加密      nomal mode 
    test_data[5] = 0x59;

    test_data[6] = 0x57;   //  Gc3  pwd2  加密     nomal mode
    test_data[7] = 0xda;

    ret = write_config_zone(0x20, test_data, 8, 0);
    if(ret){
        printf("write_config_zone error.\n");
        return -1;
    }else{
       printf("write_config_zone successful.\n");
    }

#endif

    uchar addr = 0x0;
    printf("%02x :   ", addr);
    for(j = 0; j < 31; j++){
        ret = read_config_zone(addr + j * 8, test_data, 8);
        if(ret){
            //return -1;
        }else{
            for(i = 0; i < 8; i++){
                printf("%02x ", test_data[i]);
            }
            printf("\n%02x :   ",addr + (j+1) * 8);
        }
    }
#if 0
        ret = read_config_zone(0x0, test_data, 8);
    if(ret){
        printf("read_config_zone error.\n");
        return -1;
    }else{
       printf("read_config_zone successful.\n");
        for(i = 0; i < 8; i++){
            printf("%02x ", test_data[i]);
        }
        printf("\n");
    }

        ret = read_config_zone(0x0, test_data, 8);
    if(ret){
        printf("read_config_zone error.\n");
        return -1;
    }else{
       printf("read_config_zone successful.\n");
        for(i = 0; i < 8; i++){
            printf("%02x ", test_data[i]);
        }
        printf("\n");
    }


    ret = read_config_zone(0x18, test_data, 1);
    if(ret){
        printf("read_config_zone error.\n");
        return -1;
    }else{
       printf("read_config_zone successful.\n");
       printf("DCR = %02x\n", test_data[0]);
    }

    ret = read_config_zone(0x20, test_data, 8);
    if(ret){
        printf("read_config_zone error.\n");
        return -1;
    }else{
        printf("read_config_zone  0x20 successful.\n");
        for(i = 0; i < 8; i++){
            printf("%02x ", test_data[i]);
        }
        printf("\n");
    }

    ret = read_config_zone(0x90, test_data, 8);
    if(ret){
        printf("read_config_zone error.\n");
        return -1;
    }else{
        printf("read_config_zone  0x90 successful.\n");
        for(i = 0; i < 8; i++){
            printf("%02x ", test_data[i]);
        }
        printf("\n");
    }

    ret = read_config_zone(0x98, test_data, 8);
    if(ret){
        printf("read_config_zone error.\n");
        return -1;
    }else{
        printf("read_config_zone  0x98 successful.\n");
        for(i = 0; i < 8; i++){
            printf("%02x ", test_data[i]);
        }
        printf("\n");
    }


    ret = read_config_zone(0xa0, test_data, 8);
    if(ret){
        printf("read_config_zone error.\n");
        return -1;
    }else{
        printf("read_config_zone  0xa0 successful.\n");
        for(i = 0; i < 8; i++){
            printf("%02x ", test_data[i]);
        }
        printf("\n");
    }

    ret = read_config_zone(0xa8, test_data, 8);
    if(ret){
        printf("read_config_zone error.\n");
        return -1;
    }else{
        printf("read_config_zone  0xa8 successful.\n");
        for(i = 0; i < 8; i++){
            printf("%02x ", test_data[i]);
        }
        printf("\n");
    }

        ret = read_config_zone(0xb0, test_data, 8);
    if(ret){
        printf("read_config_zone error.\n");
        return -1;
    }else{
        printf("read_config_zone  0xb0 successful.\n");
        for(i = 0; i < 8; i++){
            printf("%02x ", test_data[i]);
        }
        printf("\n");
    }


        ret = read_config_zone(0xb8, test_data, 8);
    if(ret){
        printf("read_config_zone error.\n");
        return -1;
    }else{
        printf("read_config_zone  0xb8 successful.\n");
        for(i = 0; i < 8; i++){
            printf("%02x ", test_data[i]);
        }
        printf("\n");
    }


        ret = read_config_zone(0xc0, test_data, 8);
    if(ret){
        printf("read_config_zone error.\n");
        return -1;
    }else{
        printf("read_config_zone  0xc0 successful.\n");
        for(i = 0; i < 8; i++){
            printf("%02x ", test_data[i]);
        }
        printf("\n");
    }


        ret = read_config_zone(0xc8, test_data, 8);
    if(ret){
        printf("read_config_zone error.\n");
        return -1;
    }else{
        printf("read_config_zone  0xc8 successful.\n");
        for(i = 0; i < 8; i++){
            printf("%02x ", test_data[i]);
        }
        printf("\n");
    }

    ret = read_config_zone(0xe8, test_data, 8);
    if(ret){
        printf("read_config_zone error.\n");
        return -1;
    }else{
        printf("read_config_zone  0xe8 successful.\n");
        for(i = 0; i < 8; i++){
            printf("%02x ", test_data[i]);
        }
        printf("\n");
    }

#endif

    /* 用户区1  需要 认证Gc2  , 加密，验证密码3*/
    test_data[0] = 0x22;
    test_data[1] = 0x22;
    test_data[2] = 0x22;
    test_data[3] = 0x22;
    test_data[4] = 0x22;
    test_data[5] = 0x22;
    test_data[6] = 0x22;
    test_data[7] = 0x22;

    ret = authentication(2, test_data, 1);
    if(ret){
        printf("authentication error\n");
        return -1;
    }else{
        printf("authentication Gc2 successful.\n");
    }

    test_data[0] = 0x44;
    test_data[1] = 0x55;
    test_data[2] = 0x66;
    ret = verify_password(test_data, 3, 0);
    if(ret){
        printf("PSW 3 write verify error.\n");
        return -1;
    }else{
        printf("PSW 3 write  verify successful.\n");
    }

    test_data[0] = 0x66;
    test_data[1] = 0x55;
    test_data[2] = 0x44;
    ret = verify_password(test_data, 3, 1);
    if(ret){
        printf("PSW 3 read verify error.\n");
        return -1;
    }else{
        printf("PSW 3 read  verify successful.\n");
    }

    ret = set_user_zone(0, 0);
    if(ret){
        printf("set_user_zone error\n");
        return -1;
    }else{
        printf("set_user_zone 0 successful.\n");
    }

    ret = read_user_zone(0, read_user_zone_0, 16);
    if(ret){
        printf("read_user_zone 0 error\n");
        return -1;
    }else{
        printf("read_user_zone  0 successful.\n                                                    ");
    }





    ret = set_user_zone(1, 0);
    if(ret){
        printf("set_user_zone error\n");
        //return -1;
    }else{
        printf("set_user_zone 1 successful.\n");
    }

    /*
    ret = write_user_zone(0, read_user_zone_0, 16);
    if(ret){
        printf("write_user_zone 1 error\n");
        //return -1;
   }else{
        ret = send_checksum(NULL);
        if(ret){
            printf("send_checksum  error\n");
            //return -1;
        }else{
            printf("write_user_zone  1 successful.\n");
        }
    }
    */
    
     ret = read_user_zone(0, read_user_zone_1, 16);
    if(ret){
        printf("read_user_zone 1 error\n");
        return -1;
    }else{
        printf("read_user_zone  1 successful.\n                                                    ");
    }

    //deactivesecure();


    /* 用户区2  需要 认证Gc1  , 加密，验证密码1*/
    test_data[0] = 0x11;
    test_data[1] = 0x11;
    test_data[2] = 0x11;
    test_data[3] = 0x11;
    test_data[4] = 0x11;
    test_data[5] = 0x11;
    test_data[6] = 0x11;
    test_data[7] = 0x11;

    ret = authentication(1, test_data, 1);
    if(ret){
        printf("authentication error\n");
        return -1;
    }else{
        printf("authentication Gc1 successful.\n");
    }

    test_data[0] = 0x22;
    test_data[1] = 0x33;
    test_data[2] = 0x44;
    ret = verify_password(test_data, 1, 0);
    if(ret){
        printf("PSW 1 write verify error.\n");
        return -1;
    }else{
        printf("PSW 1 write  verify successful.\n");
    }

    test_data[0] = 0x44;
    test_data[1] = 0x33;
    test_data[2] = 0x22;
    ret = verify_password(test_data, 1, 1);
    if(ret){
        printf("PSW 1 read verify error.\n");
       return -1;
    }else{
        printf("PSW 1 read  verify successful.\n");
    }



    
    ret = set_user_zone(2, 0);
    if(ret){
        printf("set_user_zone error\n");
        return -1;
    }else{
        printf("set_user_zone 2 successful.\n");
    }

    ret = read_user_zone(0, read_user_zone_2, 16);
    if(ret){
        printf("read_user_zone 2 error\n");
        return -1;
    }else{
        printf("read_user_zone  2 successful.\n                                                    ");
    }


    //deactivesecure();


    /* 用户区3  需要 认证Gc3  , 加密，验证密码2*/
    test_data[0] = 0x33;
    test_data[1] = 0x33;
    test_data[2] = 0x33;
    test_data[3] = 0x33;
    test_data[4] = 0x33;
    test_data[5] = 0x33;
    test_data[6] = 0x33;
    test_data[7] = 0x33;

    ret = authentication(3, test_data, 1);
    if(ret){
        printf("authentication error\n");
        return -1;
    }else{
        printf("authentication Gc3 successful.\n");
    }

    test_data[0] = 0x33;
    test_data[1] = 0x44;
    test_data[2] = 0x55;
    ret = verify_password(test_data, 2, 0);
    if(ret){
        printf("PSW 2 write verify error.\n");
        return -1;
    }else{
        printf("PSW 2 write  verify successful.\n");
    }

    test_data[0] = 0x55;
    test_data[1] = 0x44;
    test_data[2] = 0x33;
    ret = verify_password(test_data, 2, 1);
    if(ret){
        printf("PSW 2 read verify error.\n");
        return -1;
    }else{
        printf("PSW 2 read  verify successful.\n");
    }




    ret = set_user_zone(3, 0);
    if(ret){
        printf("set_user_zone error\n");
        return -1;
    }else{
        printf("set_user_zone 3 successful.\n");
    }


    ret = read_user_zone(0, read_user_zone_3, 16);
    if(ret){
        printf("read_user_zone 3 error\n");
        return -1;
    }else{
        printf("read_user_zone  3 successful.\n                                                    ");
    }

    deactivesecure();

    if(memcmp(user_0_data, read_user_zone_0, 16) != 0
        || memcmp(user_1_data, read_user_zone_1, 16) != 0
        || memcmp(user_2_data, read_user_zone_2, 16) != 0
        || memcmp(user_3_data, read_user_zone_3, 16) != 0){
        printf("user data error\n");
        return -1;
    }else{
        printf("ALL is OK !\n");
    }
    
    close(fd);
    return 0;
}
