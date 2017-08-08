#ifndef __AT88SC0104_H__
#define __AT88SC0104_H__

#include <linux/types.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/gpio.h>
#include <linux/uaccess.h>
#include <linux/random.h>
 

// Basic Datatypes
typedef unsigned char  uchar;
typedef unsigned char *puchar;  
typedef signed char    schar;
typedef signed char   *pschar;  
//typedef unsigned int   uint;
typedef unsigned int  *puint;  
typedef signed int     sint;
typedef signed int    *psint;  


/* 调试打印 */
//#define __DEBUG_PRINTK__
#ifdef __DEBUG_PRINTK__ 
#define debug(format,...) printk("LINE[%d]"format,  __LINE__, ##__VA_ARGS__)
#else 
#define debug(format,...)   
#endif 


/*****************************************************************
                                    部分配置区寄存器定义
  ****************************************************************/
#define DCR_ADDR      (0x18)
#define DCR_SME       (0x80)
#define DCR_UCR       (0x40)
#define DCR_UAT       (0x20)
#define DCR_ETA       (0x10)
#define DCR_CS        (0x0F)

#define CM_Ci         (0x50)
#define CM_Sk         (0x58)
#define CM_G          (0x90)

#define CM_FAB        (0x06)
#define CM_CMA        (0x04)
#define CM_PER        (0x00)

#define CM_PSW        (0xB0)
#define CM_PWREAD     (1)
#define CM_PWWRITE    (0)

#define CM_PWRON_CLKS (15)


/*****************************************************************
  					返回值定义
  ****************************************************************/
#define SUCCESS                       (0)
#define FAILED                         (1)
#define FAIL_CMDSTART          (2)
#define FAIL_CMDSEND            (3)
#define FAIL_WRDATA             (4)
#define FAIL_RDDATA              (5)


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




/***********************************************************************
                                    算法部分共定义及函数声明                                                                                  
************************************************************************/
#define RA       (ucGpaRegisters[0])
#define RB       (ucGpaRegisters[1])
#define RC       (ucGpaRegisters[2])
#define RD       (ucGpaRegisters[3])
#define RE       (ucGpaRegisters[4])
#define RF       (ucGpaRegisters[5])
#define RG       (ucGpaRegisters[6])
#define TA       (ucGpaRegisters[7])
#define TB       (ucGpaRegisters[8])
#define TC       (ucGpaRegisters[9])
#define TD       (ucGpaRegisters[10])
#define TE       (ucGpaRegisters[11])
#define SA       (ucGpaRegisters[12])
#define SB       (ucGpaRegisters[13])
#define SC       (ucGpaRegisters[14])
#define SD       (ucGpaRegisters[15])
#define SE       (ucGpaRegisters[16])
#define SF       (ucGpaRegisters[17])
#define SG       (ucGpaRegisters[18])
#define Gpa_byte (ucGpaRegisters[19])
#define Gpa_Regs (20)

#define CM_MOD_R (0x1F)
#define CM_MOD_T (0x1F)
#define CM_MOD_S (0x7F)

#define cm_Mod(x,y,m) ((x+y)>m?(x+y-m):(x+y))
#define cm_RotT(x)    (((x<<1)&0x1e)|((x>>4)&0x01))
#define cm_RotR(x)    (((x<<1)&0x1e)|((x>>4)&0x01))
#define cm_RotS(x)    (((x<<1)&0x7e)|((x>>6)&0x01))


// Basic Definations (if not available elsewhere)
#ifndef FALSE
#define FALSE       (0)
#define TRUE        (!FALSE)
#endif
#ifndef NULL
#define NULL ((void *)0)
#endif

/*************************************************************************
                                            GPIO  部分宏定义
*************************************************************************/
#define CM_CLK_OUT 	gpio_direction_output(at88sc->pin_scl, 1)
#define CM_CLK_HI  	gpio_set_value(at88sc->pin_scl, 1)
#define CM_CLK_LO   	gpio_set_value(at88sc->pin_scl, 0)

#define CM_DATA_OUT 	gpio_direction_output(at88sc->pin_sda, 1)
#define CM_DATA_IN    	gpio_direction_input(at88sc->pin_sda)
#define CM_DATA_HI 		gpio_set_value(at88sc->pin_sda, 1)
#define CM_DATA_LO  		gpio_set_value(at88sc->pin_sda, 0)
#define CM_DATA_RD  		gpio_get_value(at88sc->pin_sda)



/*****************************************************************
  					ioctl 部分接口函数
  ****************************************************************/
uchar cm_SelectChip(uchar ucChipId);
uchar cm_ActiveSecurity(uchar ucKeySet, puchar pucKey, puchar pucRandom, uchar ucEncrypt);
uchar cm_DeactiveSecurity(void);
uchar cm_VerifyPassword(puchar pucPassword, uchar ucSet, uchar ucRW);
uchar cm_ResetPassword(void);
uchar cm_ReadConfigZone(uchar ucCryptoAddr, puchar pucBuffer, uchar ucCount);
uchar cm_WriteConfigZone(uchar ucCryptoAddr, puchar pucBuffer, uchar ucCount, uchar ucAntiTearing);
uchar cm_SetUserZone(uchar ucZoneNumber, uchar ucAntiTearing);
uchar cm_ReadLargeZone(uint uiCryptoAddr, puchar pucBuffer, uchar ucCount);
uchar cm_ReadSmallZone(uchar ucCryptoAddr, puchar pucBuffer, uchar ucCount);
char cm_WriteLargeZone(uint uiCryptoAddr, puchar pucBuffer, uchar ucCount);
uchar cm_WriteSmallZone(uchar ucCryptoAddr, puchar pucBuffer, uchar ucCount);
uchar cm_SendChecksum(puchar pucChkSum);
uchar cm_ReadChecksum(puchar pucChkSum);
uchar cm_ReadFuse(puchar pucFuze);
uchar cm_BurnFuse(uchar ucFuze);

/*
    结构体定义
*/
typedef struct{
    uchar (*SendCommand)(puchar pucCommandBuffer);
    uchar (*ReceiveRet)(puchar pucReceiveData, uchar ucLength);
    uchar (*SendData)(puchar pucSendData, uchar ucLength);
    void (*RandomGen)(puchar pucRandomData);
    void (*WaitClock)(uchar ucLoop);
    uchar (*SendCmdByte)(uchar ucCommand);
} cm_low_level;


struct at88sc_t {
	char *name;
	struct cdev at88sc_cdev;
	int pin_sda;
	int pin_scl;
};
static struct at88sc_t *at88sc;





// 算法部分函数声明
void cm_ResetCrypto(void);
uchar cm_GPAGen(uchar Datain);
void cm_CalChecksum(uchar *Ck_sum);
void cm_AuthenEncryptCal(uchar *Ci, uchar *G_Sk, uchar *Q, uchar *Ch);
void cm_GPAGenN(uchar Count);
void cm_GPAGenNF(uchar Count, uchar DataIn);
void cm_GPAcmd2(puchar pucInsBuff);
void cm_GPAcmd3(puchar pucInsBuff);
void cm_GPAdecrypt(uchar ucEncrypt, puchar pucBuffer, uchar ucCount);
void cm_GPAencrypt(uchar ucEncrypt, puchar pucBuffer, uchar ucCount); 



void cm_PowerOn(void);   
void cm_PowerOff(void);
uchar cm_SendCommand(puchar pucCommandBuffer);
uchar cm_ReceiveData(puchar pucReceiveData, uchar ucLength);
uchar cm_SendData(puchar pucSendData, uchar ucLength);
void cm_RandGen(puchar pucRandomData);
void cm_WaitClock(uchar ucLoop);
uchar cm_SendCmdByte(uchar ucCommand);

uchar cm_ReadCommand(puchar pucInsBuff, puchar pucRetVal, uchar ucLen);
uchar cm_WriteCommand(puchar pucInsBuff, puchar pucSendVal, uchar ucLen);

/*****************************************************************
                                    I2C  部分函数声明
  ****************************************************************/
void cm_Clockhigh(void);
void cm_Clocklow(void);
void cm_ClockCycle(void);
void cm_ClockCycles(uchar ucCount);
void cm_Start(void);
void cm_Stop(void);
uchar cm_Write(uchar ucData);
uchar cm_Read(void);
void cm_WaitClock(uchar loop);
uchar cm_SendCommand(puchar pucInsBuff);
uchar cm_ReceiveRet(puchar pucRecBuf, uchar ucLen);
uchar cm_SendDat(puchar pucSendBuf, uchar ucLen);
void cm_RandomGen(puchar pucRanddat);
void cm_Delay(uchar ucDelay);


#endif    /* __AT88SC0104_H__ */
