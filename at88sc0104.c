#include "at88sc0104.h"


// 全局变量
static uchar ucCM_Ci[8], ucCM_G_Sk[8];
static uchar ucCM_Q_Ch[16], ucCM_Ci2[8];
static uchar ucCM_UserZone;
static uchar ucCM_AntiTearing;
static uchar ucCM_InsBuff[4];
static uchar ucCM_Encrypt;
static uchar ucCM_Authenticate;
static uchar ucGpaRegisters[Gpa_Regs];
static int major;
static dev_t devid;
static struct class *cls;





// CryptoMemory 底层接口
cm_low_level CM_LOW_LEVEL = {
    cm_SendCommand,  // SendCommand
    cm_ReceiveData,     // ReceiveRet
    cm_SendData,        // SendData
    cm_RandGen,         // RandomGen
    cm_WaitClock,       // WaitClock
    cm_SendCmdByte      // SendCmdByte
};


static uchar cm_AuthenEncrypt(uchar ucCmd1, uchar ucAddrCi, puchar pucCi, puchar pucG_Sk, puchar pucRandom)
{
    uchar i;
    uchar ucReturn;

    /* 获取随机数 */
    if (pucRandom) {
        for (i = 0; i < 8; ++i) {
            ucCM_Q_Ch[i] = pucRandom[i];
        } 
    }else{      
        CM_LOW_LEVEL.RandomGen(ucCM_Q_Ch);
    }

    cm_AuthenEncryptCal(pucCi, pucG_Sk, ucCM_Q_Ch, &ucCM_Q_Ch[8]);
    
    /* 发起认证 */
    ucCM_InsBuff[0] = 0xb8;
    ucCM_InsBuff[1] = ucCmd1;
    ucCM_InsBuff[2] = 0x00;
    ucCM_InsBuff[3] = 0x10;
    if ((ucReturn = cm_WriteCommand(ucCM_InsBuff, ucCM_Q_Ch, 16)) != SUCCESS) {
        debug("cm_WriteCommand failed\n");
        return ucReturn;
    }   
    
    /* 芯片校验需要等待几个时钟 */
    CM_LOW_LEVEL.WaitClock(3);
                             
    /* 读取校验结果 */
    if ((ucReturn = cm_ReadConfigZone(ucAddrCi, ucCM_Ci2, 8)) != SUCCESS) {
        debug("cm_ReadConfigZone failed\n");
        return ucReturn;
    }

    /* 比较 */
    for(i=0; i<8; i++) {
        if (pucCi[i] != ucCM_Ci2[i]) {
            debug("authentication  failed\n");
            return FAILED;
        }
    }

    return SUCCESS;
}

// Activate Security
//
// When called the function:
// reads the current cryptogram (Ci) of the key set, 
// computes the next cryptogram (Ci+1) based on the secret key pucKey (GCi) and the random number selected,
// sends the (Ci+1) and the random number to the CryptoMemory?device, 
// computes (Ci+2) and compares its computed value the new cryptogram of the key set.
// If (Ci+2) matches the new cryptogram of the key set, authentication was successful.
// In addition, if ucEncrypt is TRUE the function:
// computes the new session key (Ci+3) and a challenge, 
// sends the new session key and the challenge to the CryptoMemory?device, 
// If the new session key and the challenge are correctly related, encryption is activated.
//

uchar cm_ActiveSecurity(uchar ucKeySet, puchar pucKey, puchar pucRandom, uchar ucEncrypt)
{
    uchar i;
    uchar ucAddrCi;
    uchar ucReturn;
    
    /* 读取Ci  */
    ucAddrCi = CM_Ci + (ucKeySet << 4);
    if ((ucReturn = cm_ReadConfigZone(ucAddrCi, ucCM_Ci, 8)) != SUCCESS){
        return ucReturn;
    }
    
    /* Gc */
    for (i = 0; i < 8; ++i) 
        ucCM_G_Sk[i] = pucKey[i];

    /* 激活认证 */
    if ((ucReturn = cm_AuthenEncrypt(ucKeySet, ucAddrCi, ucCM_Ci, ucCM_G_Sk, pucRandom)) != SUCCESS) {
        debug("cm_AuthenEncrypt failed\n");
        return ucReturn;
    }
    
    ucCM_Authenticate = TRUE;
        
    /* 如果需要加密认证，则激活加密认证 */
    if (ucEncrypt) {
        if (pucRandom) {
            pucRandom += 8;
        }
        
        if ((ucReturn = cm_AuthenEncrypt(ucKeySet+0x10, ucAddrCi, ucCM_Ci, ucCM_G_Sk, pucRandom)) != SUCCESS) {
            debug("cm_AuthenEncrypt failed\n");
            return ucReturn;
        }
        ucCM_Encrypt = TRUE;
    }

    /* 认证成功 */
    return SUCCESS;
}


//芯片通讯测试函数
uchar cm_aCommunicationTest(void)
{
    uchar write_data[2] = {0x55, 0xaa};//测试数据
    uchar read_data[2];
    cm_WriteConfigZone(0xa, write_data, 2, FALSE);
    cm_ReadConfigZone(0xa, read_data, 2);
    if(memcmp(write_data, read_data, 2) != 0){
        return FAILED;
    }
    return SUCCESS;
}


/*************************************************************************
                                       总线通讯基础函数                                                                                                     
**************************************************************************/

 // 半个时钟周期高
void cm_Clockhigh(void)
{
    cm_Delay(1);
    CM_CLK_HI;
    cm_Delay(1);
}

// 半个时钟周期低
void cm_Clocklow(void)
{
    cm_Delay(1);
    CM_CLK_LO;
    cm_Delay(1);
}

//一个完整的时钟
void cm_ClockCycle(void)
{
    cm_Delay(1);
    CM_CLK_LO;
    cm_Delay(2);
    CM_CLK_HI;
    cm_Delay(1);
}

// n 个完整的时钟
void cm_ClockCycles(uchar ucCount)
{
    uchar i;
    for (i = 0; i < ucCount; ++i) {
        cm_ClockCycle();
    }
}

// 启动总线
void cm_Start(void)
{
    CM_DATA_OUT;
    cm_Clocklow();
    CM_DATA_HI;
    cm_Delay(4);
    cm_Clockhigh();
    cm_Delay(4);
    CM_DATA_LO;
    cm_Delay(8);
    cm_Clocklow();
    cm_Delay(8);
}

// 停止总线
void cm_Stop(void)
{
    CM_DATA_OUT; 
    cm_Clocklow();
    CM_DATA_LO;
    cm_Delay(4);
    cm_Clockhigh();
    cm_Delay(8);
    CM_DATA_HI;
    cm_Delay(4);
}

// 总线写一个字节
uchar cm_Write(uchar ucData)
{
    uchar i;

    CM_DATA_OUT;
    for(i=0; i<8; i++) {
        cm_Clocklow();
        if (ucData&0x80) 
            CM_DATA_HI;
        else             
            CM_DATA_LO;
        cm_Clockhigh();
        ucData = ucData<<1;
    }
    cm_Clocklow();

    // 等待ACK
    CM_DATA_IN;
    cm_Delay(8);
    cm_Clockhigh();
    
    while(i > 1) {
        cm_Delay(2);
        if (CM_DATA_RD)
            i--;
        else 
            i = 0;    //ACK 
    }      
    cm_Clocklow();
    CM_DATA_OUT;
    
    return i;
}

// 发送ACK  或NACK
void cm_AckNak(uchar ucAck)
{
    CM_DATA_OUT; 
    cm_Clocklow();
    if (ucAck) 
        CM_DATA_LO;               // ACK
    else       
        CM_DATA_HI;               //  NACK
    cm_Delay(2);
    cm_Clockhigh();
    cm_Delay(8);
    cm_Clocklow();
}


//总线读一个字节
uchar cm_Read(void)
{
    uchar i;
    uchar rByte = 0;
    
    CM_DATA_IN;
    CM_DATA_HI;
    for(i=0x80; i; i=i>>1)
    {
        cm_ClockCycle();
        if (CM_DATA_RD) rByte |= i;
        cm_Clocklow();
    }
    CM_DATA_OUT;
    return rByte;
}


// 等待时钟
void cm_WaitClock(uchar loop)
{
    uchar i, j;
    debug("%s\n", __func__);
    CM_DATA_LO;
    for(j=0; j<loop; j++) {
        cm_Start();
        for(i = 0; i<15; i++) 
            cm_ClockCycle();
        cm_Stop();
    }
}

// 发送一个命令(4  字节)
uchar cm_SendCommand(puchar pucInsBuff)
{
    uchar i, ucCmd;
    
    i = 100;
    ucCmd = (pucInsBuff[0]&0x0F) | 0xb0;

    while (i) {
        cm_Start();
        if (cm_Write(ucCmd) == 0)
            break;
        
        if (--i == 0) 
            return FAIL_CMDSTART;
    }
    
    for(i = 1; i< 4; i++) {
        if (cm_Write(pucInsBuff[i]) != 0) 
            return FAIL_CMDSEND;
    }

    debug("%s ok\n", __func__);    
    return SUCCESS;
}


//  接收数据
uchar cm_ReceiveData(puchar pucRecBuf, uchar ucLen)
{
    int i;
    debug("%s\n", __func__);
    for(i = 0; i < (ucLen-1); i++) {
        pucRecBuf[i] = cm_Read();
        cm_AckNak(TRUE);
    }
    pucRecBuf[i] = cm_Read();
    cm_AckNak(FALSE);
    cm_Stop();
    return SUCCESS;
}

// 发送数据
uchar cm_SendData(puchar pucSendBuf, uchar ucLen)
{
    int i;
    debug("%s\n", __func__);
    for(i = 0; i< ucLen; i++) {
        if (cm_Write(pucSendBuf[i])==1) 
            return FAIL_WRDATA;
    }
    cm_Stop();
    
    return SUCCESS;
}

// 发起读命令
uchar cm_ReadCommand(puchar pucInsBuff, puchar pucRetVal, uchar ucLen)
{ 
    uchar ucReturn;
    int i;

    for(i = 0; i < 20; i++){
        if ((ucReturn = CM_LOW_LEVEL.SendCommand(pucInsBuff)) != SUCCESS) 
            continue;
        else
            break;
    }
    
    if(i >= 20){
        return ucReturn;
    }

    return CM_LOW_LEVEL.ReceiveRet(pucRetVal, ucLen);
}




// 发起写命令
uchar cm_WriteCommand(puchar pucInsBuff, puchar pucSendVal, uchar ucLen)
{ 
    uchar ucReturn;
    if ((ucReturn = CM_LOW_LEVEL.SendCommand(pucInsBuff)) != SUCCESS) {
        debug("CM_LOW_LEVEL.SendCommand\n");
        return ucReturn;
    }
    debug("%s ok\n", __func__);    

    return CM_LOW_LEVEL.SendData(pucSendVal, ucLen);
}






/****************************************************************************
                                         ioctl 部分接口函数                                                                                                       
****************************************************************************/

// 设置(选择)用户区
uchar cm_SetUserZone(uchar ucZoneNumber, uchar ucAntiTearing)
{
    uchar ucReturn;
    
    ucCM_InsBuff[0] = 0xb4;
    if (ucAntiTearing)
        ucCM_InsBuff[1] = 0x0b;
    else               
        ucCM_InsBuff[1] = 0x03;
    ucCM_InsBuff[2] = ucZoneNumber;
    ucCM_InsBuff[3] = 0x00;

    cm_GPAGen(ucZoneNumber);
    
    if ((ucReturn = CM_LOW_LEVEL.SendCommand(ucCM_InsBuff))!= SUCCESS) {
        debug("SendCommand failed \n");
        return ucReturn;
    }    
    
    // 保存全局变量
    ucCM_UserZone = ucZoneNumber;
    ucCM_AntiTearing = ucAntiTearing;
    debug("%s ok\n", __func__);    


    return  SUCCESS;
}



// 熔断熔丝
uchar cm_BurnFuse(uchar ucFuze)
{
    uchar ucReturn;
    uchar ucCmdWrFuze[4] = {0xb4, 0x01, 0x00, 0x00}; 

    ucCmdWrFuze[2] = ucFuze;
    if((ucReturn = CM_LOW_LEVEL.SendCommand(ucCmdWrFuze))!= SUCCESS){
        debug("SendCommand failed \n");
        return ucReturn;
    }

    debug("%s ok\n", __func__);    

    return  SUCCESS;
}


// 读配置区
uchar cm_ReadConfigZone(uchar ucCryptoAddr, puchar pucBuffer, uchar ucCount)
{
    uchar ucReturn, ucEncrypt;

    ucCM_InsBuff[0] = 0xb6;
    ucCM_InsBuff[1] = 0x00;
    ucCM_InsBuff[2] = ucCryptoAddr;
    ucCM_InsBuff[3] = ucCount;

    // 参数需要加入多项式中
    cm_GPAcmd2(ucCM_InsBuff);

    // 读操作
    if ((ucReturn = cm_ReadCommand(ucCM_InsBuff, pucBuffer, ucCount)) != SUCCESS){
        debug("cm_ReadCommand failed \n");
        return ucReturn;
    }
    
    // 密码区是加密的，读出来需要解密
    ucEncrypt = ((ucCryptoAddr >=  CM_PSW) && ucCM_Encrypt);

    // 解密
    cm_GPAdecrypt(ucEncrypt, pucBuffer, ucCount); 

    debug("%s ok\n", __func__);    

    return SUCCESS;
}



// 读校验和
uchar cm_ReadChecksum(puchar pucChkSum)
{
    uchar ucDCR[1];
    uchar ucReturn;
    uchar ucCmdRdChk[4] = {0xb6, 0x02, 0x00, 0x02};

    cm_GPAGenN(20);
      
    // 读操作             
    if((ucReturn = cm_ReadCommand(ucCmdRdChk, pucChkSum, 2))!= SUCCESS){ 
        return ucReturn;
    }
    
    // 检查是否限制读校验和
    if ((ucReturn = cm_ReadConfigZone(DCR_ADDR, ucDCR, 1)) != SUCCESS){
        return ucReturn;
    }

    if ((ucDCR[0] & DCR_UCR)) {
        cm_ResetCrypto();
        debug("cm_ResetCrypto\n");
    }

    debug("%s ok\n", __func__);    

    return SUCCESS;
}

//读用户空间
//cm_ReadLargeZone 用于读用户空间大于256  Byte 的设备(AT88SC6416C)
//cm_ReadSmallZone 用于读用户空间小于256  Byte 的设备(at88sc0104)
uchar cm_ReadLargeZone(uint uiCryptoAddr, puchar pucBuffer, uchar ucCount)
{
    uchar ucReturn;

    ucCM_InsBuff[0] = 0xb2;
    ucCM_InsBuff[1] = (uchar)(uiCryptoAddr >> 8);
    ucCM_InsBuff[2] = (uchar)uiCryptoAddr;
    ucCM_InsBuff[3] = ucCount;

    //参数加入多项式
    cm_GPAcmd3(ucCM_InsBuff);
    
    //读操作
    if ((ucReturn = cm_ReadCommand(ucCM_InsBuff, pucBuffer, ucCount)) != SUCCESS)
        return ucReturn;
    
    //如果加密的话，需要解密
    cm_GPAdecrypt(ucCM_Encrypt, pucBuffer, ucCount); 

    debug("%s ok\n", __func__);    
    return SUCCESS;
}


uchar cm_ReadSmallZone(uchar ucCryptoAddr, puchar pucBuffer, uchar ucCount)
{
    uchar ucReturn;

    ucCM_InsBuff[0] = 0xb2;
    ucCM_InsBuff[1] = 0;
    ucCM_InsBuff[2] = ucCryptoAddr;
    ucCM_InsBuff[3] = ucCount;

    //参数加入多项式
    cm_GPAcmd2(ucCM_InsBuff);

    //读操作
    if ((ucReturn = cm_ReadCommand(ucCM_InsBuff, pucBuffer, ucCount)) != SUCCESS) {
        debug("cm_ReadCommand           failed%d\n", ucReturn);
        return ucReturn;
    }

    debug(" ucCM_Encrypt = %d\n ",ucCM_Encrypt); 
    //如果加密的话，需要解密
    cm_GPAdecrypt(ucCM_Encrypt, pucBuffer, ucCount); 

    debug("%s ok\n", __func__);    

    return SUCCESS;
}


//写用户空间
//cm_WriteLargeZone 用于写用户空间大于256  Byte 的设备(AT88SC6416C)
//cm_WriteSmallZone 用于写用户空间小于256  Byte 的设备(at88sc0104)
char cm_WriteLargeZone(uint uiCryptoAddr, puchar pucBuffer, uchar ucCount)
{
    uchar ucReturn;

    ucCM_InsBuff[0] = 0xb0;
    ucCM_InsBuff[1] = (uchar)(uiCryptoAddr>>8);
    ucCM_InsBuff[2] = (uchar)uiCryptoAddr;
    ucCM_InsBuff[3] = ucCount;

    //参数加入多项式
    cm_GPAcmd3(ucCM_InsBuff);
    
    //如果加密的话，需要对数据加密
    cm_GPAencrypt(ucCM_Encrypt, pucBuffer, ucCount); 

    ucReturn = cm_WriteCommand(ucCM_InsBuff, pucBuffer, ucCount);

    // 如果使用 anti-tearing, 需要等待 >= 20ms 
    if (ucCM_AntiTearing) 
        CM_LOW_LEVEL.WaitClock(10);

    debug("%s ok\n", __func__);    
    return ucReturn;
}

uchar cm_WriteSmallZone(uchar  ucCryptoAddr, puchar pucBuffer, uchar ucCount)
{
    uchar ucReturn;
    
    ucCM_InsBuff[0] = 0xb0;
    ucCM_InsBuff[1] = 0x00;
    ucCM_InsBuff[2] = ucCryptoAddr;
    ucCM_InsBuff[3] = ucCount;

    //参数加入多项式
    cm_GPAcmd2(ucCM_InsBuff);

    debug("ucCryptoAddr = %02x  ucCount = %02x  ucCM_Encrypt = %d\n", ucCryptoAddr, ucCount, ucCM_Encrypt);
    
    //如果加密的话，需要对数据加密
    cm_GPAencrypt(ucCM_Encrypt, pucBuffer, ucCount); 

    // 写数据
    ucReturn = cm_WriteCommand(ucCM_InsBuff, pucBuffer,ucCount);
    debug("ucReturn = %02x\n",ucReturn);

    // 如果使用 anti-tearing, 需要等待 >= 20ms 
    if (ucCM_AntiTearing) 
        CM_LOW_LEVEL.WaitClock(10);

    debug("%s ok\n", __func__);    
    return ucReturn;
}


// 读熔断位
uchar cm_ReadFuse(puchar pucFuze)
{
    uchar ucReturn;
    uchar ucCmdRdFuze[4] = {0xb6, 0x01, 0x00, 0x01};

    cm_GPAGenNF(11, 0x01);

    if((ucReturn = cm_ReadCommand(ucCmdRdFuze,pucFuze,1)) != SUCCESS) {
        return ucReturn;
    }
    
    cm_GPAGen(*pucFuze);
    cm_GPAGenN(5); 

    debug("%s ok\n", __func__);    
    return SUCCESS;
    
}


// 认证安全码
uchar verify_secure_passwd(uchar *passwd)
{
    uchar cmd[4], pwd[3];
    uchar ucReturn;
    cmd[0]=0xBA;
    cmd[1]=0x07;
    cmd[2]=0x00;
    cmd[3]=0x03;
    pwd[0]=passwd[0];
    pwd[1]=passwd[1];
    pwd[2]=passwd[2];
    
    ucReturn = cm_WriteCommand(cmd, pwd, 3);
     
    CM_LOW_LEVEL.WaitClock(3);
   
    // 读取PAC
    if (ucReturn == SUCCESS) {
        ucReturn = cm_ReadConfigZone(0xE8, pwd, 1);
        if (pwd[0]!= 0xFF) {
            debug("PAC != 0xff\n");
            ucReturn = FAILED;
        }
    }

    debug("%s ok\n", __func__);    
    return ucReturn;

}


// 认证密码
uchar cm_VerifyPassword(puchar pucPassword, uchar ucSet, uchar ucRW)
{
    uchar i, j;
    uchar ucReturn;
    uchar ucAddr;
    uchar ucCmdPassword[4] = {0xba, 0x00, 0x00, 0x03};
    uchar ucPSW[3];
    
    // 组织命令和密码域
    ucAddr = CM_PSW + (ucSet << 3);
    ucCmdPassword[1] = ucSet;
    if (ucRW != CM_PWWRITE) {
        ucCmdPassword[1] |= 0x10;
        ucAddr += 4;
    }
      
    // 处理加密
    for (j = 0; j<3; j++) {
        if(ucCM_Authenticate) {
            debug("ucCM_Authenticate is true\n");
            for(i = 0; i < 5; i++) 
                cm_GPAGen(pucPassword[j]);
                ucPSW[j] = Gpa_byte;
        }else{
        // 不使用加密
            ucPSW[j] = pucPassword[j];
        }
    }
      
    // 发起认证
    ucReturn = cm_WriteCommand(ucCmdPassword, ucPSW, 3);
     
     // 等待片刻
     CM_LOW_LEVEL.WaitClock(3);
   
    // 读取PAC
    if (ucReturn == SUCCESS) {
        ucReturn = cm_ReadConfigZone(ucAddr, ucPSW, 1);
        if (ucPSW[0]!= 0xFF) {
            debug("ucAddr = %x   ucPSW[0] = %x \n", ucAddr, ucPSW[0]);
            debug("PAC != 0xff\n");
            ucReturn = FAILED;
        }
    }

    if (ucCM_Authenticate && (ucReturn != SUCCESS)){
        cm_ResetCrypto();
        debug("cm_ResetCrypto          failed\n");
    }

    debug("%s ok\n", __func__);    
    return ucReturn;
}


// 写配置区
uchar cm_WriteConfigZone(uchar ucCryptoAddr, puchar pucBuffer, uchar ucCount, uchar ucAntiTearing)
{
    uchar ucReturn, ucEncrypt;

    ucCM_InsBuff[0] = 0xb4;
    if(ucAntiTearing) 
        ucCM_InsBuff[1] = 0x08;
    else              
        ucCM_InsBuff[1] = 0x00;

    ucCM_InsBuff[2] = ucCryptoAddr;
    ucCM_InsBuff[3] = ucCount;

    //参数加入多项式中
    cm_GPAcmd2(ucCM_InsBuff);
    
    // 密码区是加密的
    ucEncrypt = ((ucCryptoAddr>= CM_PSW) && ucCM_Encrypt);

    //加密数据
    cm_GPAencrypt(ucEncrypt, pucBuffer, ucCount); 

    // 写操作
    ucReturn = cm_WriteCommand(ucCM_InsBuff, pucBuffer,ucCount);

    // 如果使用 anti-tearing, 需要等待 >= 20ms 
    if (ucAntiTearing) 
        CM_LOW_LEVEL.WaitClock(10);

    debug("%s ok\n", __func__);    
    return ucReturn;
}


// 发送校验和
uchar cm_SendChecksum(puchar pucChkSum)
{
    uchar ucReturn;
    uchar ucChkSum[2];
    uchar ucCmdWrChk[4] = {0xb4, 0x02, 0x00, 0x02};
    // 获取校验和
    if(pucChkSum == NULL) {
        cm_CalChecksum(ucChkSum);
    }else {
       ucChkSum[0] = *pucChkSum++; 
       ucChkSum[1] = *pucChkSum; 
    } 
    
    // 发送
    ucReturn = cm_WriteCommand(ucCmdWrChk, ucChkSum, 2);

    //等待片刻
    CM_LOW_LEVEL.WaitClock(5);

    debug("%s ok\n", __func__);    
    return ucReturn;
}




// 灭活认证
uchar cm_DeactiveSecurity(void)
{
    uchar ucReturn;
     
    if ((ucReturn = CM_LOW_LEVEL.SendCmdByte(0xb8)) != SUCCESS) 
        return ucReturn;
    cm_ResetCrypto();

    debug("%s ok\n", __func__);    

    return SUCCESS;
}




/****************************************************************************
                                             CryptoMemory 底层接口                                                                                               
****************************************************************************/

// 发送一个字节命令
uchar cm_SendCmdByte(uchar ucCommand)
{
    uchar i, ucCmd;
    
    i = 100;

    ucCmd = (ucCommand & 0x0F) | 0xb0;
    while (i) {
      cm_Start();
        if (cm_Write(ucCmd) == 0) 
            break;
        if (--i == 0)
            return FAIL_CMDSTART;
    }

    debug("%s ok\n", __func__);    

    return SUCCESS;
}


/************************************************************************

*************************************************************************/

void cm_Delay(uchar ucDelay)
{
    udelay(ucDelay);
}

void cm_PowerOn(void)   
{
    cm_ResetCrypto();
    ucCM_UserZone = ucCM_AntiTearing = 0;
    
    //初始化总线
    CM_DATA_OUT;
    CM_CLK_OUT;
    CM_CLK_LO;
    CM_DATA_HI; 
    cm_ClockCycles(CM_PWRON_CLKS);            // 给一定个数的时钟初始化总线
}


void cm_PowerOff(void)
{
    cm_Delay(1);
    CM_CLK_LO;
    cm_Delay(6);
}



// Reset Password
uchar cm_ResetPassword(void)
{
       return CM_LOW_LEVEL.SendCmdByte(0xba);
}


// Low quality random number generator
void cm_RandGen(puchar pucRanddat)
{
    debug("%s\n", __func__);
    get_random_bytes(pucRanddat, 8);
}



/***************************************************************************
                                                   算法相关的函数                                                                                         
****************************************************************************/


// 复位算法相关的变量
void cm_ResetCrypto(void)
{
    uchar i;

    for (i = 0; i < Gpa_Regs; ++i) 
        ucGpaRegisters[i] = 0;
    ucCM_Encrypt = ucCM_Authenticate = FALSE;
}

// Generate next value
uchar cm_GPAGen(uchar Datain)
{
    uchar Din_gpa;
    uchar Ri, Si, Ti;
    uchar R_sum, S_sum, T_sum;
    
    // Input Character
    Din_gpa = Datain^Gpa_byte;
    Ri = Din_gpa & 0x1f;                              //Ri[4:0] = Din_gpa[4:0]
    Si = ((Din_gpa << 3) & 0x78)|((Din_gpa >> 5) & 0x07);   //Si[6:0] = {Din_gpa[3:0], Din_gpa[7:5]}
    Ti = (Din_gpa >> 3) & 0x1f;                         //Ti[4:0] = Din_gpa[7:3];
       
    //R polynomial
    R_sum = cm_Mod(RD, cm_RotR(RG), CM_MOD_R);
    RG = RF;
    RF = RE;
    RE = RD;
    RD = RC ^ Ri;
    RC = RB;
    RB = RA;
    RA = R_sum;
    
    //S ploynomial
    S_sum = cm_Mod(SF, cm_RotS(SG), CM_MOD_S);
    SG = SF;
    SF = SE ^ Si;
    SE = SD;
    SD = SC;
    SC = SB;
    SB = SA;
    SA = S_sum;
        
    //T polynomial
    T_sum = cm_Mod(TE,TC,CM_MOD_T);
    TE = TD;
    TD = TC;
    TC = TB ^ Ti;
    TB = TA;
    TA = T_sum;

    // Output Stage
    Gpa_byte =(Gpa_byte << 4) & 0xF0;                                  // shift gpa_byte left by 4
    Gpa_byte |= ((((RA ^ RE) & 0x1F) & (~SA)) | (((TA ^ TD) & 0x1F) & SA)) & 0x0F; // concat 4 prev bits and 4 new bits
    return Gpa_byte;
}

// Do authenticate/encrypt chalange encryption
void cm_AuthenEncryptCal(uchar *Ci, uchar *G_Sk, uchar *Q, uchar *Ch)
{   
    uchar i, j;

    // Reset all registers
    for (i = 0; i < Gpa_Regs; ++i) 
        ucGpaRegisters[i] = 0;
    
    // Setup the cyptographic registers
    for(j = 0; j < 4; j++) {
        for(i = 0; i < 3; i++) 
            cm_GPAGen(Ci[2 * j]);    
        for(i = 0; i < 3; i++) 
            cm_GPAGen(Ci[2 * j + 1]);
        cm_GPAGen(Q[j]);
    }
    
    for(j = 0; j<4; j++ ) {
        for(i = 0; i < 3; i++) 
            cm_GPAGen(G_Sk[2 * j]);
        for(i = 0; i < 3; i++) 
            cm_GPAGen(G_Sk[2 * j + 1]);
        cm_GPAGen(Q[j + 4]);
    }
    
    // begin to generate Ch
    cm_GPAGenN(6);                    // 6 0x00s
    Ch[0] = Gpa_byte;

    for (j = 1; j < 8; j++) {
        cm_GPAGenN(7);                // 7 0x00s
        Ch[j] = Gpa_byte;
    }
    
    // then calculate new Ci and Sk, to compare with the new Ci and Sk read from eeprom
    Ci[0] = 0xff;                     // reset AAC 
    for(j = 1; j < 8; j++) {
        cm_GPAGenN(2);                // 2 0x00s
        Ci[j] = Gpa_byte;
    }

    for(j = 0; j < 8; j++) {
        cm_GPAGenN(2);                // 2 0x00s
         G_Sk[j] = Gpa_byte;
    }
   
    cm_GPAGenN(3);                    // 3 0x00s
}

// Calaculate Checksum
void cm_CalChecksum(uchar *Ck_sum)
{
    cm_GPAGenN(15);                    // 15 0x00s
    Ck_sum[0] = Gpa_byte;
    cm_GPAGenN(5);                     // 5 0x00s
    Ck_sum[1] = Gpa_byte;   
}


// Clock some zeros into the state machine
void cm_GPAGenN(uchar Count)
{
    while(Count--)
        cm_GPAGen(0x00);
}

// Clock some zeros into the state machine, then clock in a byte of data
void cm_GPAGenNF(uchar Count, uchar DataIn)
{
    cm_GPAGenN(Count);                             // First ones are allways zeros
    cm_GPAGen(DataIn);                             // Final one is sometimes different
}

// Include 2 bytes of a command into a polynominal
void cm_GPAcmd2(puchar pucInsBuff)
{
      cm_GPAGenNF(5, pucInsBuff[2]);
      cm_GPAGenNF(5, pucInsBuff[3]);
}
    
// Include 3 bytes of a command into a polynominal
void cm_GPAcmd3(puchar pucInsBuff)
{
      cm_GPAGenNF(5, pucInsBuff[1]);
      cm_GPAcmd2(pucInsBuff);
}
    
// Include the data in the polynominals and decrypt it required
void cm_GPAdecrypt(uchar ucEncrypt, puchar pucBuffer, uchar ucCount)
{
      uchar i;
       
      for (i = 0; i < ucCount; ++i) {
          if (ucEncrypt) 
                pucBuffer[i] = pucBuffer[i] ^ Gpa_byte;
          cm_GPAGen(pucBuffer[i]);
          cm_GPAGenN(5);        // 5 clocks with 0x00 data
    }
}

// Include the data in the polynominals and encrypt it required
void cm_GPAencrypt(uchar ucEncrypt, puchar pucBuffer, uchar ucCount)
{
    uchar i, ucData; 

    for (i = 0; i<ucCount; i++) {
        cm_GPAGenN(5);                          // 5 0x00s
        ucData = pucBuffer[i];
        if (ucEncrypt) 
            pucBuffer[i] = pucBuffer[i] ^ Gpa_byte;
        cm_GPAGen(ucData);
    }
}



/***************************************************************************
                                              字符驱动模型                                                                                                  
*****************************************************************************/

static int at88_open(struct inode *inode,struct file *filp)
{    
    cm_PowerOn();       
    return 0;
}
static int at88_release(struct inode *inode,struct file *filp)
{
    cm_PowerOff();
    return 0;
}

static ssize_t at88_read (struct file *filp, char *buf, size_t count, loff_t *f_pos)
{
    return 0;
}

static ssize_t at88_write (struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
    return 0;
}


struct ioctl_data {
    uchar common1;
    uchar common2;
    uchar write_buffer1[8];
    uchar write_buffer2[8];
    uchar read_buffer[16];
    uchar buffer_len;
};

static long at88_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
    struct ioctl_data data;
    int ret = -1;

    if((void *)arg != NULL){
        if(copy_from_user(&data, (struct ioctl_data *)arg, sizeof(struct ioctl_data))){
            return -EFAULT;
        }
    }
    
    if(_IOC_TYPE(cmd) != AT88SC_CMD_MAGIC) 
        return - EINVAL;

    if(_IOC_NR(cmd) > AT88SC_CMD_MAX_NR) 
        return - EINVAL;

    switch(cmd){
    case COMMUNICATION_TEST:
        ret = cm_aCommunicationTest();
        debug("ret = %d\n", ret);
        break;
    case AUTHENTICATION:
            ret = cm_ActiveSecurity(data.common1, data.write_buffer1, NULL, data.common2);// NULL 表示由本驱动提供随机数
        break;
    case VERIFY_WRITE_PASSWORD:
         debug("%02x%02x%02x\n", data.write_buffer1[0], data.write_buffer1[1], data.write_buffer1[2]);
        ret =  cm_VerifyPassword( data.write_buffer1, data.common1, data.common2);
        break;
    case SET_USER_ZONE:
        ret = cm_SetUserZone(data.common1, data.common2);
        break;
    case READ_USER_ZONE:
        debug("READ_USER_ZONE %02x  %02x\n", data.common1,  data.buffer_len);
        ret = cm_ReadSmallZone(data.common1, data.read_buffer, data.buffer_len);
        debug("RET = %d\n", ret);
        if(ret == SUCCESS){
            if(copy_to_user((struct ioctl_data *)arg, &data, sizeof(struct ioctl_data))){
                return -EFAULT;
            }
        }
        break;
    case WRITE_USER_ZONE:
        debug("WRITE_USER_ZONE data.common1 = %02x data.buffer_len = %02x\n",data.common1, data.buffer_len);
        ret = cm_WriteSmallZone(data.common1, data.write_buffer1, data.buffer_len);
        break;
    case WRITE_CONFIG_ZONE:
        ret = cm_WriteConfigZone(data.common1, data.write_buffer1, data.buffer_len, data.common2);
        break;
    case READ_CONFIG_ZONE:
        ret = cm_ReadConfigZone(data.common1, data.read_buffer, data.buffer_len);
        if(ret == SUCCESS){
             if(copy_to_user((struct ioctl_data *)arg, &data, sizeof(struct ioctl_data))){
                return -EFAULT;
             }
        }
        break;
    case SEND_CHECKSUM:
        if((void *)arg == NULL){
            //debug("ret = cm_SendChecksum(NULL);");
            ret = cm_SendChecksum(NULL);
        }else{
            ret = cm_SendChecksum(data.write_buffer1);
        }
        break;
    case READ_CHECKSUM:
        ret = cm_ReadChecksum(data.read_buffer);
        if(ret == SUCCESS){
            if(copy_to_user((struct ioctl_data *)arg, &data, sizeof(struct ioctl_data))){
                return -EFAULT;
            }
        }
        break;
    case READ_FUSE_BYTE:
        ret = cm_ReadFuse(data.read_buffer);
        if(ret == SUCCESS){
            if(copy_to_user((struct ioctl_data *)arg, &data, sizeof(struct ioctl_data))){
                return -EFAULT;
            }
        }
        break;
    case BURN_FUSE:
        ret = cm_BurnFuse(data.common1);
        break;
    case VERIFY_SC_PASSWD:
        ret = verify_secure_passwd(data.write_buffer1);
        break;
    case DEACTIVESECURITY:
        ret = cm_DeactiveSecurity();
        break;
    }
    return ret;
}

static struct file_operations at88_fops = {
    .open       = at88_open,
    .release    = at88_release, 
    .read       = at88_read,
    .write      = at88_write,
    .unlocked_ioctl     = at88_ioctl,
};


static int __init davinci_at88_init(void)
{
    int res;

    /* Register the character device (atleast try) */
    debug("davinci Crypto module init. \n");
    at88sc = kmalloc(sizeof(struct at88sc_t), GFP_KERNEL);
    if(at88sc == NULL){
        return -1;
    }

    at88sc->name = "at88sc";
    at88sc->pin_scl = 228;          //PH04
    at88sc->pin_sda = 229;          //PH05
    
    if (major) {
        devid = MKDEV(major, 0);
        register_chrdev_region(devid, 1, at88sc->name);  
    } else {
        alloc_chrdev_region(&devid, 0, 1, at88sc->name); 
        major = MAJOR(devid);                     
    }

    cdev_init(&at88sc->at88sc_cdev, &at88_fops);
    cdev_add(&at88sc->at88sc_cdev, devid, 1);

    cls = class_create(THIS_MODULE, at88sc->name);
    device_create(cls, NULL, devid, NULL, at88sc->name);    /* /dev/at88sc */

    /*Request GPIO*/
    res = gpio_request(at88sc->pin_scl,"AT88SC_SCL");
    if(res){
        debug("Cannot request gpio. err = %d\n",res);
        goto out;
    }

    res = gpio_request(at88sc->pin_sda,"AT88SC_SDA");
    if(res){
        debug("Cannot request gpio. err = %d\n",res);
        goto out;
    }

    return 0;
out:
    
    device_destroy(cls, devid);
    class_destroy(cls);

    cdev_del(&at88sc->at88sc_cdev);
    unregister_chrdev_region(devid, 1);
    return -1;


}
 
static void __exit davinci_at88_exit(void)
{
    device_destroy(cls, devid);
    class_destroy(cls);

    cdev_del(&at88sc->at88sc_cdev);
    unregister_chrdev_region(devid, 1);

    gpio_free(at88sc->pin_scl);
    gpio_free(at88sc->pin_sda);

    
    kfree(at88sc);

    debug("davinci at88 release success.\n");
}

module_init(davinci_at88_init);
module_exit(davinci_at88_exit);


MODULE_AUTHOR ("www.gzseeing.com");
MODULE_DESCRIPTION("Crypto chip driver for linux");
MODULE_LICENSE("GPL v2");
