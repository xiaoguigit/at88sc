#include "at88sc0104.h"

#define CM_MAJOR    205
static int major;
static dev_t devid;
static struct class *cls;

#define baseaddr    ( (unsigned char)0x01c40000)

// -------------------------------------------------------------------------------------------------
// Data
// -------------------------------------------------------------------------------------------------

uchar ucCM_DevGpaRegisters[16][Gpa_Regs];
uchar ucCM_DevEncrypt[16];
uchar ucCM_DevAuthenticate[16];
uchar ucCM_DevUserZone[16];
uchar ucCM_DevAntiTearing[16];

// Data Structures that configure the low level CryptoMemory functions

// CryptoMemory Low Level Linkage
// 
cm_low_level CM_LOW_LEVEL = {
    cm_TRUE,                // Carddetect
    cm_PowerOff,        // PowerOff
    cm_PowerOn,         // PowerOn
    cm_SendCommand,  // SendCommand
    cm_ReceiveData,     // ReceiveRet
    cm_SendData,        // SendData
    cm_RandGen,         // RandomGen
    cm_WaitClock,       // WaitClock
    cm_SendCmdByte      // SendCmdByte
};

// CryptoMemory Low Level Configuration
//
// Note: the port address is included in a manner that does not require a chip
//       specific header file. Note, the address of the port is the LAST address
//       of the group of three addresses of the port (the port output register).
//

cm_port_cfg  CM_PORT_CFG = {
    0xb0, // ucChipSelect        (0xb0 is default address for CryptoMemory)
    baseaddr, // ucClockPort         (0x32 is PORTD)
    10,    // ucClockPin          (SCL on bit 0)
    baseaddr, // ucDataPort          (0x32 is PORTD)
    11,    // ucDataPin           (SDA on bit 2)    
    baseaddr, // ucCardSensePort     (0x32 is PORTD)
    10,    // ucCardSensePin      (card sense switch, if any, on bit 2) 
    TRUE, // ucCardSensePolarity (TRUE -> "1" on bit in register means card is inserted)
    baseaddr, // ucPowerPort         (0x32 is PORTD)
    11,    // ucPowerPin          (power control, if any, on bit 3)
    TRUE, // ucPowerPolarity     (TRUE -> "1" on bit in register supplies power)
    100,  // ucDelayCount
    100    // ucStartTries
};

// -------------------------------------------------------------------------------------------------
// Functions
// -------------------------------------------------------------------------------------------------

// Function return TRUE
//

uchar cm_TRUE(void)
{
    return TRUE;
}


// Local function prototypes
static uchar cm_AuthenEncrypt(uchar ucCmd1, uchar ucAddrCi, puchar pucCi, puchar pucG_Sk, puchar pucRandom);

// Global Data
uchar ucCM_Ci[8], ucCM_G_Sk[8];
uchar ucCM_Q_Ch[16], ucCM_Ci2[8];

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

    debug("ucKeySet = 0x%x\n", ucKeySet);
    debug("ucEncrypt = 0x%x\n", ucEncrypt);
    
    // Read Ci for selected key set
    ucAddrCi = CM_Ci + (ucKeySet << 4);              // Ci blocks on 16 byte boundries
    if ((ucReturn = cm_ReadConfigZone(ucAddrCi, ucCM_Ci, 8)) != SUCCESS) 
        return ucReturn;

    
    // Try to activate authentication
    for (i = 0; i < 8; ++i) 
        ucCM_G_Sk[i] = pucKey[i];

    if ((ucReturn = cm_AuthenEncrypt(ucKeySet, ucAddrCi, ucCM_Ci, ucCM_G_Sk, pucRandom)) != SUCCESS) {
        debug("cm_AuthenEncrypt failed\n");
        return ucReturn;
    }
    ucCM_Authenticate = TRUE;
        
    // If Encryption required, try to activate that too
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

    debug("cm_ActiveSecurity successful \n");
    // Done
    return SUCCESS;
}

// Common code for both activating authentication and encryption
static uchar cm_AuthenEncrypt(uchar ucCmd1, uchar ucAddrCi, puchar pucCi, puchar pucG_Sk, puchar pucRandom)
{
    uchar i;
    uchar ucReturn;
    
    // Generate challange data
    if (pucRandom) {
        for (i = 0; i < 8; ++i) {
            ucCM_Q_Ch[i] = pucRandom[i];
        } 
    }else{      
        CM_LOW_LEVEL.RandomGen(ucCM_Q_Ch);
    }
    debug("Random:\n");
    for(i = 0; i < 8; i++){
        debug("%02x ", ucCM_Q_Ch[i]);
    }
    debug("\n");

    //for (i = 0; i < 8; ++i) ucCM_Q_Ch[i] = pucRandom[i];
    cm_AuthenEncryptCal(pucCi, pucG_Sk, ucCM_Q_Ch, &ucCM_Q_Ch[8]);
    
    // Send chalange
    ucCM_InsBuff[0] = 0xb8;
    ucCM_InsBuff[1] = ucCmd1;
    ucCM_InsBuff[2] = 0x00;
    ucCM_InsBuff[3] = 0x10;
    if ((ucReturn = cm_WriteCommand(ucCM_InsBuff, ucCM_Q_Ch, 16)) != SUCCESS) {
        debug("cm_WriteCommand failed\n");
        return ucReturn;
    }   
    
    // Give chips some clocks to do calculations
    CM_LOW_LEVEL.WaitClock(3);
                             
    // Verify result
    if ((ucReturn = cm_ReadConfigZone(ucAddrCi, ucCM_Ci2, 8)) != SUCCESS) {
        debug("cm_ReadConfigZone failed\n");
        return ucReturn;
    }
    
    for(i=0; i<8; i++) {
        if (pucCi[i] != ucCM_Ci2[i]) {
            debug("authentication  failed\n");
            return FAILED;
        }
    }

    debug("cm_AuthenEncrypt successful \n");

    // Done
    return SUCCESS;
}

uchar cm_aCommunicationTest(void)
{
    uchar write_data[2] = {0x55, 0xaa};
    uchar read_data[2];
    cm_WriteConfigZone(0xa, write_data, 2, FALSE);
    cm_ReadConfigZone(0xa, read_data, 2);
    if(memcmp(write_data, read_data, 2) != 0){
        return FAILED;
    }
    return SUCCESS;
}

 // 1/2 Clock Cycle transition to HIGH
//
void cm_Clockhigh(void)
{
    cm_Delay(1);
    CM_CLK_HI;
    cm_Delay(1);
}

// 1/2 Clock Cycle transition to LOW
//
void cm_Clocklow(void)
{
    cm_Delay(1);
    CM_CLK_LO;
    cm_Delay(1);
}

// Do one full clock cycle
//
// Changed 1/19/05 to eliminate one level of return stack requirements
//
void cm_ClockCycle(void)
{
    cm_Delay(1);
    CM_CLK_LO;
    cm_Delay(2);
    CM_CLK_HI;
    cm_Delay(1);
}

// Do a number of clock cycles
//
void cm_ClockCycles(uchar ucCount)
{
    uchar i;
    for (i = 0; i < ucCount; ++i) {
        cm_ClockCycle();
    }
}

// Send a start sequence
//
// Modified 7-21-04 to correctly set SDA to be an output
// 
void cm_Start(void)
{
    CM_DATA_OUT;                         // Data line must be an output to send a start sequence
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

// Send a stop sequence
//
// Modified 7-21-04 to correctly set SDA to be an output
// 
void cm_Stop(void)
{
    CM_DATA_OUT;                         // Data line must be an output to send a stop sequence
    cm_Clocklow();
    CM_DATA_LO;
    cm_Delay(4);
    cm_Clockhigh();
    cm_Delay(8);
    CM_DATA_HI;
    cm_Delay(4);
}

// Write a byte
//
// Returns 0 if write successed, 1 if write fails failure
//
// Modified 7-21-04 to correctly control SDA
// 
uchar cm_Write(uchar ucData)
{
    uchar i;

    CM_DATA_OUT;                         // Set data line to be an output
    for(i=0; i<8; i++) {                 // Send 8 bits of data
        cm_Clocklow();
        if (ucData&0x80) 
            CM_DATA_HI;
        else             
            CM_DATA_LO;
        cm_Clockhigh();
        ucData = ucData<<1;
    }
    cm_Clocklow();

    // wait for the ack
    CM_DATA_IN;                      // Set data line to be an input
    cm_Delay(8);
    cm_Clockhigh();
    
    while(i > 1) {                    // loop waiting for ack (loop above left i == 8)
        cm_Delay(2);
        if (CM_DATA_RD)
            i--;        // if SDA is high level decrement retry counter
        else 
            i = 0;
    }      
    cm_Clocklow();
    CM_DATA_OUT;                     // Set data line to be an output

    
    return i;
}

// Send a ACK or NAK or to the device
void cm_AckNak(uchar ucAck)
{
    CM_DATA_OUT;                         // Data line must be an output to send an ACK
    cm_Clocklow();
    if (ucAck) 
        CM_DATA_LO;               // Low on data line indicates an ACK
    else       
        CM_DATA_HI;               // High on data line indicates an NACK
    cm_Delay(2);
    cm_Clockhigh();
    cm_Delay(8);
    cm_Clocklow();
}

#ifdef PIGS_FLY

// ------------------------------------------------------------------------------------- 
// Original Version
// ------------------------------------------------------------------------------------- 

// Send a ACK to the device
void cm_Ack(void)
{
    CM_DATA_OUT;                         // Data line must be an output to send an ACK
    cm_Clocklow();
    CM_DATA_LO;                          // Low on data line indicates an ACK
    cm_Delay(2);
    cm_Clockhigh();
    cm_Delay(8);
    cm_Clocklow();
    //SET_SDA;
}

// Send a NACK to the device
void cm_N_Ack(void)
{
    CM_DATA_OUT;                         // Data line must be an output to send an NACK
    cm_Clocklow();
    CM_DATA_HI;                          // High on data line indicates an NACK
    cm_Delay(2);
    cm_Clockhigh();
    cm_Delay(8);
    cm_Clocklow();
    //SET_SDA;
}

// ------------------------------------------------------------------------------------- 
// Version that uses one less level of call stack
// ------------------------------------------------------------------------------------- 

// Send a ACK to the device
void cm_Ack(void)
{
    CM_DATA_OUT;                         // Data line must be an output to send an ACK
    cm_Delay(1);
    CM_CLK_LO;
    cm_Delay(1);
    CM_DATA_LO;                          // Low on data line indicates an ACK
    cm_Delay(3);
    CM_CLK_HI;
    cm_Delay(9);
    cm_Clocklow();
}

// Send a NACK to the device
void cm_N_Ack(void)
{
    CM_DATA_OUT;                         // Data line must be an output to send an NACK
    cm_Delay(1);
    CM_CLK_LO;
    cm_Delay(1);
    CM_DATA_HI;                          // High on data line indicates an NACK
    cm_Delay(2);
    CM_CLK_HI;
    cm_Delay(9);
    cm_Clocklow();
}
#endif

//     Read a byte from device, MSB
//
// Modified 7-21-04 to correctly control SDA
// 
uchar cm_Read(void)
{
    uchar i;
    uchar rByte = 0;
    
    CM_DATA_IN;                          // Set data line to be an input
    CM_DATA_HI;
    for(i=0x80; i; i=i>>1)
    {
        cm_ClockCycle();
        if (CM_DATA_RD) rByte |= i;
        cm_Clocklow();
    }
    CM_DATA_OUT;                         // Set data line to be an output
    return rByte;
}

void cm_WaitClock(uchar loop)
{
    uchar i, j;
    
    CM_DATA_LO;
    for(j=0; j<loop; j++) {
        cm_Start();
        for(i = 0; i<15; i++) 
            cm_ClockCycle();
        cm_Stop();
    }
}

// Send a command
//
uchar cm_SendCommand(puchar pucInsBuff)
{
    uchar i, ucCmd;

    printk("%s \n", __func__);
    
    i = CM_START_TRIES;
    ucCmd = (pucInsBuff[0]&0x0F) | CM_PORT_CFG.ucChipSelect;

    printk("cmd = %02x\n", ucCmd);
    printk("%02x %02x %02x\n", pucInsBuff[1], pucInsBuff[2], pucInsBuff[3]);
        
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
    printk("cm_SendCommand ok\n");
    return SUCCESS;
}

uchar cm_ReceiveData(puchar pucRecBuf, uchar ucLen)
{
    int i;

    for(i = 0; i < (ucLen-1); i++) {
        pucRecBuf[i] = cm_Read();
        cm_AckNak(TRUE);
    }
    pucRecBuf[i] = cm_Read();
    cm_AckNak(FALSE);
    cm_Stop();
    return SUCCESS;
}

uchar cm_SendData(puchar pucSendBuf, uchar ucLen)
{
    int i;
    for(i = 0; i< ucLen; i++) {
        if (cm_Write(pucSendBuf[i])==1) 
            return FAIL_WRDATA;
    }
    cm_Stop();
    
    return SUCCESS;
}

// Set User Zone
uchar cm_SetUserZone(uchar ucZoneNumber, uchar ucAntiTearing)
{
    uchar ucReturn;
    debug("ucZoneNumber = 0x%x\n", ucZoneNumber);
    debug("ucAntiTearing = 0x%x\n", ucAntiTearing);
    
    ucCM_InsBuff[0] = 0xb4;
    if (ucAntiTearing)
        ucCM_InsBuff[1] = 0x0b;
    else               
        ucCM_InsBuff[1] = 0x03;
        ucCM_InsBuff[2] = ucZoneNumber;
    ucCM_InsBuff[3] = 0x00;

    // Only zone number is included in the polynomial
    cm_GPAGen(ucZoneNumber);
    
    if ((ucReturn = CM_LOW_LEVEL.SendCommand(ucCM_InsBuff))!= SUCCESS) {
        debug("SendCommand failed \n");
        return ucReturn;
    }    
    
    // save zone number and anti-tearing state
    ucCM_UserZone = ucZoneNumber;
    ucCM_AntiTearing = ucAntiTearing;

    // done 
    return  SUCCESS;//CM_LOW_LEVEL.ReceiveRet(NULL,0);
}



// Burn Fuse
uchar cm_BurnFuse(uchar ucFuze)
{
    uchar ucReturn;
   uchar ucCmdWrFuze[4] = {0xb4, 0x01, 0x00, 0x00}; 
    // Burn Fuze
    ucCmdWrFuze[2] = ucFuze;
    if((ucReturn = CM_LOW_LEVEL.SendCommand(ucCmdWrFuze))!= SUCCESS){
        debug("SendCommand failed \n");
        return ucReturn;
    }

    // done   
    return  SUCCESS;//CM_LOW_LEVEL.ReceiveRet(NULL,0);
}

uchar cm_CardDetect(void)
{
     CM_DETECT_IN;                                       // Make detect pin an input
     if (CM_DETECT_RD){
        return CM_DETECT_POL?TRUE:FALSE;  // Adjust pin HI for polarity
     }

     return CM_DETECT_POL?FALSE:TRUE;                    // Adjust pin LO for polarity
}

// Functions that directly control the hardware that are not needed in all cases
// Send a command byte
//
uchar cm_SendCmdByte(uchar ucCommand)
{
    uchar i, ucCmd;
    
    i = CM_START_TRIES;

    ucCmd = (ucCommand & 0x0F) | CM_PORT_CFG.ucChipSelect;
    while (i) {
      cm_Start();
        if (cm_Write(ucCmd) == 0) 
            break;
        if (--i == 0)
            return FAIL_CMDSTART;
    }

    return SUCCESS;
}

// Data and Functions used by other low level functions
//
// Note: this module must be after all other low level functions in the library
//       to assure that any reference to functions in this library are satistified.
// Zone Data
uchar ucCM_UserZone;
uchar ucCM_AntiTearing;

// Chip state
uchar ucCM_Encrypt;
uchar ucCM_Authenticate;

// Global data
uchar ucCM_InsBuff[4];

// Delay
void cm_Delay(uchar ucDelay)
{
    udelay(ucDelay);
}

// Functions control the logical power on/off for the chip

// Power On Chip  
//
// Returns 0 (SUCCESS) if no error
//
void cm_PowerOn(void)   
{
    // Reset chip data
    cm_ResetCrypto();
    ucCM_UserZone = ucCM_AntiTearing = 0;
    
    // Sequence for powering on secure memory according to ATMEL spec
    CM_DATA_OUT;                              // SDA and SCL start as outputs
    CM_CLK_OUT;
    CM_CLK_LO;                                // Clock should start LOW
    CM_DATA_HI;                               // Data high during reset
    cm_ClockCycles(CM_PWRON_CLKS);            // Give chip some clocks cycles to get started

    // Chip should now be in sync mode and ready to operate
}

// Shut down secure memory
//
void cm_PowerOff(void)
{
    cm_Delay(1);
    CM_CLK_LO;
    cm_Delay(6);
}
// Functions that directly control the hardware

// Power On Chip  
//
// Returns 0 (SUCCESS) if no error
//
void cm_FullPowerOn(void)   
{
    // Reset chip data
    cm_ResetCrypto();
    ucCM_UserZone = ucCM_AntiTearing = 0;
    
    // Power control
    CM_POWER_OUT;                           // Set power pin to be an output
    
    if (CM_POWER_POL) 
        CM_POWER_LO; 
    else 
        CM_POWER_HI;   // Turn OFF power
        
    CM_DIR_INIT;                              // SDA, SCL both start as outputs
    CM_CLK_LO;                                // Clock should start LOW
    CM_DATA_HI;                               // Data high during reset
    
    if (CM_POWER_POL) 
        CM_POWER_HI; 
    else 
        CM_POWER_LO;   // Turn ON power
        
    cm_Delay(100);                           // Give chip a chance stabilize after power is applied
      
    // Sequence for powering on secure memory according to ATMEL spec
    cm_ClockCycles(CM_PWRON_CLKS);           // Give chip some clocks cycles to get started

    // Chip should now be in sync mode and ready to operate
}

// Shut down secure memory
//
void cm_FullPowerOff(void)
{
    cm_Delay(1);
    CM_CLK_LO;
    cm_Delay(6);
    if (CM_POWER_POL) 
        CM_POWER_LO; 
    else 
        CM_POWER_HI;   // Turn OFF power
}
// Read Configuration Zone
//

// CryptoMemory Library Include Files
// Read Configuration Zone
uchar cm_ReadConfigZone(uchar ucCryptoAddr, puchar pucBuffer, uchar ucCount)
{
    uchar ucReturn, ucEncrypt;
    int i = 0;
    debug("%s\n", __func__);

    debug("ucCryptoAddr = 0x%x\n", ucCryptoAddr);
    debug("ucCount = 0x%x\n", ucCount);

    ucCM_InsBuff[0] = 0xb6;
    ucCM_InsBuff[1] = 0x00;
    ucCM_InsBuff[2] = ucCryptoAddr;
    ucCM_InsBuff[3] = ucCount;

    // Three bytes of the command must be included in the polynominals
    cm_GPAcmd2(ucCM_InsBuff);


    // Do the read
    if ((ucReturn = cm_ReadCommand(ucCM_InsBuff, pucBuffer, ucCount)) != SUCCESS){
        debug("cm_ReadCommand failed \n");
        return ucReturn;
    }
    
    for(i = 0; i < ucCount; i++){
        debug("%02x ", pucBuffer[i]);        
    }

    // Only password zone is ever encrypted
    ucEncrypt = ((ucCryptoAddr >=  CM_PSW) && ucCM_Encrypt);

    if(ucEncrypt){
        debug("****current is  ucEncrypt****\n");
    }

    // Include the data in the polynominals and decrypt if required
    cm_GPAdecrypt(ucEncrypt, pucBuffer, ucCount); 


    debug("*************************\n");
    for(i = 0; i < ucCount; i++){
        debug("%02x ", pucBuffer[i]);        
    }

    // Done
    return SUCCESS;
}

// Read Checksum
//

// CryptoMemory Library Include Files

uchar   ucCmdRdChk[4] = {0xb6, 0x02, 0x00, 0x02};

// Read Checksum
uchar cm_ReadChecksum(puchar pucChkSum)
{
    uchar ucDCR[1];
    uchar ucReturn;
    debug("%s\n", __func__);

    // 20 0x00s (10 0x00s, ignore first byte, 5 0x00s, ignore second byte, 5 0x00s  
    cm_GPAGenN(20);
      
    // Read the checksum                  
    if((ucReturn = cm_ReadCommand(ucCmdRdChk, pucChkSum, 2))!= SUCCESS){ 
        return ucReturn;
    }
    
    // Check if unlimited reads allowed
    if ((ucReturn = cm_ReadConfigZone(DCR_ADDR, ucDCR, 1)) != SUCCESS){
        return ucReturn;
    }

    
    if ((ucDCR[0] & DCR_UCR)) 
        cm_ResetCrypto();
    
    return SUCCESS;
}

// Read Fuze Byte
//
uchar   ucCmdRdFuze[4] = {0xb6, 0x01, 0x00, 0x01};

// Read Fuse Byte
uchar cm_ReadFuse(puchar pucFuze)
{
    uchar ucReturn;
    debug("%s\n", __func__);

    // 5 0x00, A2 (0x00), 5 0x00, N (0x01)    
    cm_GPAGenNF(11, 0x01);

    if((ucReturn = cm_ReadCommand(ucCmdRdFuze,pucFuze,1)) != SUCCESS) {
        return ucReturn;
    }
    
    cm_GPAGen(*pucFuze);         // fuze byte
    cm_GPAGenN(5);               // 5 0x00s
  
    return SUCCESS;
    
}

// Read User Zone
//
// The Read Large User Zone function is used to read data from CryptoMemory devices
// that have greater than 256 bytes in each user zone (AT88SC6416C, and larger)

// Read User Zone
uchar cm_ReadLargeZone(uint uiCryptoAddr, puchar pucBuffer, uchar ucCount)
{
    uchar ucReturn;
    debug("%s\n", __func__);

    ucCM_InsBuff[0] = 0xb2;
    ucCM_InsBuff[1] = (uchar)(uiCryptoAddr >> 8);
    ucCM_InsBuff[2] = (uchar)uiCryptoAddr;
    ucCM_InsBuff[3] = ucCount;

    // Three bytes of the command must be included in the polynominals
    cm_GPAcmd3(ucCM_InsBuff);
    
    // Read the data
    if ((ucReturn = cm_ReadCommand(ucCM_InsBuff, pucBuffer, ucCount)) != SUCCESS)
        return ucReturn;
    
    // Include the data in the polynominals and decrypt if required
    cm_GPAdecrypt(ucCM_Encrypt, pucBuffer, ucCount); 

    return SUCCESS;
}

// Read Small User Zone
//
// The Read Small User Zone function is used to read data from CryptoMemory devices that
// have 256 bytes or less in each user zone (AT88SC3216C, and smaller)

// Read Small User Zone
uchar cm_ReadSmallZone(uchar ucCryptoAddr, puchar pucBuffer, uchar ucCount)
{
    uchar ucReturn;
    int i = 0;
    debug("%s\n", __func__);


    ucCM_InsBuff[0] = 0xb2;
    ucCM_InsBuff[1] = 0;
    ucCM_InsBuff[2] = ucCryptoAddr;
    ucCM_InsBuff[3] = ucCount;


     printk("ucCryptoAddr = %02x  ucCount = %02x\n", ucCryptoAddr, ucCount);

    // Two bytes of the command must be included in the polynominals
    cm_GPAcmd2(ucCM_InsBuff);
     printk("ucCM_InsBuff[2] = %02x  ucCM_InsBuff[3] = %02x\n", ucCM_InsBuff[2], ucCM_InsBuff[3]);


    // Read the data
    if ((ucReturn = cm_ReadCommand(ucCM_InsBuff, pucBuffer, ucCount)) != SUCCESS) {
        debug("cm_ReadCommand failed  %d\n", ucReturn);
        return ucReturn;
    }
    // Include the data in the polynominals and decrypt it required
    cm_GPAdecrypt(ucCM_Encrypt, pucBuffer, ucCount); 

    for(i = 0; i < ucCount; i++){
        debug("pucBuffer[%d] = 0x%02x\n", i, pucBuffer[i]);
    }

    // Done
    return SUCCESS;
}

// Write User Zone
//
// The Write Large User Zone function is used to write data to CryptoMemory devices that have
// greater than 256 bytes in each user zone (AT88SC6416C, and larger).

// Write User Zone
char cm_WriteLargeZone(uint uiCryptoAddr, puchar pucBuffer, uchar ucCount)
{
    uchar ucReturn;
    debug("%s\n", __func__);

    ucCM_InsBuff[0] = 0xb0;
    ucCM_InsBuff[1] = (uchar)(uiCryptoAddr>>8);
    ucCM_InsBuff[2] = (uchar)uiCryptoAddr;
    ucCM_InsBuff[3] = ucCount;

    // Three bytes of the command must be included in the polynominals
    cm_GPAcmd3(ucCM_InsBuff);
    
    // Include the data in the polynominals and encrypt it required
    cm_GPAencrypt(ucCM_Encrypt, pucBuffer, ucCount); 

    ucReturn = cm_WriteCommand(ucCM_InsBuff, pucBuffer, ucCount);

    // when anti-tearing, the host should send ACK should >= 20ms after write command
    if (ucCM_AntiTearing) 
        CM_LOW_LEVEL.WaitClock(10);

    // Done
    return ucReturn;
}

// Write Small User Zone
//
// The Write Small User Zone function is used to write data to CryptoMemory devices that have
// 256 bytes or less in each user zone (AT88SC3216C, and smaller)

// Write Small User Zone
uchar cm_WriteSmallZone(uchar  ucCryptoAddr, puchar pucBuffer, uchar ucCount)
{
    uchar ucReturn;
    int i = 0; 
    
    ucCM_InsBuff[0] = 0xb0;
    ucCM_InsBuff[1] = 0x00;
    ucCM_InsBuff[2] = ucCryptoAddr;
    ucCM_InsBuff[3] = ucCount;

    for(i = 0; i < 4+ucCount; i++){
        if(i < 4){
            debug("%x ", ucCM_InsBuff[i]);
        }else{
            debug("%x ", pucBuffer[i]);
        }
    }

    // Two bytes of the command must be included in the polynominals
    cm_GPAcmd2(ucCM_InsBuff);
    
    // Include the data in the polynominals and encrypt it required
    cm_GPAencrypt(ucCM_Encrypt, pucBuffer, ucCount); 

    // Write the data
    ucReturn = cm_WriteCommand(ucCM_InsBuff, pucBuffer,ucCount);

    // when anti-tearing, the host should send ACK should >= 20ms after write command
    if (ucCM_AntiTearing) 
        CM_LOW_LEVEL.WaitClock(10);

    return ucReturn;
}


// Mid Level Utility Function: cm_ReadCommand()
//
// Note: this module must be after all low level functions in the library and
//       before all high level user function to assure that any reference to
//       this function in this library are satistified.

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

// Reset Password
//
// Reset Password
uchar cm_ResetPassword(void)
{
       return CM_LOW_LEVEL.SendCmdByte(0xba);
}

// Deactivate Security
//
// Deactivate Security
uchar cm_DeactiveSecurity(void)
{
    uchar ucReturn;
     
    if ((ucReturn = CM_LOW_LEVEL.SendCmdByte(0xb8)) != SUCCESS) 
        return ucReturn;
    cm_ResetCrypto();
    
    return SUCCESS;
}

// Low quality random number generator
void cm_RandGen(puchar pucRanddat)
{
    //uchar i;
    //for(i = 0; i < 8; i++) 
    //    pucRanddat[i] = (uchar)(i%6);

    get_random_bytes(pucRanddat, 8);
    
}

// Verify Password
//

// CryptoMemory Library Include Files

uchar ucCmdPassword[4] = {0xba, 0x00, 0x00, 0x03};
uchar ucPSW[3];

// Verify Password
uchar cm_VerifyPassword(puchar pucPassword, uchar ucSet, uchar ucRW)
{
    uchar i, j;
    uchar ucReturn;
    uchar ucAddr;
    debug("%s\n", __func__);
    debug("ucSet = 0x%x, ucRW = 0x%x\n", ucSet, ucRW);
    
    // Build command and PAC address
    ucAddr = CM_PSW + (ucSet << 3);
    ucCmdPassword[1] = ucSet;
    if (ucRW != CM_PWWRITE) {
        ucCmdPassword[1] |= 0x10;
        ucAddr += 4;
    }

    for(i = 0; i < 4; i++){
            debug("%02x ", ucCmdPassword[i]);
    }


    for(i = 0; i < 3; i++){
            debug("%x ", pucPassword[i]);
    }

      
    // Deal with encryption if in authenticate mode
    for (j = 0; j<3; j++) {
        // Encrypt the password
        if(ucCM_Authenticate) {
            debug("ucCM_Authenticate is true\n");
            for(i = 0; i < 5; i++) 
                cm_GPAGen(pucPassword[j]);
                ucPSW[j] = Gpa_byte;
        }else{
        // Else just copy it
            ucPSW[j] = pucPassword[j];
        }
    }


    printk("#############\n");
    for(i = 0; i < 3; i++){
            debug("%x ", ucPSW[i]);
    }

      
    // Send the command
    ucReturn = cm_WriteCommand(ucCmdPassword, ucPSW, 3);
     
     // Wait for chip to process password
     CM_LOW_LEVEL.WaitClock(3);
   
    // Read Password attempts counter to determine if the password was accepted
    if (ucReturn == SUCCESS) {
        ucReturn = cm_ReadConfigZone(ucAddr, ucPSW, 1);
        if (ucPSW[0]!= 0xFF) {
            debug("ucAddr = %x   ucPSW[0] = %x \n", ucAddr, ucPSW[0]);
            debug("PAC != 0xff\n");
            ucReturn = FAILED;
        }
    }

    if (ucCM_Authenticate && (ucReturn != SUCCESS)) 
        cm_ResetCrypto();

    // Done
    return ucReturn;
}

// Write Configuration Zone
// Write Configuration Zone
uchar cm_WriteConfigZone(uchar ucCryptoAddr, puchar pucBuffer, uchar ucCount, uchar ucAntiTearing)
{
    uchar ucReturn, ucEncrypt;
    int i = 0; 


    debug("%s\n", __func__);
    ucCM_InsBuff[0] = 0xb4;
    if(ucAntiTearing) 
        ucCM_InsBuff[1] = 0x08;
    else              
        ucCM_InsBuff[1] = 0x00;

    ucCM_InsBuff[2] = ucCryptoAddr;
    ucCM_InsBuff[3] = ucCount;

    for(i = 0; i < 4;  i++){
            debug("%x ", ucCM_InsBuff[i]);
    }

    for(i = 0; i < ucCount; i++){
             printk("0x%x ", pucBuffer[i]);
    }
    
    // Three bytes of the command must be included in the polynominals
    cm_GPAcmd2(ucCM_InsBuff);
    
    // Only password zone is ever encrypted
    ucEncrypt = ((ucCryptoAddr>= CM_PSW) && ucCM_Encrypt);

    // Include the data in the polynominals and encrypt if required
    cm_GPAencrypt(ucEncrypt, pucBuffer, ucCount); 

    // Do the write
    ucReturn = cm_WriteCommand(ucCM_InsBuff, pucBuffer,ucCount);

    // when anti-tearing, the host should send ACK should >= 20ms after write command
    if (ucAntiTearing) 
        CM_LOW_LEVEL.WaitClock(10);

    return ucReturn;
}

// Write Checksum
uchar   ucCmdWrChk[4] = {0xb4, 0x02, 0x00, 0x02};

// Send Checksum
uchar cm_SendChecksum(puchar pucChkSum)
{
    uchar ucReturn;
    uchar ucChkSum[2];
    int i = 0; 

    debug("%s\n", __func__);

    for(i = 0; i < 4+2; i++){
        if(i < 4){
            debug("%x ", ucCmdWrChk[i]);
        }else{
            debug("%x ", pucChkSum[i]);
        }
    }

    // Get Checksum if required
    if(pucChkSum == NULL) 
        cm_CalChecksum(ucChkSum);
    else {
       ucChkSum[0] = *pucChkSum++; 
       ucChkSum[1] = *pucChkSum; 
    } 
    
    // Send the command
    ucReturn = cm_WriteCommand(ucCmdWrChk, ucChkSum, 2);

    // Give the CyrptoMemory some processing time
    CM_LOW_LEVEL.WaitClock(5);
    
    // Done
    return ucReturn;
}

// Mid Level Utility Function: cm_WriteCommand()
//
// Note: this module must be after all low level functions in the library and
//       before all high level user function to assure that any reference to
//       this function in this library are satistified.

uchar cm_WriteCommand(puchar pucInsBuff, puchar pucSendVal, uchar ucLen)
{ 
    uchar ucReturn;
    debug("%s\n", __func__);

    if ((ucReturn = CM_LOW_LEVEL.SendCommand(pucInsBuff)) != SUCCESS) 
        return ucReturn;
    return CM_LOW_LEVEL.SendData(pucSendVal, ucLen);
}

// Encryption Functions
//
// Note: the naming conventions in this module do not match those used in all other modules. This
//       is because the name used in this module are intended to be as close to those used in the
//       Atmel documentation to make verification of these functions simpler.

// -------------------------------------------------------------------------------------------------
// Data
// -------------------------------------------------------------------------------------------------

uchar ucGpaRegisters[Gpa_Regs];

// -------------------------------------------------------------------------------------------------
// Functions
// -------------------------------------------------------------------------------------------------

// Reset the cryptographic state
void cm_ResetCrypto(void)
{
    uchar i;
    debug("%s\n", __func__);

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
    debug("%s\n", __func__);

    // Reset all registers
    cm_ResetCrypto();
    
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

// The following functions are "macros" for commonly done actions

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
    uchar zero_buf[8] = {0};
    int ret = -1;
    
    if(copy_from_user(&data, (struct ioctl_data *)arg, sizeof(struct ioctl_data))){
        return -EFAULT;
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
        if(memcmp(data.write_buffer2, zero_buf, 8) == 0){
            ret = cm_ActiveSecurity(data.common1, data.write_buffer1, NULL, data.common2);
        }else{
            ret = cm_ActiveSecurity(data.common1, data.write_buffer1, data.write_buffer2, data.common2);
        }
        break;
    case VERIFY_WRITE_PASSWORD:
         printk("%02x%02x%02x\n", data.write_buffer1[0], data.write_buffer1[1], data.write_buffer1[2]);
        ret =  cm_VerifyPassword( data.write_buffer1, data.common1, data.common2);
        break;
    case SET_USER_ZONE:
        ret = cm_SetUserZone(data.common1, data.common2);
        break;
    case READ_USER_ZONE:
        printk("%02x  %02x\n", data.common1,  data.buffer_len);
        ret = cm_ReadSmallZone(data.common1, data.read_buffer, data.buffer_len);
        if(copy_to_user((struct ioctl_data *)arg, &data, sizeof(struct ioctl_data))){
            return -EFAULT;
        }
        break;
    case WRITE_USER_ZONE:
        ret = cm_WriteSmallZone(data.common1, data.write_buffer1, data.buffer_len);
        break;
    case WRITE_CONFIG_ZONE:
        ret = cm_WriteConfigZone(data.common1, data.write_buffer1, data.buffer_len, data.common2);
        break;
    case READ_CONFIG_ZONE:
        ret = cm_ReadConfigZone(data.common1, data.read_buffer, data.buffer_len);
         if(copy_to_user((struct ioctl_data *)arg, &data, sizeof(struct ioctl_data))){
            return -EFAULT;
         }
        break;
    case SEND_CHECKSUM:
        ret = cm_SendChecksum(data.write_buffer1);
        break;
    case READ_CHECKSUM:
        ret = cm_ReadChecksum(data.read_buffer);
        if(copy_to_user((struct ioctl_data *)arg, &data, sizeof(struct ioctl_data))){
            return -EFAULT;
        }
        break;
    case READ_FUSE_BYTE:
        ret = cm_ReadFuse(data.read_buffer);
        if(copy_to_user((struct ioctl_data *)arg, &data, sizeof(struct ioctl_data))){
            return -EFAULT;
        }
        break;
    case BURN_FUSE:
        ret = cm_BurnFuse(data.common1);
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

    printk("davinci at88 release success.\n");
}

module_init(davinci_at88_init);
module_exit(davinci_at88_exit);


MODULE_AUTHOR ("www.gzseeing.com");
MODULE_DESCRIPTION("Crypto chip driver for linux");
MODULE_LICENSE("GPL v2");
