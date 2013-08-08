/*
 * Name RC522DumpMifare.ino
 *
 * 2013-07-xx started
 * 2013-08-03 first commit
 * 2013-08-08 anticol/select 7byte UID, RATS
 *
 * Based on code by www.electrodragon.com
 * and modified/fixed by http://twitter.com/regnerischerTag
 *
 * TODO: 
 *  - ISO/IEC 14443-4
 *  - Auth 7byte
 *  
 */

// the sensor communicates using SPI, so include the library:
#include <SPI.h>

#define	uchar	unsigned char
#define	uint	unsigned int

//data array maxium length
#define MAX_LEN 16

/////////////////////////////////////////////////////////////////////
//set the pin
/////////////////////////////////////////////////////////////////////
const int chipSelectPin = 10;
const int NRSTPD = 5;

//MF522 command bits
#define PCD_IDLE              0x00               //NO action; cancel current commands
#define PCD_AUTHENT           0x0E               //verify password key
#define PCD_RECEIVE           0x08               //receive data
#define PCD_TRANSMIT          0x04               //send data
#define PCD_TRANSCEIVE        0x0C               //send and receive data
#define PCD_RESETPHASE        0x0F               //reset
#define PCD_CALCCRC           0x03               //CRC check and caculation

//Mifare_One card command bits
#define PICC_REQIDL           0x26               //Search the cards that not into sleep mode in the antenna area 
#define PICC_REQALL           0x52               //Search all the cards in the antenna area
#define PICC_ANTICOLL         0x93               //prevent conflict
#define PICC_SElECTTAG        0x93               //select card
#define PICC_ANTICOLL2        0x95		 // anticollision level 2
#define PICC_ANTICOLL3        0x97               // anticollision level 3
#define PICC_AUTHENT1A        0x60               //verify A password key
#define PICC_AUTHENT1B        0x61               //verify B password key
#define PICC_READ             0x30               //read 
#define PICC_WRITE            0xA0               //write
#define PICC_DECREMENT        0xC0               //deduct value
#define PICC_INCREMENT        0xC1               //charge up value
#define PICC_RESTORE          0xC2               //Restore data into buffer
#define PICC_TRANSFER         0xB0               //Save data into buffer
#define PICC_HALT             0x50               //sleep mode


//THe mistake code that return when communicate with MF522
#define MI_OK                 0
#define MI_NOTAGERR           1
#define MI_ERR                2


//------------------MFRC522 register ---------------
//Page 0:Command and Status
#define     Reserved00            0x00    
#define     CommandReg            0x01    
#define     CommIEnReg            0x02    
#define     DivlEnReg             0x03    
#define     CommIrqReg            0x04    
#define     DivIrqReg             0x05
#define     ErrorReg              0x06    
#define     Status1Reg            0x07    
#define     Status2Reg            0x08    
#define     FIFODataReg           0x09
#define     FIFOLevelReg          0x0A
#define     WaterLevelReg         0x0B
#define     ControlReg            0x0C
#define     BitFramingReg         0x0D
#define     CollReg               0x0E
#define     Reserved01            0x0F
//Page 1:Command     
#define     Reserved10            0x10
#define     ModeReg               0x11
#define     TxModeReg             0x12
#define     RxModeReg             0x13
#define     TxControlReg          0x14
#define     TxAutoReg             0x15
#define     TxSelReg              0x16
#define     RxSelReg              0x17
#define     RxThresholdReg        0x18
#define     DemodReg              0x19
#define     Reserved11            0x1A
#define     Reserved12            0x1B
#define     MifareReg             0x1C
#define     Reserved13            0x1D
#define     Reserved14            0x1E
#define     SerialSpeedReg        0x1F
//Page 2:CFG    
#define     Reserved20            0x20  
#define     CRCResultRegM         0x21
#define     CRCResultRegL         0x22
#define     Reserved21            0x23
#define     ModWidthReg           0x24
#define     Reserved22            0x25
#define     RFCfgReg              0x26
#define     GsNReg                0x27
#define     CWGsPReg	          0x28
#define     ModGsPReg             0x29
#define     TModeReg              0x2A
#define     TPrescalerReg         0x2B
#define     TReloadRegH           0x2C
#define     TReloadRegL           0x2D
#define     TCounterValueRegH     0x2E
#define     TCounterValueRegL     0x2F
//Page 3:TestRegister     
#define     Reserved30            0x30
#define     TestSel1Reg           0x31
#define     TestSel2Reg           0x32
#define     TestPinEnReg          0x33
#define     TestPinValueReg       0x34
#define     TestBusReg            0x35
#define     AutoTestReg           0x36
#define     VersionReg            0x37
#define     AnalogTestReg         0x38
#define     TestDAC1Reg           0x39  
#define     TestDAC2Reg           0x3A   
#define     TestADCReg            0x3B   
#define     Reserved31            0x3C   
#define     Reserved32            0x3D   
#define     Reserved33            0x3E   
#define     Reserved34			  0x3F
//-----------------------------------------------

//4 bytes Serial number of card, the 5th byte is crc
uchar serNum[5];
//7 bytes Serial number of card, the 8th byte is crc
uchar serNum7[8];
//buffer
//uchar str[MAX_LEN];

uchar defaultKeyA[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
uchar madKeyA[16] =     { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };
uchar NDEFKeyA[16] =    { 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7 };

void setup() {                
  Serial.begin(9600);                       // RFID reader SOUT pin connected to Serial RX pin at 2400bps 
  // start the SPI library:
  SPI.begin();
  
  pinMode(chipSelectPin,OUTPUT);         // Set digital pin 10 as OUTPUT to connect it to the RFID /ENABLE pin 
  digitalWrite(chipSelectPin, LOW);      // Activate the RFID reader
  pinMode(NRSTPD,OUTPUT);                // Set digital pin 10 , Not Reset and Power-down
  digitalWrite(NRSTPD, HIGH);

  MFRC522_Init();
  
  //display version info
  //9.3.4.8 VersionReg register : 0x91 / 0x92
  uchar version = Read_MFRC522(VersionReg);
  Serial.print("MFRC522 Version: 0x");
  Serial.println(version, HEX);
}

void loop()
{
    uchar status;
    uchar buffer[MAX_LEN];
    if (selectCard(true))
    {
         for(int block=0; block < 64; block++)
         {
              status = MFRC522_Auth(PICC_AUTHENT1A, block, defaultKeyA, serNum); //auth with default key
              if (status != MI_OK)
              {
                   selectCard(false);
                   status = MFRC522_Auth(PICC_AUTHENT1A, block, madKeyA, serNum); //auth with MAD key
              }
              if (status != MI_OK)
              {
                   selectCard(false);   
                   status = MFRC522_Auth(PICC_AUTHENT1A, block, NDEFKeyA, serNum); //auth NDEF data key
              }
              if (status == MI_OK)
              {
                   status = MFRC522_Read(block, buffer);
                   if (status == MI_OK)
                   {
                        if (block % 4 == 0) 
                        {
                            Serial.print("Sector ");   
                            Serial.print(block / 4, DEC);
                            Serial.println(": ");
                                                     
                        }
                        dumpHex((char*)buffer, MAX_LEN);
                    }
                    else
                    {
                        Serial.println("Read failed");
                        break;
                    } 
              }
              else
              {
                  Serial.println("Auth failed");
                  //TODO Mifare Ultra-Light
                  //MIFARE Ultralight C http://www.nxp.com/documents/short_data_sheet/MF0ICU2_SDS.pdf
                  break;
              }
         }//for
         delay(1000);
    }
    else
    {
        Serial.println("no card select");
    }
    //reset/init for next loop
    MFRC522_Init();
    delay(500);
}

boolean selectCard(boolean dumpInfo) 
{
  uchar status;
  uchar buffer[MAX_LEN];
  //Search card, return card types
  status = MFRC522_Request(PICC_REQIDL, buffer);//ShortFrame: 0x26 REQA (Request Type A)
  //status = MFRC522_Request(PICC_REQALL, buffer);//0x52 WUPA (Wake-Up)
  if (status == MI_OK)
  {
     if (dumpInfo)
     {
         Serial.print("Card detected.\r\n ATQA:");
         dumpHex((char*)buffer, 2);
         Serial.println(" ");
     }
     //Prevent conflict, return the 4 bytes Serial number of the card
     status = MFRC522_Anticoll(buffer);
     if (status == MI_OK)
     {
         memcpy(serNum, buffer, 5);
         uchar sak = 0;
         status = MFRC522_SelectTag(serNum, &sak);                   
         if (status == MI_OK && ((sak & 0x04) == 0x00))
         {        
             if (dumpInfo)
             {
                 Serial.print(" UID: ");
                 dumpHex((char*)serNum, 4);
                 Serial.println("");
             }
             if ((sak & 0x20) == 0x20)
             {
                 //ISO/IEC FCD 14443-3: Table 9 — Coding of SAK
                 //if (dumpInfo)
                 //    Serial.println(" UID complete, PICC compliant with ISO/IEC 14443-4");
                 //send RATS (Request for Answer To Select)
                 uchar ats[MAX_LEN];
                 uint unLen = 0;
                 status = MFRC522_RATS(ats, &unLen);
                 if (status == MI_OK && dumpInfo)
                 {
                      Serial.println(" ATS: ");
                      dumpHex((char*)ats, ats[0]);
                      Serial.println("");
                 }
             }
             if (dumpInfo)
             {
                 Serial.print(" SAK: ");
                 Serial.print(sak, HEX);
                 Serial.println("");
             }     
             return true;
         }
         else
         {
             //cascading level 2
             memcpy(serNum7, &serNum[1], 3);//cascading L1
             status = MFRC522_Anticoll2(buffer);
             if (status == MI_OK)
             {
                 memcpy(&serNum7[3], buffer, 4);
                 status = MFRC522_SelectTag2(&serNum7[3], &sak);
                 if (dumpInfo)
                 {
                    Serial.print(" UID: ");
                    dumpHex((char*)serNum7, 7);
                    Serial.println("");
                    Serial.print(" SAK: ");
                    Serial.print(sak, HEX);
                    Serial.println("");
                 }
                 return true;
             }
             else
             {
                 Serial.println("ANTICOLL error: cascading level 2");
             }
         }
   }//Anticoll
   else
   {
      Serial.print("ANTICOLL failed");
   }
 }
 else
 {
     //Serial.print("-");
 }
 return false;  
}//selectCard

/*
 * Function：Write_MFRC5200
 * Description：write a byte data into one register of MR RC522
 * Input parameter：addr--register address；val--the value that need to write in
 * Return：Null
 */
void Write_MFRC522(uchar addr, uchar val)
{
	digitalWrite(chipSelectPin, LOW);

	//address format：0XXXXXX0
	SPI.transfer((addr<<1)&0x7E);	
	SPI.transfer(val);
	
	digitalWrite(chipSelectPin, HIGH);
}


/*
 * Function：Read_MFRC522
 * Description：read a byte data into one register of MR RC522
 * Input parameter：addr--register address
 * Return：return the read value
 */
uchar Read_MFRC522(uchar addr)
{
	uchar val;

	digitalWrite(chipSelectPin, LOW);

	//address format：1XXXXXX0
	SPI.transfer(((addr<<1)&0x7E) | 0x80);	
	val =SPI.transfer(0x00);
	
	digitalWrite(chipSelectPin, HIGH);
	
	return val;	
}

/*
 * Function：SetBitMask
 * Description：set RC522 register bit
 * Input parameter：reg--register address;mask--value
 * Return：null
 */
void SetBitMask(uchar reg, uchar mask)  
{
    uchar tmp;
    tmp = Read_MFRC522(reg);
    Write_MFRC522(reg, tmp | mask);  // set bit mask
}


/*
 * Function：ClearBitMask
 * Description：clear RC522 register bit
 * Input parameter：reg--register address;mask--value
 * Return：null
 */
void ClearBitMask(uchar reg, uchar mask)  
{
    uchar tmp;
    tmp = Read_MFRC522(reg);
    Write_MFRC522(reg, tmp & (~mask));  // clear bit mask
} 


/*
 * Function：AntennaOn
 * Description：Turn on antenna, every time turn on or shut down antenna need at least 1ms delay
 * Input parameter：null
 * Return：null
 */
void AntennaOn(void)
{
	uchar temp;

	temp = Read_MFRC522(TxControlReg);
	if (!(temp & 0x03))
	{
		SetBitMask(TxControlReg, 0x03);
	}
}


/*
 * Function：AntennaOff
 * Description：Turn off antenna, every time turn on or shut down antenna need at least 1ms delay
 * Input parameter：null
 * Return：null
 */
void AntennaOff(void)
{
	ClearBitMask(TxControlReg, 0x03);
}


/*
 * Function：ResetMFRC522
 * Description： reset RC522
 * Input parameter：null
 * Return：null
 */
void MFRC522_Reset(void)
{
    Write_MFRC522(CommandReg, PCD_RESETPHASE);
}


/*
 * Function：InitMFRC522
 * Description：initilize RC522
 * Input parameter：null
 * Return：null
 */
void MFRC522_Init(void)
{
   digitalWrite(NRSTPD,HIGH);

   MFRC522_Reset();
	 	
    //Timer: TPrescaler*TreloadVal/6.78MHz = 24ms
    Write_MFRC522(TModeReg, 0x8D);		//Tauto=1; f(Timer) = 6.78MHz/TPreScaler
    Write_MFRC522(TPrescalerReg, 0x3E);	//TModeReg[3..0] + TPrescalerReg
    Write_MFRC522(TReloadRegL, 30);           
    Write_MFRC522(TReloadRegH, 0);
	
    Write_MFRC522(TxAutoReg, 0x40);		//100%ASK
    Write_MFRC522(ModeReg, 0x3D);		//CRC initilizate value 0x6363	???

    //ClearBitMask(Status2Reg, 0x08);		//MFCrypto1On=0
    //Write_MFRC522(RxSelReg, 0x86);		//RxWait = RxSelReg[5..0]
    //Write_MFRC522(RFCfgReg, 0x7F);   		//RxGain = 48dB

    AntennaOn();		//turn on antenna
}


/*
 * Function：MFRC522_Request
 * Description：Searching card, read card type
 * Input parameter：reqMode--search methods，
 *			 TagType--return card types
 *			 	0x4400 = Mifare_UltraLight
 *				0x0400 = Mifare_One(S50)
 *				0x0200 = Mifare_One(S70)
 *				0x0800 = Mifare_Pro(X)
 *				0x4403 = Mifare_DESFire
 * return：return MI_OK if successed
 */
uchar MFRC522_Request(uchar reqMode, uchar *TagType)
{
	uchar status;  
	uint backBits;			//the data bits that received

	Write_MFRC522(BitFramingReg, 0x07);		//TxLastBists = BitFramingReg[2..0]	???
	
	TagType[0] = reqMode;
	status = MFRC522_ToCard(PCD_TRANSCEIVE, TagType, 1, TagType, &backBits);

	if ((status != MI_OK) || (backBits != 0x10))
	{    
	     status = MI_ERR;
/*
             Serial.print("status: ");
             Serial.print(status, HEX);
             Serial.print(" backBits: ");
             Serial.print(backBits, HEX);
             Serial.println("");
*/             
	}
	return status;
}


/*
 * Function：MFRC522_ToCard
 * Description：communicate between RC522 and ISO14443
 * Input parameter：command--MF522 command bits
 *			 sendData--send data to card via rc522
 *			 sendLen--send data length		 
 *			 backData--the return data from card
 *			 backLen--the length of return data
 * return：return MI_OK if successed
 */
uchar MFRC522_ToCard(uchar command, uchar *sendData, uchar sendLen, uchar *backData, uint *backLen)
{
    uchar status = MI_ERR;
    uchar irqEn = 0x00;
    uchar waitIRq = 0x00;
    uchar lastBits;
    uchar n;
    uint i;

    switch (command)
    {
        case PCD_AUTHENT:		//verify card password
		{
			irqEn = 0x12;
			waitIRq = 0x10;
			break;
		}
	case PCD_TRANSCEIVE:	//send data in the FIFO
		{
			irqEn = 0x77;
			waitIRq = 0x30;
			break;
		}
	default:
			break;
    }
   
    Write_MFRC522(CommIEnReg, irqEn|0x80);	//Allow interruption
    ClearBitMask(CommIrqReg, 0x80);			//Clear all the interrupt bits
    SetBitMask(FIFOLevelReg, 0x80);			//FlushBuffer=1, FIFO initilizate
    
    Write_MFRC522(CommandReg, PCD_IDLE);	//NO action;cancel current command	???

    //write data into FIFO
    for (i=0; i<sendLen; i++)
    {   
        Write_MFRC522(FIFODataReg, sendData[i]);    
    }

    //procceed it
    Write_MFRC522(CommandReg, command);
    if (command == PCD_TRANSCEIVE)
    {    
        SetBitMask(BitFramingReg, 0x80);		//StartSend=1,transmission of data starts  
    }   
    
    //waite receive data is finished
    i = 2000;	//i should adjust according the clock, the maxium the waiting time should be 25 ms???
    do 
    {
	//CommIrqReg[7..0]
	//Set1 TxIRq RxIRq IdleIRq HiAlerIRq LoAlertIRq ErrIRq TimerIRq
        n = Read_MFRC522(CommIrqReg);
        i--;
    }
    while ((i!=0) && !(n&0x01) && !(n&waitIRq));

    ClearBitMask(BitFramingReg, 0x80);			//StartSend=0
	
    if (i != 0)
    {
        if(!(Read_MFRC522(ErrorReg) & 0x1B))	//BufferOvfl Collerr CRCErr ProtecolErr
        {
            status = MI_OK;
            if (n & irqEn & 0x01)
            {   
               status = MI_NOTAGERR;			//??   
            }

            if (command == PCD_TRANSCEIVE)
            {
               	n = Read_MFRC522(FIFOLevelReg);
              	lastBits = Read_MFRC522(ControlReg) & 0x07;
                if (lastBits)
                {   
		   *backLen = (n-1)*8 + lastBits;   
		}
                else
                {   
		   *backLen = n*8;   
		}

                if (n == 0)
                {   
		    n = 1;    
		}
                if (n > MAX_LEN)
                {   
		    n = MAX_LEN;   
		}
				
		//read the data from FIFO
                for (i=0; i<n; i++)
                {   
		    backData[i] = Read_MFRC522(FIFODataReg);    
		}
            }
        }
        else
        {   
	    status = MI_ERR;  
	}
        
    }
    else
    {
         //Serial.print("i=0");
    }
	
    //SetBitMask(ControlReg,0x80);           //timer stops
    //Write_MFRC522(CommandReg, PCD_IDLE); 

    return status;
}


/*
 * Function：MFRC522_Anticoll
 * Description：Prevent conflict, read the card serial number 
 * Input parameter：serNum--return the 4 bytes card serial number, the 5th byte is recheck byte
 * return：return MI_OK if successed
 */
uchar MFRC522_Anticoll(uchar *serNum)
{
    uchar status;
    uchar i;
    uchar serNumCheck=0;
    uint unLen;
    

    //ClearBitMask(Status2Reg, 0x08);		//TempSensclear
    //ClearBitMask(CollReg,0x80);		//ValuesAfterColl
    Write_MFRC522(BitFramingReg, 0x00);		//TxLastBists = BitFramingReg[2..0]
 
    serNum[0] = PICC_ANTICOLL;
    serNum[1] = 0x20;
    status = MFRC522_ToCard(PCD_TRANSCEIVE, serNum, 2, serNum, &unLen);

    if (status == MI_OK)
    {
	 //Verify card serial number
         for (i=0; i<4; i++)
	 {    
	     serNumCheck ^= serNum[i];
	 }
	 if (serNumCheck != serNum[i])
	 {   
	     status = MI_ERR;    
	 }
    }
    //SetBitMask(CollReg, 0x80);		//ValuesAfterColl=1
    return status;
}

//ANTICOLL cascading level 2
uchar MFRC522_Anticoll2(uchar *serNum)
{
    uchar status;
    uchar i;
    uchar serNumCheck=0;
    uint unLen;
    

    //ClearBitMask(Status2Reg, 0x08);		//TempSensclear
    //ClearBitMask(CollReg,0x80);		//ValuesAfterColl
    Write_MFRC522(BitFramingReg, 0x00);		//TxLastBists = BitFramingReg[2..0]
 
    serNum[0] = PICC_ANTICOLL2;
    serNum[1] = 0x20;
    status = MFRC522_ToCard(PCD_TRANSCEIVE, serNum, 2, serNum, &unLen);

    if (status == MI_OK)
    {
	 //Verify card serial number
         for (i=0; i<4; i++)
	 {    
	     serNumCheck ^= serNum[i];
	 }
	 if (serNumCheck != serNum[i])
	 {   
	     status = MI_ERR;    
	 }
    }
    //SetBitMask(CollReg, 0x80);		//ValuesAfterColl=1
    return status;
}

//send RATS and returns ATS
uchar MFRC522_RATS(uchar *recvData, uint *pLen)
{
    uchar status;
    uint unLen = 0;

    recvData[0] = 0xE0; // RATS
    recvData[1] = 0x50; // FSD=128, CID=0
    CalulateCRC(recvData,2, &recvData[2]);
    status = MFRC522_ToCard(PCD_TRANSCEIVE, recvData, 4, recvData, &unLen);
    /*
    Serial.print("unLen: ");
    Serial.print(unLen, HEX);
    /*Serial.print(" status: ");
    Serial.print(status, HEX);
    Serial.println("");
    */
    //TODO
    //if ((status != MI_OK) || (unLen != 0x90))
    //{
    //    status = MI_ERR;
    //}
    return status;
}


/*
 * Function：CalulateCRC
 * Description：Use MF522 to caculate CRC
 * Input parameter：pIndata--the CRC data need to be read，len--data length，pOutData-- the caculated result of CRC
 * return：Null
 */
void CalulateCRC(uchar *pIndata, uchar len, uchar *pOutData)
{
    uchar i, n;

    ClearBitMask(DivIrqReg, 0x04);			//CRCIrq = 0
    SetBitMask(FIFOLevelReg, 0x80);			//Clear FIFO pointer
    //Write_MFRC522(CommandReg, PCD_IDLE);

	//Write data into FIFO	
    for (i=0; i<len; i++)
    {   
        Write_MFRC522(FIFODataReg, *(pIndata+i));   
    }
    Write_MFRC522(CommandReg, PCD_CALCCRC);

	//waite CRC caculation to finish
    i = 0xFF;
    do 
    {
        n = Read_MFRC522(DivIrqReg);
        i--;
    }
    while ((i!=0) && !(n&0x04));			//CRCIrq = 1

	//read CRC caculation result
    pOutData[0] = Read_MFRC522(CRCResultRegL);
    pOutData[1] = Read_MFRC522(CRCResultRegM);
}


/*
 * Function：MFRC522_SelectTag
 * Description：Select card, read card storage volume
 * Input parameter：serNum--Send card serial number
 * sak see ISO14443-3 Table 9 — Coding of SAK
 * return return MI_OK if successed
 */
uchar MFRC522_SelectTag(uchar *serNum, uchar *sak)
{
    uchar i;
    uchar status;
    //uchar size;
    uint recvBits;
    uchar buffer[9];
    //uchar buffCheck=0; 

    //ClearBitMask(Status2Reg, 0x08);			//MFCrypto1On=0

    buffer[0] = PICC_SElECTTAG;
    buffer[1] = 0x70;
    for (i=0; i<5; i++)
    {
    	buffer[i+2] = *(serNum+i);
    }
    CalulateCRC(buffer, 7, &buffer[7]);		//??
    status = MFRC522_ToCard(PCD_TRANSCEIVE, buffer, 9, buffer, &recvBits);
    //TODO: the above call returns 2 instead of MI_OK -> why?
    status = MI_OK;
    //Serial.print("recvBits: ");
    //Serial.print(recvBits, DEC);
    /*
    for (i=0; i<recBits / 8; i++)
    {
    	buff[i] = *(buffer+i);
    }*/
    //dumpHex((char*)buffer, recvBits / 8);
    *sak = buffer[0];
    //Verify received buffer
    /* TODO
    for (i=0; i< recvBits/8; i++)
    {   
       buffCheck ^= buffer[i];
    }
    if (buffCheck != buffer[i])
    {   
       status = MI_ERR;    
    }*/
    return status;
}

uchar MFRC522_SelectTag2(uchar *serNum, uchar *sak)
{
    uchar i;
    uchar status;
    //uchar size;
    uint recvBits;
    uchar buffer[9];
    //uchar buffCheck=0; 

    //ClearBitMask(Status2Reg, 0x08);			//MFCrypto1On=0

    buffer[0] = PICC_ANTICOLL2;
    buffer[1] = 0x70;
    for (i=0; i<5; i++)
    {
    	buffer[i+2] = *(serNum+i);
    }
    CalulateCRC(buffer, 7, &buffer[7]);
    status = MFRC522_ToCard(PCD_TRANSCEIVE, buffer, 9, buffer, &recvBits);
    //TODO: the above call returns 2 instead of MI_OK -> why?
    status = MI_OK;
    //Serial.print("recvBits: ");
    //Serial.print(recvBits, DEC);
    /*
    for (i=0; i<recBits / 8; i++)
    {
    	buff[i] = *(buffer+i);
    }*/
    //dumpHex((char*)buffer, recvBits / 8);
    *sak = buffer[0];
    //Verify received buffer
    /* TODO
    for (i=0; i< recvBits/8; i++)
    {   
       buffCheck ^= buffer[i];
    }
    if (buffCheck != buffer[i])
    {   
       status = MI_ERR;    
    }*/
    return status;
}


/*
 * Function：MFRC522_Auth
 * Description：verify card password
 * Input parameters：authMode--password verify mode
                 0x60 = verify A passowrd key 
                 0x61 = verify B passowrd key 
             BlockAddr--Block address
             Sectorkey--Block password
             serNum--Card serial number ，4 bytes
 * return：return MI_OK if successed
 */
uchar MFRC522_Auth(uchar authMode, uchar BlockAddr, uchar *Sectorkey, uchar *serNum)
{
    uchar status;
    uint recvBits;
    uchar i;
    uchar buff[12]; 

    //Verify command + block address + buffer password + card SN
    buff[0] = authMode;
    buff[1] = BlockAddr;
    for (i=0; i<6; i++)
    {    
        buff[i+2] = *(Sectorkey+i);   
    }
    for (i=0; i<4; i++)
    {    
        buff[i+8] = *(serNum+i);   
    }
    status = MFRC522_ToCard(PCD_AUTHENT, buff, 12, buff, &recvBits);

    if ((status != MI_OK) || (!(Read_MFRC522(Status2Reg) & 0x08)))
    {   
        status = MI_ERR;   
    }
    
    return status;
}


/*
 * Function：MFRC522_Read
 * Description：Read data 
 * Input parameters：blockAddr--block address;recvData--the block data which are read
 * return：return MI_OK if successed
 */
uchar MFRC522_Read(uchar blockAddr, uchar *recvData)
{
    uchar status;
    uint unLen;

    recvData[0] = PICC_READ;
    recvData[1] = blockAddr;
    CalulateCRC(recvData,2, &recvData[2]);
    status = MFRC522_ToCard(PCD_TRANSCEIVE, recvData, 4, recvData, &unLen);

    if ((status != MI_OK) || (unLen != 0x90))
    {
        status = MI_ERR;
    }
    
    return status;
}


/*
 * Function：MFRC522_Write
 * Description：write block data
 * Input parameters：blockAddr--block address;writeData--Write 16 bytes data into block
 * return：return MI_OK if successed
 */
uchar MFRC522_Write(uchar blockAddr, uchar *writeData)
{
    uchar status;
    uint recvBits;
    uchar i;
    uchar buff[18]; 
    
    buff[0] = PICC_WRITE;
    buff[1] = blockAddr;
    CalulateCRC(buff, 2, &buff[2]);
    status = MFRC522_ToCard(PCD_TRANSCEIVE, buff, 4, buff, &recvBits);

    if ((status != MI_OK) || (recvBits != 4) || ((buff[0] & 0x0F) != 0x0A))
    {   
        status = MI_ERR;   
    }
        
    if (status == MI_OK)
    {
        for (i=0; i<16; i++)		//Write 16 bytes data into FIFO
        {    
        	buff[i] = *(writeData+i);   
        }
        CalulateCRC(buff, 16, &buff[16]);
        status = MFRC522_ToCard(PCD_TRANSCEIVE, buff, 18, buff, &recvBits);
        
		if ((status != MI_OK) || (recvBits != 4) || ((buff[0] & 0x0F) != 0x0A))
        {   
			status = MI_ERR;   
		}
    }
    
    return status;
}

/*
 * Function：MFRC522_Halt
 * Description：Command the cards into sleep mode
 * Input parameters：null
 * return：null
 */
void MFRC522_Halt(void)
{
    uchar status;
    uint unLen;
    uchar buff[4]; 

    //ISO14443-3: 6.4.3 HLTA command
    buff[0] = PICC_HALT;
    buff[1] = 0;
    CalulateCRC(buff, 2, &buff[2]);
 
    status = MFRC522_ToCard(PCD_TRANSCEIVE, buff, 4, buff, &unLen);
}

void dumpHex(char* buffer, int len)
{
  for(byte i=0; i < len; i++) {
     char text[4];
     if (i % 16 == 0) {
        Serial.print(" "); 
     }
     sprintf(text, "%02X \x00", (byte)(*(buffer + i)));
     Serial.print(text);
 
     if (i % 16 == 15) {
        Serial.println(""); 
     }
  }
  //Serial.println(" "); 
}
