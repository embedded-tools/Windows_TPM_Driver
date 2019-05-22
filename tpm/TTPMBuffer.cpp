#include "TTPMBuffer.h"

/*******************************************************
 *   Ctor
 *   Function initializes all class members and then 
 *   calls SetNewSize method
 *
 *   Returns        : Nothing
 *******************************************************/
TTPMBuffer::TTPMBuffer(unsigned long bufferSize)
{	
	//initializes all data to zero values
	m_pBuffer = NULL;	
	m_bufferDataCount = 0;
	m_bufferSize = 0;
	m_readingPosition = 0;
	tpm_sha1_init(&m_sha1);

	m_InputParamDigestReady = false;
	memset(m_inputParamDigest.digest, 0, sizeof(m_inputParamDigest.digest));

	//allocates required memory amount
	SetNewSize(bufferSize);
}

/*******************************************************
 *   Dtor
 *   Function unallocates all memory blocks
 *
 *   Returns        : Nothing
 *******************************************************/
TTPMBuffer::~TTPMBuffer()
{
	if (m_pBuffer!=NULL)
	{
		delete m_pBuffer;
		m_pBuffer = NULL;
		m_bufferDataCount = 0;
		m_bufferSize = 0;
	}
}

/*******************************************************
 *   WriteCommandHeader
 *   Each TPM command contains the same sequence in the beginning:
 *   0000:  2 bytes : TPM_TAG
 *   0002:  4 bytes : paramSize (default paramSize is 6 bytes)
 *   0006:  
 *
 *   Returns        : Nothing
 *******************************************************/
void TTPMBuffer::WriteCommandHeader(unsigned short commandType)
{
	WriteUInt16(commandType, false);
	WriteUInt32(6, false);
}

/*******************************************************
 *   UpdateCommandHeaderSize
 *
 *   Each TPM command contains the same sequence in the beginning:
 *   0000:  2 bytes : TPM_TAG
 *   0002:  4 bytes : paramSize (these bytes are replaced by real size)
 *   0006:  command data
 *   00XX:  command data
 *   00XX:  command data
 *
 *   Updates paramSize after inserting all command data to buffer
 *
 *   Returns        : Nothing
 *******************************************************/
void TTPMBuffer::UpdateCommandHeaderSize()
{
	if ((m_pBuffer!=NULL) && (m_bufferDataCount))
	{
		unsigned char* pBufferSize = (unsigned char*)&m_bufferDataCount;
		m_pBuffer[2] = pBufferSize[3];
		m_pBuffer[3] = pBufferSize[2];
		m_pBuffer[4] = pBufferSize[1];
		m_pBuffer[5] = pBufferSize[0];
	}
}

/*******************************************************
 *   SettNewSize
 *   
 *   Sets new buffer size. Old data are not lost. 
 *   
 *   Returns        : TRUE if reallocation was successful
 *                  : FALSE if reallocation failed                 
 *******************************************************/
bool TTPMBuffer::SetNewSize(unsigned int newSize)
{
	if (m_pBuffer!=NULL)
	{
		m_pBuffer = (unsigned char*)realloc((void*)m_pBuffer, newSize);
	} else {
		m_pBuffer = (unsigned char*)malloc(newSize);
	}
	if (m_pBuffer==NULL)
	{
		m_bufferDataCount = 0;
		m_bufferSize = 0;		
		return false;
	}
	m_bufferSize = newSize;
	return true;
}

/*******************************************************
 *   WriteUInt32
 *   
 *   Converts UInt32 to BIGENDIAN, writes it to buffer and
 *   updates SHA1 hash if required
 *   
 *   Returns           : Nothing
 *   bool includeToSHA1: TRUE -  adds i to SHA1 hash
 *                     : FALSE - no SHA1 update
 *******************************************************/
void TTPMBuffer::WriteUInt32(unsigned int i, bool includeTo1H1)
{
	unsigned int newBufferLength = m_bufferDataCount+4;
	if (newBufferLength>=m_bufferSize)
	{
		SetNewSize(m_bufferSize+256);
	}
	if (m_pBuffer!=NULL) 
	{
		unsigned char* scrData = (unsigned char*)&i;
		m_pBuffer[m_bufferDataCount] = scrData[3];
		m_pBuffer[m_bufferDataCount+1] = scrData[2];
		m_pBuffer[m_bufferDataCount+2] = scrData[1];
		m_pBuffer[m_bufferDataCount+3] = scrData[0];
		if (includeTo1H1)
		{
			tpm_sha1_update(&m_sha1, (const BYTE*)&m_pBuffer[m_bufferDataCount], sizeof(i));			
		}
		m_bufferDataCount+=4;
	}
}


/*******************************************************
 *   WriteUInt16
 *   
 *   Converts UInt16 to BIGENDIAN, writes it to buffer and
 *   updates SHA1 hash if required
 *   
 *   Returns           : Nothing
 *   bool includeToSHA1: TRUE -  adds i to SHA1 hash
 *                     : FALSE - no SHA1 update
 *******************************************************/
void TTPMBuffer::WriteUInt16(unsigned short w, bool includeTo1H1)
{
	unsigned int newBufferLength = m_bufferDataCount+2;
	if (newBufferLength>=m_bufferSize)
	{
		SetNewSize(m_bufferSize+256);
	}
	if (m_pBuffer!=NULL) 
	{
		unsigned char* scrData = (unsigned char*)&w;
		m_pBuffer[m_bufferDataCount] = scrData[1];
		m_pBuffer[m_bufferDataCount+1] = scrData[0];
		if (includeTo1H1)
		{
			tpm_sha1_update(&m_sha1, (const BYTE*)&m_pBuffer[m_bufferDataCount], sizeof(w));			
		}
		m_bufferDataCount+=2;
	}
}

/*******************************************************
 *   WriteUInt8
 *   
 *   Writes UInt8 it to buffer and updates SHA1 hash if required
 *   
 *   Returns           : Nothing
 *   bool includeToSHA1: TRUE -  adds i to SHA1 hash
 *                     : FALSE - no SHA1 update
 *******************************************************/
void TTPMBuffer::WriteUInt8(unsigned char b, bool includeTo1H1)
{
	unsigned int newBufferLength = m_bufferDataCount+1;
	if (newBufferLength>=m_bufferSize)
	{
		SetNewSize(m_bufferSize+256);
	}
	if (m_pBuffer!=NULL) 
	{
		m_pBuffer[m_bufferDataCount] = b;
		if (includeTo1H1)
		{
			tpm_sha1_update(&m_sha1, (const BYTE*)&m_pBuffer[m_bufferDataCount], sizeof(b));			
		}
		m_bufferDataCount++;

	}
}

/*******************************************************
 *   WriteBinaryData
 *   
 *   Writes binary data to buffer and updates SHA1 hash if required
 *   
 *   Returns           : Nothing
 *   bool includeToSHA1: TRUE -  adds data to SHA1 hash
 *                     : FALSE - no SHA1 update
 *******************************************************/
void TTPMBuffer::WriteBinaryData(unsigned char* pData, unsigned int dataLength, bool includeTo1H1, bool convertBigEndianToLittleEndian)
{
	unsigned int newBufferLength = m_bufferDataCount+dataLength;
	if (newBufferLength>=m_bufferSize)
	{
		SetNewSize(dataLength<256? m_bufferSize+256 : m_bufferSize+dataLength);
	}
	if (m_pBuffer!=NULL) 
	{
		if (convertBigEndianToLittleEndian)
		{
			//converts BIG ENDIAN to LITTLE ENDIAN
			unsigned long bufferPosition = m_bufferDataCount + dataLength - 1;
			for(unsigned long i = 0; i<dataLength;i++)
			{
				m_pBuffer[bufferPosition--] = pData[i];
			}
		} else {
			memcpy(&m_pBuffer[m_bufferDataCount], pData, dataLength);
		}
		if (includeTo1H1)
		{
			tpm_sha1_update(&m_sha1, (const BYTE*)&m_pBuffer[m_bufferDataCount], dataLength);			
		}
		m_bufferDataCount+=dataLength;
	}		
}

/*******************************************************
 *   GetSHA1Digest
 *   
 *   Returns SHA1 digest for input data
 *   
 *   Returns           : SHA1 digest
 *   bool includeToSHA1: TRUE 
 *******************************************************/
bool TTPMBuffer::GetSHA1Digest(TPM_DIGEST& sha1Digest)
{
	if (!m_InputParamDigestReady)
	{
		tpm_sha1_final(&m_sha1, m_inputParamDigest.digest);
		m_InputParamDigestReady = true;
	}
	memcpy(sha1Digest.digest, m_inputParamDigest.digest, sizeof(m_inputParamDigest.digest));
	
	return true;
}

/*******************************************************
 *   ReadResponseHeader
 *   
 *   Each TPM response contains data:
 *   0000: (2 bytes) commandType
 *   0002: (4 bytes) responseSize
 *   0006: (4 bytes) returnCode
 *
 *   Methods reads three parameters contained in each tmp
 *   command response and sets m_bufferDataCount to real
 *   response size
 *
 *   Returns           : Nothing
 *******************************************************/
void TTPMBuffer::ReadResponseHeader(unsigned short &commandType, unsigned long &returnCode)
{
	if ((m_pBuffer==NULL) || (m_bufferSize<6)) return;

	m_bufferDataCount = 6;             //forcibly changes data count to 6 (otherwise following commands ReadUInt16 and ReadUInt32 will fail)
	m_readingPosition = 0;             //resets reading position
	commandType = ReadUInt16();        //reads response tag (TPM_TAG_RSP_XXXXXXX)
	m_bufferDataCount = ReadUInt32();  //reads response size (how much data was received by TPM chip)
	returnCode = ReadUInt32();	       //reads response error code (TPM_RESULT)
}

/*******************************************************
 *   ReadUInt8
 *   
 *   Methods reads UInt8 from buffer. Method does not allow
 *   to read more data than was really received from TPM
 *
 *   Returns           : UInt8
 *******************************************************/
unsigned char TTPMBuffer::ReadUInt8()
{
	unsigned long dataTypeSize = 1;
	if (m_readingPosition+dataTypeSize>m_bufferDataCount)
	{
		//buffer would overflow during data reading -> returns zero
		return 0;
	}
	unsigned char result = m_pBuffer[m_readingPosition];
	m_readingPosition+=dataTypeSize;
	return result;
}

/*******************************************************
 *   ReadUInt16
 *   
 *   Methods reads UInt16 from buffer. Method does not allow
 *   to read more data than was really received from TPM
 *
 *   Returns           : UInt8
 *******************************************************/
unsigned short TTPMBuffer::ReadUInt16()
{
	//checks buffer overflow
	unsigned long dataTypeSize = 2;
	if (m_readingPosition+dataTypeSize>m_bufferDataCount)
	{
		//buffer would overflow during data reading -> returns zero
		return 0;
	}
	unsigned short result = 0;

	//converts BIG ENDIAN to LITTLE ENDIAN
	unsigned char* pResult = (unsigned char*)&result;
	pResult[0] = m_pBuffer[m_readingPosition+1];
	pResult[1] = m_pBuffer[m_readingPosition+0];

	m_readingPosition+=dataTypeSize;
	return result;
}

/*******************************************************
 *   ReadUInt32
 *   
 *   Methods reads UInt32 from buffer. Method does not allow
 *   to read more data than was really received from TPM
 *
 *   Returns           : UInt8
 *******************************************************/
unsigned long TTPMBuffer::ReadUInt32()
{
	//checks buffer overflow
	unsigned long dataTypeSize = 4;
	if (m_readingPosition+dataTypeSize>m_bufferDataCount)
	{
		//buffer would overflow during data reading -> returns zero
		return 0;
	}
	unsigned long result = 0;

	//converts BIG ENDIAN to LITTLE ENDIAN
	unsigned char* pResult = (unsigned char*)&result;
	pResult[0] = m_pBuffer[m_readingPosition+3];
	pResult[1] = m_pBuffer[m_readingPosition+2];
	pResult[2] = m_pBuffer[m_readingPosition+1];
	pResult[3] = m_pBuffer[m_readingPosition];

	m_readingPosition+=dataTypeSize;
	return result;
}

/*******************************************************
 *   ReadBinaryData
 *   
 *   Methods reads BinaryData from buffer. 
 *
 *   Returns           : FALSE if is asked to read more
 *                             data than was really received
 *                             from TPM
 *   targetBufferSize  : output buffer size
 *   binaryDataLength  : requested data size
 *   convertBigEndianToLittleEndian: TRUE - swaps first byte with last etc.
 *******************************************************/
bool TTPMBuffer::ReadBinaryData(unsigned char* pData, const unsigned long dataLength, bool convertBigEndianToLittleEndian)
{

	//checks buffer overflow
	if (m_readingPosition+dataLength>m_bufferDataCount)
	{
		//buffer would overflow during data reading -> returns zero
		return 0;
	}
	unsigned short result = 0;

	if (convertBigEndianToLittleEndian)
	{
		//converts BIG ENDIAN to LITTLE ENDIAN
		unsigned long inputBufferPosition = m_readingPosition + dataLength - 1;
		for(unsigned long i = 0; i<dataLength;i++)
		{
			pData[i] = m_pBuffer[inputBufferPosition--];
		}
	} else {
		memcpy(pData, &m_pBuffer[m_readingPosition], dataLength);
	}

	m_readingPosition+=dataLength;
	return true;
}

/*******************************************************
 *   GetBufferPtr
 *   
 *   Method returns pointer to internal buffer.
 *
 *   Returns           : Pointer in internal buffer
 *******************************************************/
unsigned char* TTPMBuffer::GetBufferPtr()
{
	return m_pBuffer;
}

/*******************************************************
 *   GetDataCount
 *   
 *   Method returns amount of real data stored in buffer
 *   
 *   Returns           : internal buffer size
 *******************************************************/
unsigned long TTPMBuffer::GetDataCount()
{
	return m_bufferDataCount;
}

/*******************************************************
 *   GetBufferSize
 *   
 *   Method returns buffer size
 *   
 *   Returns           : internal buffer size
 *******************************************************/
unsigned long TTPMBuffer::GetBufferSize()
{
	return m_bufferSize;
}

/*******************************************************
 *   GetReadingPosition
 *   
 *   Method returns current reading position
 *   
 *   Returns           : current reading position
 *******************************************************/
unsigned long TTPMBuffer::GetReadingPosition()
{
	return m_readingPosition;
}

/*******************************************************
 *   Eof
 *   
 *   Method returns TRUE if buffer contains no more data
 *   
 *   Returns           : TRUE (end of file detected)
 *******************************************************/
bool TTPMBuffer::Eof()
{
	return m_readingPosition>=m_bufferDataCount;
}