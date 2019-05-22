#ifndef TPM_BUFFER___H
#define TPM_BUFFER___H

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "TPM_structures.h"
#include "sha1.h"
#include "hmac.h"

class TTPMBuffer
{
	private:
        unsigned char*	m_pBuffer;
		unsigned int	m_bufferSize;
		unsigned int	m_bufferDataCount;
		tpm_sha1_t      m_sha1;
		bool            m_InputParamDigestReady;
		TPM_DIGEST   	m_inputParamDigest; 
		unsigned long   m_readingPosition;

		bool SetNewSize(unsigned int newSize);

	public:
		
		TTPMBuffer(unsigned long bufferSize=256);	
		~TTPMBuffer();

		void WriteCommandHeader(unsigned short commandType = TPM_TAG_RQU_COMMAND);
		void UpdateCommandHeaderSize();

		void WriteUInt32(unsigned int i, bool includeToSHA1=true);
		void WriteUInt16(unsigned short w, bool includeToSHA1=true);
		void WriteUInt8(unsigned char b, bool includeToSHA1=true);
		void WriteBinaryData(unsigned char* pData, unsigned int pDataLength, bool includeToSHA1=true, bool convertBigEndianToLittleEndian=false);
		bool GetSHA1Digest(TPM_DIGEST& sha1Digest);

		void ReadResponseHeader(unsigned short &commandType, unsigned long &returnCode);
		unsigned char ReadUInt8();
		unsigned short ReadUInt16();
		unsigned long  ReadUInt32();
		bool ReadBinaryData(unsigned char* pData, const unsigned long dataLength, bool convertBigEndianToLittleEndian=false);
		
		unsigned char* GetBufferPtr();
		unsigned long GetDataCount();
		unsigned long GetBufferSize();
		unsigned long GetReadingPosition();
		bool Eof();
	
};

#endif