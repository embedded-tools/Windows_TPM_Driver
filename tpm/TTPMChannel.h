#ifndef TPM_CHANNEL___H
#define TPM_CHANNEL___H

#include <windows.h>
#include <tbs.h>

class TTPMChannel
{
public:

	TTPMChannel();
	~TTPMChannel();

	bool Open();
	bool Close();

	bool Transmit(const unsigned char* pbRequest, unsigned long cbRequest,unsigned char *pbResponse, unsigned long *cbResponse, bool physicalPresenceCommand=false);	
	unsigned long GetCode();
	const char*  ErrorToString();
 
    static const char* ErrorToString(unsigned long errorCode);

protected:
   TBS_HCONTEXT m_hContext;	 
   unsigned char *m_pbResponce;
   unsigned long m_cbResponce;
   unsigned long m_ulError;

};

#endif