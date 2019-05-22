#ifndef TPM___H
#define TPM___H

#include <stddef.h>
#include "TPM_structures.h"
#include "TTPMBuffer.h"

#define TPM_CHANNEL_ERROR_DETECTED 0x00002000
#define TPM_BUFFER_TOO_SMALL	    0x00002001
#define TPM_INVALID_TPM_RESPONSE   0x00002002
#define TPM_UNKNOWN_SESSION_TYPE   0x00002003

class TTPMChannel;
class TTPMAttributeList;


class TTPM
{
public:

	TTPM(TTPMChannel *pChannel=NULL);

	void SetChannel(TTPMChannel *pChannel);
	bool Init(TTPMAttributeList *props=NULL);

	bool GetProperty(TTPMAttributeList *props=NULL);
	bool ChangePassword(TTPMAttributeList *props=NULL);
	bool Reset(TTPMAttributeList* props=NULL);
		
	bool ReadPubEK(unsigned char* pbKey, unsigned long* cbKey);

    bool GenerateKey(unsigned char *pbdata, unsigned long *cbdata, TTPMAttributeList *props=NULL);
	bool ImportKey(unsigned long *hKey,const unsigned char *pbdata,unsigned long cbdata, TTPMAttributeList *props=NULL);
	bool ExportKey(unsigned long hKey,unsigned char *pbdata,unsigned long *cbdata,TTPMAttributeList *props=NULL);	
	bool GetPublicKey(unsigned long hKey, unsigned char* pbData, unsigned long* cbData, TTPMAttributeList* props=NULL);	

	bool Seal(unsigned long keyHandle, unsigned char* pbData, unsigned long cbData, unsigned char* pbOutput, unsigned long* cbOutput, TTPMAttributeList *props=NULL);
	bool Unseal(unsigned long keyHandle, unsigned char* pbData, unsigned long cbData, unsigned char* pbOutput, unsigned long* cbOutput, TTPMAttributeList *props=NULL);

	bool Sign(unsigned long keyHandle, unsigned char* pbData, unsigned long cbData, unsigned char* pbSign, unsigned long *cbSign, TTPMAttributeList *props=NULL);

	bool TakeOwnership(TPM_DIGEST& ownerAuth, TPM_DIGEST& srkAuth);  

	unsigned long GetCode();
	const char*  ErrorToString();	

	static const char* ErrorToString(unsigned long errorCode);
	static void GetStringDigest(const char* pString, TPM_DIGEST &digest);

protected:

	TTPMChannel  *m_pChannel;  
	unsigned long m_ulError;
	
	//used by Init method and GetProperty method
	bool          m_bTpmActive;
	bool          m_bTpmOwnerSet;
	unsigned long m_lTpmVersion;
	unsigned long m_lTpmVendor;

	//used by SendOIAPAuthentication method
	unsigned char m_OIAP_continue;
	unsigned long m_OIAP_authHandle;
	TPM_NONCE     m_OIAP_nonceOdd;
	TPM_NONCE     m_OIAP_authLastNonceEven;
	TPM_AUTHDATA  m_OIAP_authData;

	//used by SendOSAPAuthentication method
	unsigned char m_OSAP_continue;
	unsigned long m_OSAP_authHandle;
	TPM_NONCE	  m_OSAP_authLastNonceEven;
	TPM_NONCE     m_OSAP_nonceOdd;
	TPM_NONCE     m_OSAP_nonceEven;
	TPM_NONCE     m_OSAP_sharedSecret;
	TPM_AUTHDATA  m_OSAP_authData;

	
	//used by SendDataAuthentication method
	unsigned char m_OSAP_dataContinue;
	unsigned long m_OSAP_dataAuthHandle;
	TPM_NONCE	  m_OSAP_dataLastNonceEven;
	TPM_NONCE     m_OSAP_datanonceOdd;
	TPM_NONCE     m_OSAP_datanonceEven;
	TPM_NONCE     m_OSAP_dataSharedSecret;
	TPM_AUTHDATA  m_OSAP_dataAuth;
	

	//used by HMAC methods
	tpm_hmac_t m_HMAC;

	bool ReadTPMVersion();
	bool CheckTPMOwner();

	void FillKeyParams(TPM_KEY& keyParams, TTPMAttributeList *props);
	void WriteKeyParams(TPM_KEY& keyParams, TTPMBuffer &requestBuffer);

	void InitHMAC(unsigned char* pBinaryData, unsigned long binaryDataLength);
	void UpdateHMAC(unsigned char* pBinaryData, unsigned long binaryDataLength);
	void FinishHMAC(unsigned char* pOutputBuffer);
	
	bool SendTPMCommand(TTPMBuffer& requestBuffer, TTPMBuffer &responseBuffer);
	bool ReadOSAPResponse(TTPMBuffer &responseBuffer);
	bool ReadOIAPResponse(TTPMBuffer &responseBuffer);	

	bool GetRandom(unsigned char* pOutputBuffer, unsigned long outputBufferLength);

	bool SendOIAPAuthentication();
	bool SendOSAPAuthentication(TPM_ENTITY_TYPE entityType, unsigned long entityHandle, const TPM_DIGEST &entityUsageSecret);
	bool SendDataOSAPAuthentication(TPM_ENTITY_TYPE entityType, unsigned long entityHandle, const TPM_DIGEST &entityUsageSecret);
	
	void CalculateEncUsageSecret(const TPM_DIGEST& authData, TPM_DIGEST &encAuthData);
	void CalculateEncMigrationSecret(const TPM_DIGEST& authData, TPM_DIGEST &encAuthData);

	void WriteOIAPFooter(TTPMBuffer &requestBuffer, TPM_DIGEST &usageSecret);
	void WriteOSAPFooter(TTPMBuffer &requestBuffer);	
	void WriteDataOSAPFooter(TTPMBuffer &requestBuffer, TPM_DIGEST &usageSecret);
	

	void GetBlobPassword(TPM_DIGEST &blobPassword);


};

#endif