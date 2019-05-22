#include "TTPM.h"
#include "TTPMAttribute.h"
#include "TTPMAttributeList.h"
#include "TTPMChannel.h"
#include "TTPMBuffer.h"

TTPM::TTPM(TTPMChannel *pChannel)
{
	m_pChannel = pChannel;
	m_ulError = 0;

	m_bTpmActive = false;
	m_bTpmOwnerSet = false;
	m_lTpmVersion = 0;
	m_lTpmVendor = 0;

	m_OIAP_continue = false;
	m_OIAP_authHandle = 0;
	memset(&m_OIAP_nonceOdd, 0, sizeof(m_OIAP_nonceOdd));
	memset(&m_OIAP_authLastNonceEven, 0, sizeof(m_OIAP_authLastNonceEven));

	m_OSAP_continue = false;
	m_OSAP_authHandle = 0;
	memset(&m_OSAP_nonceOdd, 0, sizeof(m_OSAP_nonceOdd));
	memset(&m_OSAP_nonceEven, 0, sizeof(m_OSAP_nonceEven));
}

void TTPM::SetChannel(TTPMChannel *pChannel)
{
	m_pChannel = pChannel;	
}


/*******************************************************
 *   Init
 *   Checks if tpm communicates
 *
 *   Returns : TRUE  - tpm chip is present and enabled
 *           : FALSE - tpm chip is not working
 *
 ******************************************************/
bool TTPM::Init(TTPMAttributeList *props)
{
	if (m_pChannel==NULL)
	{
		return false;
	}

	bool result = ReadTPMVersion();
	if (!result)
	{
		return false;
	}

	unsigned char rnd[20];
	result = GetRandom((unsigned char*)&rnd, sizeof(rnd));
	if (result)
	{
		m_bTpmActive = true;
	}
	result = CheckTPMOwner();	
	return result;
}

/*******************************************************
 *   ReadTPMVersion
 *   Method returns tpm version info and fills internal
 *   members m_bTpmNotActive, m_lTpmVersion and m_lTpmVendor.
 *
 *   Returns        : TRUE if tpm responded correctly                  
 ******************************************************/
bool TTPM::ReadTPMVersion()
{
	//reads TPM version info 
	TTPMBuffer requestBuffer;	
	requestBuffer.WriteCommandHeader();
	requestBuffer.WriteUInt32(TPM_ORD_GetCapability, false);
	requestBuffer.WriteUInt32(TPM_CAP_VERSION_VAL, false);
	requestBuffer.WriteUInt32(0); //sub capability size = 0;
	requestBuffer.UpdateCommandHeaderSize();

	TTPMBuffer responseBuffer;
	bool result = SendTPMCommand(requestBuffer, responseBuffer);
	if (!result)
	{
		return false;
	}	

	//reads version info structure size
	unsigned long  structSize = responseBuffer.ReadUInt32();

	//reads version info structure
	unsigned short tag = responseBuffer.ReadUInt16();
	m_lTpmVersion = responseBuffer.ReadUInt32();
	unsigned short level = responseBuffer.ReadUInt16();
	unsigned char  revision = responseBuffer.ReadUInt8();
	responseBuffer.ReadBinaryData((unsigned char*)&m_lTpmVendor, 4);
	unsigned long  vendorDataSize = responseBuffer.ReadUInt16();
	unsigned char  vendorData[256];
	responseBuffer.ReadBinaryData((unsigned char*)&vendorData, vendorDataSize);	
	return true;
}

/*******************************************************
 *   ReadPubek
 *
 *   Method should read public key of EK (not debugged yet)
 *
 *   Returns        : TRUE if tpm responded correctly                  
 *******************************************************/
bool TTPM::ReadPubEK(unsigned char* pbKey, unsigned long* cbKey)
{
	TPM_NONCE nonceOdd;
	GetRandom((unsigned char*)nonceOdd.nonce, sizeof(nonceOdd.nonce));

	unsigned long ordinal = TPM_ORD_ReadPubek;

	//creates request
	TTPMBuffer requestBuffer;	
	requestBuffer.WriteCommandHeader();
	requestBuffer.WriteUInt32(ordinal);
	requestBuffer.WriteBinaryData((unsigned char*)&nonceOdd.nonce, sizeof(nonceOdd.nonce));
	requestBuffer.UpdateCommandHeaderSize();

	//sends command to tpm
	TTPMBuffer responseBuffer;
	bool result = SendTPMCommand(requestBuffer, responseBuffer);
	if (!result)
	{
		return false;
	}	

	//reads response
	unsigned long realKeySize = requestBuffer.GetDataCount()-2-4-4-20;
	if (realKeySize>*cbKey)
	{
		m_ulError = TPM_BUFFER_TOO_SMALL;
		return false;
	}

	TPM_DIGEST responseDigest;
	result = requestBuffer.ReadBinaryData(pbKey, realKeySize);
	result&= requestBuffer.ReadBinaryData(responseDigest.digest, sizeof(responseDigest.digest));
	if (!result)
	{
		m_ulError = TPM_INVALID_TPM_RESPONSE;
		return false;
	}

	TPM_DIGEST checksum;
	unsigned long returnCode = 0; 

	tpm_sha1_t sha;
	tpm_sha1_init(&sha);
	tpm_sha1_update(&sha, (unsigned char*)&returnCode, sizeof(returnCode));
	tpm_sha1_update(&sha, (unsigned char*)&ordinal, sizeof(ordinal));
	tpm_sha1_update(&sha, pbKey, realKeySize);
	tpm_sha1_update(&sha, checksum.digest, sizeof(checksum.digest));

	//reads version info structure size
	unsigned long  structSize = responseBuffer.ReadUInt32();

	//reads version info structure
	unsigned short tag = responseBuffer.ReadUInt16();
	m_lTpmVersion = responseBuffer.ReadUInt32();
	unsigned short level = responseBuffer.ReadUInt16();

	return true;
}

/*******************************************************
 *   CheckTPMOwner
 *
 *   Method checks if owner is installed. Internal property
 *   m_bTpmOnwerSet is set to TRUE if owner is installed.
 *
 *   Returns : TRUE if tpm responded correctly                  
 *******************************************************/
bool TTPM::CheckTPMOwner()
{
	//reads TPM version info 
	TTPMBuffer requestBuffer;	
	requestBuffer.WriteCommandHeader();
	requestBuffer.WriteUInt32(TPM_ORD_GetCapability, false);
	requestBuffer.WriteUInt32(TPM_CAP_PROPERTY, false);
	requestBuffer.WriteUInt32(4); //sub capability size = 4;
	requestBuffer.WriteUInt32(TPM_CAP_PROP_OWNER);
	requestBuffer.UpdateCommandHeaderSize();

	TTPMBuffer responseBuffer;
	bool result = SendTPMCommand(requestBuffer, responseBuffer);
	if (!result)
	{
		return false;
	}	
	unsigned long structSize = responseBuffer.ReadUInt32();
	if (structSize!=1)
	{
		return false;
	}
	unsigned char ownerIsInstalled = responseBuffer.ReadUInt8();
	m_bTpmOwnerSet = ownerIsInstalled!=0;
	return true;
}


void TTPM::InitHMAC(unsigned char* pBinaryData, unsigned long binaryDataLength)
{
	tpm_hmac_init(&m_HMAC, (const uint8_t*)pBinaryData, binaryDataLength);
}

void TTPM::UpdateHMAC(unsigned char* pBinaryData, unsigned long binaryDataLength)
{
	tpm_hmac_update(&m_HMAC, (const uint8_t*)pBinaryData, binaryDataLength);
}

void TTPM::FinishHMAC(unsigned char* pOutputBuffer)
{
	tpm_hmac_final(&m_HMAC, pOutputBuffer);
}

//---------------------------------------------------------
//   SendTPMCommand
//
//   Method transmits command data to TPM and receives response.
//   Also reads response header and stores error code returned
//   by TPM.
//
//   Returns        : TRUE if tpm returned no error code
//---------------------------------------------------------
bool TTPM::SendTPMCommand(TTPMBuffer& requestBuffer, TTPMBuffer &responseBuffer)
{
	const unsigned char* pRequest = requestBuffer.GetBufferPtr();
	unsigned long requestSize = requestBuffer.GetDataCount();

	unsigned char* pResponse = responseBuffer.GetBufferPtr();
	unsigned long responseSize = responseBuffer.GetBufferSize();

	bool result = m_pChannel->Transmit(pRequest, requestSize, pResponse, &responseSize);
	if (!result)
	{
		m_ulError = TPM_CHANNEL_ERROR_DETECTED;
		return false;
	}

	unsigned short commandType;
	unsigned long  returnCode;
	responseBuffer.ReadResponseHeader(commandType, returnCode);
	if (returnCode!=TPM_SUCCESS)
	{
		m_ulError = returnCode;
		return false;
	}
	return true;
}


void TTPM::WriteOSAPFooter(TTPMBuffer &requestBuffer)
{
	TPM_DIGEST inputParamDigest;
	requestBuffer.GetSHA1Digest(inputParamDigest);

	InitHMAC((unsigned char*)&m_OSAP_sharedSecret.nonce, sizeof(m_OSAP_sharedSecret.nonce));
	UpdateHMAC((unsigned char*)&inputParamDigest.digest, sizeof(inputParamDigest.digest));
	UpdateHMAC((unsigned char*)&m_OSAP_authLastNonceEven.nonce, sizeof(m_OSAP_authLastNonceEven.nonce));
	UpdateHMAC((unsigned char*)&m_OSAP_nonceOdd.nonce,  sizeof(m_OSAP_nonceOdd.nonce));
	UpdateHMAC((unsigned char*)&m_OSAP_continue, 1);
	FinishHMAC(m_OSAP_authData);		

	requestBuffer.WriteUInt32(m_OSAP_authHandle, false);
	requestBuffer.WriteBinaryData((unsigned char*)&m_OSAP_nonceOdd.nonce, sizeof(m_OSAP_nonceOdd.nonce), false);
	requestBuffer.WriteUInt8(m_OSAP_continue, false); 
	requestBuffer.WriteBinaryData((unsigned char*)&m_OSAP_authData, sizeof(m_OSAP_authData), false);
}

void TTPM::WriteOIAPFooter(TTPMBuffer &requestBuffer, TPM_DIGEST &usageSecret)
{
	TPM_DIGEST inputParamDigest;
	requestBuffer.GetSHA1Digest(inputParamDigest);

	InitHMAC(usageSecret.digest, sizeof(usageSecret.digest));
	UpdateHMAC(inputParamDigest.digest, sizeof(inputParamDigest.digest));
	UpdateHMAC(m_OIAP_authLastNonceEven.nonce, sizeof(m_OIAP_authLastNonceEven.nonce));
	UpdateHMAC(m_OIAP_nonceOdd.nonce, sizeof(m_OIAP_nonceOdd.nonce));
	UpdateHMAC((unsigned char*)&m_OIAP_continue, 1);
	FinishHMAC(m_OIAP_authData);

	requestBuffer.WriteUInt32(m_OIAP_authHandle, false);
	requestBuffer.WriteBinaryData(m_OIAP_nonceOdd.nonce, sizeof(m_OIAP_nonceOdd.nonce), false);
	requestBuffer.WriteUInt8(m_OIAP_continue, false);
	requestBuffer.WriteBinaryData((unsigned char*)&m_OIAP_authData, sizeof(m_OIAP_authData), false);
}


void TTPM::WriteDataOSAPFooter(TTPMBuffer &requestBuffer, TPM_DIGEST &usageSecret)
{
	TPM_DIGEST inputParamDigest;
	requestBuffer.GetSHA1Digest(inputParamDigest);

	InitHMAC((unsigned char*)&usageSecret.digest, sizeof(usageSecret.digest));
	UpdateHMAC((unsigned char*)&inputParamDigest.digest, sizeof(inputParamDigest.digest));
	UpdateHMAC((unsigned char*)&m_OSAP_authLastNonceEven.nonce, sizeof(m_OSAP_authLastNonceEven.nonce));
	UpdateHMAC((unsigned char*)&m_OSAP_nonceOdd.nonce,  sizeof(m_OSAP_nonceOdd.nonce));
	UpdateHMAC((unsigned char*)&m_OSAP_continue, 1);
	FinishHMAC(m_OSAP_authData);		

	requestBuffer.WriteUInt32(m_OSAP_authHandle, false);
	requestBuffer.WriteBinaryData((unsigned char*)&m_OSAP_nonceOdd.nonce, sizeof(m_OSAP_nonceOdd.nonce), false);
	requestBuffer.WriteUInt8(m_OSAP_continue, false); 
	requestBuffer.WriteBinaryData((unsigned char*)&m_OSAP_authData, sizeof(m_OSAP_authData), false);
}


//---------------------------------------------------------
//   ReadOSAPResponse
//
//   Each authorized command (with OSAP authorization) contains
//   some additional data at the end of the packet. Method
//   reads this data.
//
//   Returns        : TRUE if tpm returned no error code
//---------------------------------------------------------
bool TTPM::ReadOSAPResponse(TTPMBuffer &responseBuffer)
{
	if (responseBuffer.Eof())
	{
		//"unauthorized execution of authorized command"
		//
		// some commands dont return OSAP response if there
		// is authorization turned off for specific object.
		// This is normal therefore result is TRUE
		return true;
	}
	responseBuffer.ReadBinaryData((unsigned char*)m_OSAP_nonceEven.nonce, sizeof(m_OSAP_nonceEven.nonce));
	m_OSAP_continue = responseBuffer.ReadUInt8();
	TPM_AUTHDATA responseAuthData;
	bool result = responseBuffer.ReadBinaryData((unsigned char*)responseAuthData, sizeof(responseAuthData));
	if (!result)
	{
		m_ulError = TPM_INVALID_TPM_RESPONSE;
		return false;
	}
	return true;
}

/*******************************************************
 *   ReadOSAPResponse
 *
 *   Each authorized command (with OIAP authorization) contains
 *   some additional data at the end of the packet. Method reads 
 *   this data
 *
 *   Returns        : TRUE if tpm returned no error code
 *******************************************************/
bool TTPM::ReadOIAPResponse(TTPMBuffer &responseBuffer)
{
	if (responseBuffer.Eof())
	{
		//if command does not really need authorization,
		//returns errorCode = 0 and no OIAP response
		return true;
	}
	responseBuffer.ReadBinaryData((unsigned char*)m_OIAP_authLastNonceEven.nonce, sizeof(m_OIAP_authLastNonceEven.nonce));
	m_OSAP_continue = responseBuffer.ReadUInt8();
	TPM_AUTHDATA responseAuthData;
	bool result = responseBuffer.ReadBinaryData((unsigned char*)responseAuthData, sizeof(responseAuthData));
	if (!result)
	{
		m_ulError = TPM_INVALID_TPM_RESPONSE;
		return false;
	}
	return true;
}

/*******************************************************
 *   DoOIAPAuthentication
 *
 *   Method sends OIAP command to TPM. Stores received 
 *   authHandle and nonceEven.
 *
 *   Returns        : TRUE if tpm returned no error code
 *******************************************************/
bool TTPM::SendOIAPAuthentication()
{
	//continue session is disabled
	m_OIAP_continue = 0;
	
	//generates OIAP nonce first
	GetRandom((unsigned char*)&m_OIAP_nonceOdd.nonce, sizeof(m_OIAP_nonceOdd.nonce));

	TTPMBuffer requestBuffer;
	requestBuffer.WriteCommandHeader();
	requestBuffer.WriteUInt32(TPM_ORD_OIAP);
	requestBuffer.UpdateCommandHeaderSize();

	TTPMBuffer responseBuffer;
	bool result = SendTPMCommand(requestBuffer, responseBuffer);
	if (!result)
	{
		return false;
	}
	m_OIAP_authHandle = responseBuffer.ReadUInt32();
	responseBuffer.ReadBinaryData(m_OIAP_authLastNonceEven.nonce, sizeof(m_OIAP_authLastNonceEven.nonce));

	return true;
}

/*******************************************************
 *   SendOSAPAuthentication
 *
 *   Method sends OSAP command to TPM. Stores received 
 *   authHandle, nonceEven and nonceEvenOSAP.
 *
 *   Returns        : TRUE if tpm returned no error code
 *******************************************************/
bool TTPM::SendOSAPAuthentication(TPM_ENTITY_TYPE entityType, unsigned long entityHandle, const TPM_DIGEST &entityUsageSecret)
{
	//session will stop after finishing tpm command
	m_OSAP_continue = false;  

	//clearing OSAP shared secret
	memset(&m_OSAP_sharedSecret, 0, sizeof(m_OSAP_sharedSecret));

	//generates OSAP nonce first
	GetRandom((unsigned char*)&m_OSAP_nonceOdd.nonce, sizeof(m_OSAP_nonceOdd.nonce));

	//sends OSAP command
	TTPMBuffer requestBuffer;
	requestBuffer.WriteCommandHeader();
	requestBuffer.WriteUInt32(TPM_ORD_OSAP);
	requestBuffer.WriteUInt16(entityType, false);
	requestBuffer.WriteUInt32(entityHandle, false);
	requestBuffer.WriteBinaryData((unsigned char*)&m_OSAP_nonceOdd.nonce, sizeof(m_OSAP_nonceOdd.nonce), false);	
	requestBuffer.UpdateCommandHeaderSize();

	TTPMBuffer responseBuffer;
	bool result = SendTPMCommand(requestBuffer, responseBuffer);
	if (!result)
	{
		return false;
	}

	//reads TPM response
	m_OSAP_authHandle = responseBuffer.ReadUInt32();
	responseBuffer.ReadBinaryData(m_OSAP_authLastNonceEven.nonce, sizeof(m_OSAP_authLastNonceEven.nonce));
	result = responseBuffer.ReadBinaryData(m_OSAP_nonceEven.nonce, sizeof(m_OSAP_nonceEven.nonce));
	if (!result)
	{
		return false;
	}

    InitHMAC((unsigned char*)&entityUsageSecret.digest, sizeof(entityUsageSecret.digest));
	UpdateHMAC((unsigned char*)&m_OSAP_nonceEven.nonce, sizeof(m_OSAP_nonceEven.nonce));
	UpdateHMAC((unsigned char*)&m_OSAP_nonceOdd.nonce, sizeof(m_OSAP_nonceOdd.nonce));
	FinishHMAC((unsigned char*)&m_OSAP_sharedSecret.nonce);
	return true;
}


/*******************************************************
 *   SendOSAPAuthentication
 *
 *   Method sends OSAP command to TPM. Stores received 
 *   authHandle, nonceEven and nonceEvenOSAP.
 *
 *   Returns        : TRUE if tpm returned no error code
 *******************************************************/
bool TTPM::SendDataOSAPAuthentication(TPM_ENTITY_TYPE entityType, unsigned long entityHandle, const TPM_DIGEST &entityUsageSecret)
{
	//session will stop after finishing tpm command
	m_OSAP_dataContinue = false;

	//generates OSAP nonce first
	GetRandom((unsigned char*)&m_OSAP_datanonceOdd.nonce, sizeof(m_OSAP_datanonceOdd.nonce));

	//sends OSAP command
	TTPMBuffer requestBuffer;
	requestBuffer.WriteCommandHeader();
	requestBuffer.WriteUInt32(TPM_ORD_OSAP);
	requestBuffer.WriteUInt16(entityType, false);
	requestBuffer.WriteUInt32(entityHandle, false);
	requestBuffer.WriteBinaryData((unsigned char*)&m_OSAP_datanonceOdd.nonce, sizeof(m_OSAP_datanonceOdd.nonce), false);	
	requestBuffer.UpdateCommandHeaderSize();

	TTPMBuffer responseBuffer;
	bool result = SendTPMCommand(requestBuffer, responseBuffer);
	if (!result)
	{
		return false;
	}

	//reads TPM response
	m_OSAP_authHandle = responseBuffer.ReadUInt32();
	responseBuffer.ReadBinaryData(m_OSAP_dataLastNonceEven.nonce, sizeof(m_OSAP_dataLastNonceEven.nonce));
	result = responseBuffer.ReadBinaryData(m_OSAP_datanonceEven.nonce, sizeof(m_OSAP_datanonceEven.nonce));
	if (!result)
	{
		return false;
	}

	InitHMAC((unsigned char*)&entityUsageSecret.digest, sizeof(entityUsageSecret.digest));
	UpdateHMAC((unsigned char*)&m_OSAP_datanonceEven.nonce, sizeof(m_OSAP_datanonceEven.nonce));
	UpdateHMAC((unsigned char*)&m_OSAP_datanonceOdd.nonce, sizeof(m_OSAP_datanonceOdd.nonce));
	FinishHMAC((unsigned char*)&m_OSAP_dataSharedSecret.nonce);

	return true;
}

/*******************************************************--
 *   CalculateEncUsageSecret
 *
 *   Internal method - calculates encrypted usage secret 
 *
 *   authData:    usage secret
 *   encAuthData: returns encrypted usage secret
 *******************************************************/
void TTPM::CalculateEncUsageSecret(const TPM_DIGEST& authData, TPM_DIGEST &encAuthData)
{
	//calculation of encrypting mask 
	//(usageSecret and migrationSecret can not be sent as plain text)
	TPM_DIGEST encryptingMask;

	//original authData are xored by special mask
	//(see Authorization-Data Insertion Protocol - ADIP)
	tpm_sha1_t sha;
	tpm_sha1_init(&sha);
	tpm_sha1_update(&sha, (unsigned char*)&m_OSAP_sharedSecret.nonce, sizeof(m_OSAP_sharedSecret.nonce));
	tpm_sha1_update(&sha, (unsigned char*)&m_OSAP_authLastNonceEven.nonce, sizeof(m_OSAP_authLastNonceEven.nonce));
	tpm_sha1_final(&sha, (unsigned char*)&encryptingMask.digest);

	//XOR function is applied to AuthData, result is EncAuthData
	for(int i = 0; i<sizeof(TPM_DIGEST); i++)
	{
		encAuthData.digest[i] = authData.digest[i] ^ encryptingMask.digest[i];
	}
}

/*******************************************************
 *   CalculateEncMigrationSecret
 *
 *   Internal method - calculates encrypted usage secret 
 *   (called by method CreateWrapKey)
 *
 *   authData:    migration secret
 *   encAuthData: returns encrypted migration secret
 *******************************************************/
void TTPM::CalculateEncMigrationSecret(const TPM_DIGEST& authData, TPM_DIGEST &encAuthData)
{
	//calculation of encrypting mask 
	TPM_DIGEST encryptingMask;

	tpm_sha1_t sha;
	tpm_sha1_init(&sha);
	tpm_sha1_update(&sha, (unsigned char*)&m_OSAP_sharedSecret.nonce, sizeof(m_OSAP_sharedSecret.nonce));
	tpm_sha1_update(&sha, (unsigned char*)&m_OSAP_nonceOdd.nonce, sizeof(m_OSAP_nonceOdd.nonce));
	tpm_sha1_final(&sha, (unsigned char*)&encryptingMask.digest);

	//XOR function is applied to AuthData, result is EncAuthData
	for(int i = 0; i<sizeof(TPM_DIGEST); i++)
	{
		encAuthData.digest[i] = authData.digest[i] ^ encryptingMask.digest[i];
	}
}

/*******************************************************
 *   GetRandom
 *
 *   Method sends TPM_GetRandom command to TPM 
 *   and received byte array of random data.
 * 
 *   pOutputBuffer  : output buffer for random data
 *                  : requested number of random data
 *   Returns        : TRUE if tpm returned no error code
 *******************************************************/
bool TTPM::GetRandom(unsigned char* pOutputBuffer, unsigned long outputBufferLength)
{
	//reads TPM version info 
	TTPMBuffer requestBuffer;	
	requestBuffer.WriteCommandHeader();
	requestBuffer.WriteUInt32(TPM_ORD_GetRandom, false);
	requestBuffer.WriteUInt32(outputBufferLength, false); //number of random data
	requestBuffer.UpdateCommandHeaderSize();

	TTPMBuffer responseBuffer;
	bool result = SendTPMCommand(requestBuffer, responseBuffer);
	if (result)
	{
		unsigned randomBytesSize = responseBuffer.ReadUInt32();
		if (randomBytesSize==outputBufferLength)
		{
			result = responseBuffer.ReadBinaryData(pOutputBuffer, outputBufferLength);
		} else {
			//data size returned by TPM is different than outputBufferLength
			result = false;
		}		
	}	
	return result;	
}

/*******************************************************
 *   GetProperty
 *
 *   Method reads properties of TPM class:
 *       TPM_PROP_TPM_ACTIVE  
 *       TPM_PROP_TPM_OWNER_NOT_SET
 *       TPM_PROP_TPM_VENDOR  
 *       TPM_PROP_TPM_VERSION 
 *
 *   pOutputBuffer  : output buffer for random data
 *                  : requested number of random data
 *   Returns        : TRUE if tpm returned no error code
 *******************************************************/
bool TTPM::GetProperty(TTPMAttributeList *props)
{
	TTPMAttribute* pAttr = props->first();
	props->set(TPM_PROP_TPM_NOT_ACTIVE, m_bTpmActive);
	props->set(TPM_PROP_TPM_OWNER_NOT_SET, m_bTpmOwnerSet);
	props->set(TPM_PROP_TPM_VENDOR, m_lTpmVendor);
	props->set(TPM_PROP_TPM_VERSION, m_lTpmVersion);
	return true;
}

/*******************************************************
 *   ChangePassword
 *
 *   Method should change owner password
 *
 *   props[TPM_ATTR_USAGE_SECRET] : current password (TPM_DIGEST*)
 *   props[TPM_ATTR_NEW_OWNER_SECRET] : new password (TPM_DIGEST*)
 *   Returns           : TRUE if tpm returned no error code
 *******************************************************/
bool TTPM::ChangePassword(TTPMAttributeList *props)
{
	//usage secret (belonging to SRK key)
	TPM_DIGEST usageSecret;
	memset(&usageSecret.digest, 0, sizeof(usageSecret.digest));
	if (props!=NULL)
	{
		TTPMAttribute* parentUsageSecretAttr = props->find(TPM_ATTR_USAGE_SECRET);
		if (parentUsageSecretAttr!=NULL)
		{
			//caller method must correctly alloc and unalloc parentKey
			unsigned char * pAttrValue = parentUsageSecretAttr->getvalueAsPtr();
			if (pAttrValue!=NULL) memcpy((unsigned char*)&usageSecret.digest, pAttrValue, sizeof(TPM_DIGEST));
		}
	}	
	//new tpm owner password
	TPM_DIGEST newOwnerPassword;
	memset(&newOwnerPassword.digest, 0, sizeof(newOwnerPassword.digest));
	if (props!=NULL)
	{
		TTPMAttribute* newOwnerPasswordAttr = props->find(TPM_ATTR_NEW_USAGE_SECRET);
		if (newOwnerPasswordAttr!=NULL)
		{
			//caller method must correctly alloc and unalloc parentKeyNonce
			unsigned char *pAttrValue = newOwnerPasswordAttr->getvalueAsPtr();
			if (pAttrValue!=NULL) memcpy((unsigned char*)&newOwnerPassword.digest, pAttrValue, sizeof(TPM_NONCE));
		}
	}	

	bool osapSent = SendOSAPAuthentication(TPM_ET_SRK, TPM_KH_SRK, usageSecret);
	if (!osapSent)
	{
		return false;
	}

	TPM_DIGEST encryptedOwnerPassword; //new onwer password
	CalculateEncUsageSecret(newOwnerPassword, encryptedOwnerPassword);

	//reads TPM version info 
	TTPMBuffer requestBuffer;	
	requestBuffer.WriteCommandHeader(TPM_TAG_RQU_AUTH1_COMMAND);
	requestBuffer.WriteUInt32(TPM_ORD_ChangeAuthOwner);
	requestBuffer.WriteUInt16(TPM_PID_ADCP);
	requestBuffer.WriteBinaryData((unsigned char*)&encryptedOwnerPassword.digest, sizeof(encryptedOwnerPassword.digest));
	requestBuffer.WriteUInt16(TPM_ET_OWNER);	
	WriteOSAPFooter(requestBuffer);
	requestBuffer.UpdateCommandHeaderSize();

	TTPMBuffer responseBuffer;
	bool result = SendTPMCommand(requestBuffer, responseBuffer);
	if (!result)
	{
		return false;
	}
	return ReadOSAPResponse(responseBuffer);	

}

/*******************************************************
 *   TakeOwnership
 *
 *   Method should take ownership and set owner AuthData value
 *
 *   props[TPM_PROP_PASSWORD] : new password (const char*)
 *   Returns           : TRUE if tpm returned no error code
 *******************************************************/
bool TTPM::TakeOwnership(TPM_DIGEST& ownerAuth, TPM_DIGEST& srkAuth)
{
	unsigned char pubEK[2048];
	unsigned long pubEKSize = sizeof(pubEK);

	ReadPubEK((unsigned char*)&pubEK, (unsigned long*)pubEKSize);


	unsigned char* encryptedOwnerAuth;
	unsigned long  encryptedOwnerAuthSize;	

	unsigned char* encryptedSrkAuth;
	unsigned long  encryptedSrkAuthSize;

	TTPMAttributeList props;

	bool result = SendOIAPAuthentication();
	if (!result)
	{
		return false;
	}

	TTPMBuffer requestBuffer;
	requestBuffer.WriteCommandHeader(TPM_TAG_RQU_AUTH1_COMMAND);
	requestBuffer.WriteUInt32(TPM_ORD_TakeOwnership);
	requestBuffer.WriteUInt16(TPM_PID_OWNER);
	requestBuffer.WriteUInt32(encryptedOwnerAuthSize);
	requestBuffer.WriteBinaryData(encryptedOwnerAuth, encryptedOwnerAuthSize);
	requestBuffer.WriteUInt32(encryptedSrkAuthSize);
	requestBuffer.WriteBinaryData(encryptedSrkAuth, encryptedSrkAuthSize);	

	TPM_KEY key;
	FillKeyParams(key, &props);
	WriteKeyParams(key, requestBuffer);

	WriteOIAPFooter(requestBuffer, ownerAuth);
	requestBuffer.UpdateCommandHeaderSize();

	TTPMBuffer responseBuffer;
	result = SendTPMCommand(requestBuffer, responseBuffer);
	if (!result)
	{
		return false;
	}
	return ReadOIAPResponse(responseBuffer);
}

/*******************************************************
 *   Reset
 *
 *   Method resets tpm owner (knowledge of tpm password is needed)
 *
 *   Returns           : Nothing
 *******************************************************/
bool TTPM::Reset(TTPMAttributeList* props)
{
	TPM_DIGEST usageSecret;
	memset(&usageSecret.digest, 0, sizeof(usageSecret.digest));
	if (props!=NULL)
	{
		TTPMAttribute* parentUsageSecretAttr = props->find(TPM_ATTR_USAGE_SECRET);
		if (parentUsageSecretAttr!=NULL)
		{
			//caller method must correctly alloc and unalloc parentKey
			unsigned char * pAttrValue = parentUsageSecretAttr->getvalueAsPtr();
			if (pAttrValue!=NULL) memcpy((unsigned char*)&usageSecret.digest, pAttrValue, sizeof(TPM_DIGEST));
		}
	}	

	SendOIAPAuthentication();

	//reads TPM version info 
	TTPMBuffer requestBuffer;	
	requestBuffer.WriteCommandHeader(TPM_TAG_RQU_AUTH1_COMMAND);
	requestBuffer.WriteUInt32(TPM_ORD_OwnerClear);	

	WriteOIAPFooter(requestBuffer, usageSecret);
	requestBuffer.UpdateCommandHeaderSize();

	TTPMBuffer responseBuffer;
	bool result = SendTPMCommand(requestBuffer, responseBuffer);
	if (!result)
	{
		return false;
	}
	return ReadOIAPResponse(responseBuffer);
}


/*******************************************************
 *   FillKeyParams - helper method used by GenerateKey
 *
 *   Method set default key params 
 *
 *   keyParams : key structure to fill
 *   props     : values to change
 *******************************************************/
void TTPM::FillKeyParams(TPM_KEY &key, TTPMAttributeList *props)
{	
	//default key properties
	memset(&key,0,sizeof(key));
	key.tag = 0x0101;
    key.fill = 0x0103;
	key.keyUsage = TPM_KEY_STORAGE;// | TPM_KEY_BIND | TPM_KEY_MIGRATE;
	key.keyFlags = TPM_KEY_FLAG_MIGRATABLE | TPM_KEY_FLAG_VOLATILE;
	key.authDataUsage = TPM_AUTH_NEVER;
	key.algorithmParms.algorithmID = TPM_ALG_RSA;
	key.algorithmParms.sigScheme = TPM_SS_NONE;
	key.algorithmParms.encScheme = TPM_ES_NONE;
	key.algorithmParms.parmSize = sizeof(TPM_RSA_KEY_PARMS);
	key.algorithmParms.parms.rsa.numPrimes = 2;
	key.algorithmParms.parms.rsa.keyLength = 2048;
	key.algorithmParms.parms.rsa.exponentSize = 0;

	//change default values
	if (props!=NULL)
	{
		props->get(TPM_ATTR_KEY_USAGE, key.keyUsage);
		props->get(TPM_ATTR_KEY_FLAGS, key.keyFlags);
		props->get(TPM_ATTR_KEY_AUTHTYPE, key.authDataUsage);
	}
	switch(key.keyUsage)
	{
		case TPM_KEY_IDENTITY:
		case TPM_KEY_SIGNING: key.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1; break;
		case TPM_KEY_AUTHCHANGE:
		case TPM_KEY_BIND:
		case TPM_KEY_STORAGE: key.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1; break;
	}
}

void TTPM::WriteKeyParams(TPM_KEY& keyParams, TTPMBuffer &requestBuffer)
{
	//key info
	requestBuffer.WriteUInt16(keyParams.tag);
	requestBuffer.WriteUInt16(keyParams.fill);
	requestBuffer.WriteUInt16(keyParams.keyUsage);
	requestBuffer.WriteUInt32(keyParams.keyFlags);
	requestBuffer.WriteUInt8(keyParams.authDataUsage);
	requestBuffer.WriteUInt32(keyParams.algorithmParms.algorithmID);
	requestBuffer.WriteUInt16(keyParams.algorithmParms.encScheme);
	requestBuffer.WriteUInt16(keyParams.algorithmParms.sigScheme);
	//rsa key info
	requestBuffer.WriteUInt32(12); 
	requestBuffer.WriteUInt32(keyParams.algorithmParms.parms.rsa.keyLength);
	requestBuffer.WriteUInt32(keyParams.algorithmParms.parms.rsa.numPrimes);	
	requestBuffer.WriteUInt32(keyParams.algorithmParms.parms.rsa.exponentSize);

	requestBuffer.WriteUInt32(0); //no PCR info

	//pcrInfo - No PCR is selected
	/*
	requestBuffer.WriteUInt32(44); //pcr info
	unsigned long pcrSelection = 0;
	TPM_DIGEST digestAtRelease; memset((unsigned char*)digestAtRelease.digest, 0, sizeof(digestAtRelease.digest));
	requestBuffer.WriteBinaryData((unsigned char*)&digestAtRelease.digest, sizeof(digestAtRelease.digest));
	TPM_DIGEST digestAtCreation; memset((unsigned char*)digestAtCreation.digest, 0, sizeof(digestAtCreation.digest));
	requestBuffer.WriteBinaryData((unsigned char*)&digestAtCreation.digest, sizeof(digestAtCreation.digest));
	*/

	//endof pcrInfo
	requestBuffer.WriteUInt32(0); //publicKeySize = 0 (no public key)
	requestBuffer.WriteUInt32(0); //dataSize = 0 (no data)
	//end of key info
}

/*******************************************************
 *   GenerateKey
 *
 *   Method generates new key
 *
 *   Returns : TRUE if tpm returned no error code
 *******************************************************/
bool TTPM::GenerateKey(unsigned char *pbdata, unsigned long* cbdata, TTPMAttributeList *props)
{
	//parent key
	unsigned long hParentKey = TPM_KH_SRK; //STORAGE key is used by default
	if (props!=NULL)
	{
		props->get(TPM_ATTR_PARENT_KEY_HANDLE, hParentKey);
	}

	//parent usage secret
	//-you can't create sub keys etc. without knowing parent usage secret,
	//but it possible to turn off using parent usage secret for specific key instances
	TPM_DIGEST parentKeyUsageSecret;
	memset(&parentKeyUsageSecret.digest, 0, sizeof(parentKeyUsageSecret.digest));
	if (props!=NULL)
	{
		TTPMAttribute* parentUsageSecretAttr = props->find(TPM_ATTR_USAGE_SECRET);
		if (parentUsageSecretAttr!=NULL)
		{
			//caller method must correctly alloc and unalloc parentKeyNonce
			unsigned char * pAttrValue = parentUsageSecretAttr->getvalueAsPtr();
			if (pAttrValue!=NULL) memcpy((unsigned char*)&parentKeyUsageSecret.digest, pAttrValue, sizeof(TPM_DIGEST));
		}
	}

	bool result = SendOSAPAuthentication(TPM_ET_KEY, hParentKey, parentKeyUsageSecret);
	if (!result)
	{
		return false;
	}
	
	//defines if new key requires authentication for each operation
	unsigned char bNewKeyAuthNeeded = 0;
	//if key authentication is enabled, 
	//then there are two secrets:
	//  - usage secret (each operation related to this parent key needs authentication)
	//  - migration secret (each key migration needs authentication)
	TPM_DIGEST usageEncAuthData; 
	memset(&usageEncAuthData, 0, sizeof(usageEncAuthData));
	TPM_DIGEST migrationEncAuthData; 
	memset(&migrationEncAuthData, 0, sizeof(migrationEncAuthData));
	if (props!=NULL)
	{
		TTPMAttribute* newKeyAuthTypeAttr = props->find(TPM_ATTR_KEY_AUTHTYPE);
		if (newKeyAuthTypeAttr!=NULL)
		{
			bNewKeyAuthNeeded = (unsigned char)newKeyAuthTypeAttr->getvalue();
			if (bNewKeyAuthNeeded)
			{
				TTPMAttribute* newKeyUsageSecretAttr = props->find(TPM_ATTR_KEY_USAGE_SECRET);
				if (newKeyUsageSecretAttr!=NULL)
				{
					//caller must correctly alloc and unalloc TPM_NONCE
					TPM_DIGEST* pUsageSecret = (TPM_DIGEST*)newKeyUsageSecretAttr->getvalueAsPtr();
					if (pUsageSecret!=NULL)	CalculateEncUsageSecret(*pUsageSecret, usageEncAuthData);
				}
				TTPMAttribute* newKeyMigrationSecretAttr = props->find(TPM_ATTR_KEY_MIGRATION_SECRET);
				if (newKeyMigrationSecretAttr!=NULL)
				{
					//caller must correctly alloc and unalloc TPM_NONCE
					TPM_DIGEST* pMigrationSecret = (TPM_DIGEST*)newKeyMigrationSecretAttr->getvalueAsPtr();
					if (pMigrationSecret!=NULL)	CalculateEncMigrationSecret(*pMigrationSecret, migrationEncAuthData);
				}
			}		
		}
	}

	//command header
	TTPMBuffer requestBuffer;	
	requestBuffer.WriteCommandHeader(TPM_TAG_RQU_AUTH1_COMMAND);
	requestBuffer.WriteUInt32(TPM_ORD_CreateWrapKey);
	requestBuffer.WriteUInt32(hParentKey, false);
	requestBuffer.WriteBinaryData((unsigned char*)&usageEncAuthData.digest,  sizeof(usageEncAuthData.digest));
	requestBuffer.WriteBinaryData((unsigned char*)&migrationEncAuthData.digest, sizeof(migrationEncAuthData.digest));

	
	//default rsa key params
	TPM_KEY keyParams;	
	FillKeyParams(keyParams, props);
	WriteKeyParams(keyParams, requestBuffer);
	WriteOSAPFooter(requestBuffer);

	//command header update
	requestBuffer.UpdateCommandHeaderSize();

	//send command
	TTPMBuffer responseBuffer(2048);
	result = SendTPMCommand(requestBuffer, responseBuffer);
	if (!result)
	{
		return false;
	}	

	unsigned long realKeySize = responseBuffer.GetDataCount() - 2 - 4 - 4 - 20 - 1 -20;
	if (*cbdata<realKeySize)
	{
		m_ulError = TPM_BUFFER_TOO_SMALL;
		return false;
	}
		
	result = responseBuffer.ReadBinaryData(pbdata, realKeySize);
	if (!result)
	{
		*cbdata = 0;
		return false;
	}

	*cbdata = realKeySize;
	return ReadOSAPResponse(responseBuffer);
}


/*******************************************************
 *   Import key
 *   Method can load key blob saved by method ExportKey 
 *   (not debugged)
 *
 *   hKey           : returns new key handle
 *   pbData			: key blob data
 *   cbData         : key blob data size
 *   Returns        : TRUE  - import was succesful
 *******************************************************/
bool TTPM::ImportKey(unsigned long *hKey,const unsigned char *pbdata,unsigned long cbdata, TTPMAttributeList *props)
{
	unsigned long hParentKey = TPM_KH_SRK;
	if (props!=NULL)
	{
		props->get(TPM_ATTR_PARENT_KEY_HANDLE, hParentKey);
	}

	//parent usage secret
	//-you can't create sub keys etc. without knowing parent usage secret,
	//but it possible to turn off using parent usage secret for specific key instances
	TPM_DIGEST parentKeyUsageSecret;
	memset(&parentKeyUsageSecret.digest, 0, sizeof(parentKeyUsageSecret.digest));
	if (props!=NULL)
	{
		TTPMAttribute* parentUsageSecretAttr = props->find(TPM_ATTR_USAGE_SECRET);
		if (parentUsageSecretAttr!=NULL)
		{
			//caller method must correctly alloc and unalloc parentKeyNonce
			unsigned char * pAttrValue = parentUsageSecretAttr->getvalueAsPtr();
			if (pAttrValue!=NULL) memcpy((unsigned char*)&parentKeyUsageSecret.digest, pAttrValue, sizeof(TPM_DIGEST));
		}
	}

	unsigned char sessionType = TPM_ORD_OSAP;
	if (props!=NULL)
	{
		props->get(TPM_ATTR_SESSION_TYPE, sessionType);
	}

	bool result = false;
	switch(sessionType)
	{
		case TPM_ORD_OSAP:result = SendOSAPAuthentication(TPM_ET_KEY, hParentKey, parentKeyUsageSecret); break;
		case TPM_ORD_OIAP:result = result = SendOIAPAuthentication(); break;
		default:
			m_ulError = TPM_UNKNOWN_SESSION_TYPE;
			return false;
	}
	if (!result)
	{
		return false;
	}

	TTPMBuffer requestBuffer;
	requestBuffer.WriteCommandHeader(TPM_TAG_RQU_AUTH1_COMMAND);
	requestBuffer.WriteUInt32(TPM_ORD_LoadKey2);
	requestBuffer.WriteUInt32(hParentKey, false);
	requestBuffer.WriteBinaryData((unsigned char*)pbdata, cbdata);

	switch(sessionType)
	{
		case TPM_ORD_OSAP: WriteOSAPFooter(requestBuffer); break;
		case TPM_ORD_OIAP: WriteOIAPFooter(requestBuffer, parentKeyUsageSecret); break;
	}
	
	requestBuffer.UpdateCommandHeaderSize();

	TTPMBuffer responseBuffer;
	result = SendTPMCommand(requestBuffer, responseBuffer);
	if (!result)
	{
		return false;
	}	

	unsigned long newKeyHandle = responseBuffer.ReadUInt32();
	*hKey = newKeyHandle;
	return ReadOSAPResponse(responseBuffer);
}

/*******************************************************
 *   Export key
 *   Method should export key as blob (not implemented)
 *
 *   hKey           : handle of key to export
 *   pbData			: returns key blob data
 *   cbData         : returns key blob data size
 *   Returns        : TRUE if export was succesful
 *******************************************************/
bool TTPM::ExportKey(unsigned long hKey,unsigned char *pbdata,unsigned long *cbdata,TTPMAttributeList *props)
{
	unsigned long parentKeyHandle = TPM_KH_SRK;
	if (props!=NULL)
	{
		TTPMAttribute* parentKeyAttr = props->find(TPM_ATTR_PARENT_KEY_HANDLE);
		if (parentKeyAttr!=NULL)
		{
			parentKeyHandle = parentKeyAttr->getvalue();
		}
	}

	//parent usage secret
	TPM_DIGEST parentKeyUsageSecret;
	memset(&parentKeyUsageSecret.digest, 0, sizeof(parentKeyUsageSecret.digest));
	if (props!=NULL)
	{
		TTPMAttribute* parentUsageSecretAttr = props->find(TPM_ATTR_USAGE_SECRET);
		if (parentUsageSecretAttr!=NULL)
		{
			//caller method must correctly alloc and unalloc parentKeyNonce
			unsigned char * pAttrValue = parentUsageSecretAttr->getvalueAsPtr();
			if (pAttrValue!=NULL) memcpy((unsigned char*)&parentKeyUsageSecret.digest, pAttrValue, sizeof(TPM_DIGEST));
		}
	}

	bool osapSent = SendOSAPAuthentication(TPM_ET_KEY, hKey, parentKeyUsageSecret);
	if (!osapSent)
	{
		return false;
	}

	unsigned char publicKey[2048];
	unsigned long publicKeySize = sizeof(publicKey);
	GetPublicKey(hKey, (unsigned char*)&publicKey, &publicKeySize);

	TTPMBuffer requestBuffer;	
	requestBuffer.WriteCommandHeader(TPM_TAG_RQU_AUTH1_COMMAND);
	//
	//todo: build export command
	//
	requestBuffer.UpdateCommandHeaderSize();

	TTPMBuffer responseBuffer(2048);
	bool result = SendTPMCommand(requestBuffer, responseBuffer);
	if (!result)
	{
		return false;
	}	

	///todo: read response data

	return ReadOSAPResponse(responseBuffer);
}

/*******************************************************
 *   Encrypt
 *   Method encrypts data
 *
 *   keyHandle      : handle of RSA key
 *   pbData			: returns key blob data
 *   cbData         : returns key blob data size
 *   Returns        : TRUE if export was succesful
 *******************************************************/
bool TTPM::Seal(unsigned long keyHandle, unsigned char* pbData, unsigned long cbData, unsigned char* pbOutput, unsigned long* cbOutput, TTPMAttributeList *props)
{
	//usage secret (belonging to key)
	TPM_DIGEST usageSecret;
	memset(&usageSecret.digest, 0, sizeof(usageSecret.digest));
	if (props!=NULL)
	{
		TTPMAttribute* parentUsageSecretAttr = props->find(TPM_ATTR_USAGE_SECRET);
		if (parentUsageSecretAttr!=NULL)
		{
			//caller method must correctly alloc and unalloc parentKey
			unsigned char * pAttrValue = parentUsageSecretAttr->getvalueAsPtr();
			if (pAttrValue!=NULL) memcpy((unsigned char*)&usageSecret.digest, pAttrValue, sizeof(TPM_DIGEST));
		}
	}		
	SendOSAPAuthentication(TPM_ET_KEY, keyHandle, usageSecret);

	TPM_DIGEST blobUsageSecret;
	GetBlobPassword(blobUsageSecret);	
	memset(blobUsageSecret.digest, 0, sizeof(blobUsageSecret.digest));

	TPM_DIGEST encBlobUsageSecret;
	CalculateEncUsageSecret(blobUsageSecret, encBlobUsageSecret);
	
	TPM_PCR_INFO_SHORT pcrInfo;
	memset(&pcrInfo, 0, sizeof(TPM_PCR_INFO_SHORT));
	pcrInfo.pcrSelection.sizeOfSelect = 1;
	pcrInfo.pcrSelection.pcrSelect[0] = 1; //selects PCR0 only (PCR0 = mainboard type)	
			
	TTPMBuffer requestBuffer(cbData+256);	
	requestBuffer.WriteCommandHeader(TPM_TAG_RQU_AUTH1_COMMAND);
	requestBuffer.WriteUInt32(TPM_ORD_Seal);
	requestBuffer.WriteUInt32(keyHandle, false);
	requestBuffer.WriteBinaryData(encBlobUsageSecret.digest, sizeof(TPM_DIGEST));
	//PCRInfo	
	requestBuffer.WriteUInt32(0);
	/*
	requestBuffer.WriteUInt32(4); //No PCR Info
	requestBuffer.WriteUInt16(2); //size of PCR selection
	requestBuffer.WriteUInt16(1); //selects PCR0
	*/
	//end of PCRInfo
	requestBuffer.WriteUInt32(cbData);
	requestBuffer.WriteBinaryData(pbData, cbData);
	WriteOSAPFooter(requestBuffer);
	requestBuffer.UpdateCommandHeaderSize();

	TTPMBuffer responseBuffer(cbData+768);
	bool result = SendTPMCommand(requestBuffer, responseBuffer);
	unsigned long realDataSize = responseBuffer.GetDataCount()-responseBuffer.GetReadingPosition() - 20 - 1 - 20;
	if (*cbOutput<realDataSize)
	{
		m_ulError = TPM_BUFFER_TOO_SMALL;
		*cbOutput = 0;
		return false;
	}
	result = responseBuffer.ReadBinaryData(pbOutput, realDataSize);
	*cbOutput = realDataSize;	
	if (!result)
	{
		m_ulError = TPM_INVALID_TPM_RESPONSE;
		return false;
	}
	return ReadOSAPResponse(responseBuffer);
}

/*******************************************************
 *   Decrypt
 *   Method should decrypt data by selected key
 *
 *   keyHandle      : handle of RSA key
 *   pbData			: returns key blob data
 *   cbData         : returns key blob data size
 *   Returns        : TRUE if export was succesful
 *******************************************************/
bool TTPM::Unseal(unsigned long keyHandle, unsigned char* pbData, unsigned long cbData, unsigned char* pbOutput, unsigned long* cbOutput, TTPMAttributeList *props)
{
	//usage secret
	TPM_DIGEST usageSecret;
	memset(&usageSecret.digest, 0, sizeof(usageSecret.digest));
	if (props!=NULL)
	{
		TTPMAttribute* parentUsageSecretAttr = props->find(TPM_ATTR_USAGE_SECRET);
		if (parentUsageSecretAttr!=NULL)
		{
			//caller method must correctly alloc and unalloc parentKey
			unsigned char * pAttrValue = parentUsageSecretAttr->getvalueAsPtr();
			if (pAttrValue!=NULL) memcpy((unsigned char*)&usageSecret.digest, pAttrValue, sizeof(TPM_DIGEST));
		}
	}	
	TPM_DIGEST blobUsageSecret;
	GetBlobPassword(blobUsageSecret);
	memset(blobUsageSecret.digest, 0, sizeof(blobUsageSecret.digest));
	
	SendOSAPAuthentication(TPM_ET_KEY, keyHandle, usageSecret);
	SendOIAPAuthentication();

	TTPMBuffer requestBuffer(cbData+768);	
	requestBuffer.WriteCommandHeader(TPM_TAG_RQU_AUTH2_COMMAND);
	requestBuffer.WriteUInt32(TPM_ORD_Unseal);
	requestBuffer.WriteUInt32(keyHandle, false);
	requestBuffer.WriteBinaryData(pbData, cbData);	
	WriteOSAPFooter(requestBuffer);	
	WriteOIAPFooter(requestBuffer, blobUsageSecret);
	requestBuffer.UpdateCommandHeaderSize();

	TTPMBuffer responseBuffer(cbData+512);
	bool result = SendTPMCommand(requestBuffer, responseBuffer);
	if (!result)
	{
		return false;
	}	

	unsigned long dataSize = responseBuffer.ReadUInt32();
	if (*cbOutput<dataSize)
	{
		*cbOutput = 0;
		m_ulError = TPM_BUFFER_TOO_SMALL;
		return false;
	}
	result = responseBuffer.ReadBinaryData(pbOutput, dataSize);
	if (!result)
	{
		m_ulError = TPM_INVALID_TPM_RESPONSE;
		return false;
	}
	result &= ReadOSAPResponse(responseBuffer);
	result &= ReadOIAPResponse(responseBuffer);
	return result;
}

/*******************************************************
 *   Sign
 *   Method should decrypt data by selected key
 *
 *   keyHandle      : handle of RSA key
 *   pbData			: data to sign
 *   cbData         : datasize
 *   pbSign         : returns sign data
 *   cbSign:        : returns sign size
 *   props	        : properties
 *   Returns        : TRUE if export was succesful
 *******************************************************/
bool TTPM::Sign(unsigned long keyHandle, unsigned char* pbData, unsigned long cbData, unsigned char* pbSign, unsigned long *cbSign, TTPMAttributeList *props)
{	
	TPM_DIGEST usageSecret;
	memset(usageSecret.digest, 0, sizeof(usageSecret));
	if (props!=NULL)
	{
		TTPMAttribute* usageSecretAttr = props->find(TPM_ATTR_USAGE_SECRET);
		if (usageSecretAttr!=NULL)
		{
			unsigned char* pUsageSecret = usageSecretAttr->getvalueAsPtr();
			memcpy(&usageSecret, pUsageSecret, sizeof(usageSecret));
		}
	}

	bool osapSent = SendOSAPAuthentication(TPM_ET_KEYHANDLE, keyHandle, usageSecret);
	if (!osapSent)
	{
		return false;
	}
	
	//input parameters
	TTPMBuffer requestBuffer;	
	requestBuffer.WriteCommandHeader(TPM_TAG_RQU_AUTH1_COMMAND);
	requestBuffer.WriteUInt32(TPM_ORD_Sign);
	requestBuffer.WriteUInt32(keyHandle, false);
	requestBuffer.WriteUInt32(cbData);
	requestBuffer.WriteBinaryData(pbData, cbData);

	//sha1 digest calculation
	WriteOSAPFooter(requestBuffer);
	
	//command header update
	requestBuffer.UpdateCommandHeaderSize();

	//send command
	TTPMBuffer responseBuffer(2048);
	bool result = SendTPMCommand(requestBuffer, responseBuffer);
	if (!result)
	{
		return false;
	}	
	unsigned long signatureSize = responseBuffer.ReadUInt32();
	if (signatureSize>*cbSign)
	{
		m_ulError = TPM_BUFFER_TOO_SMALL;
		return false;
	}
	result = responseBuffer.ReadBinaryData(pbSign, signatureSize);
	if (!result)
	{
		m_ulError = TPM_INVALID_TPM_RESPONSE;
		return false;
	}
	return ReadOSAPResponse(responseBuffer);
}

unsigned long TTPM::GetCode()
{
	return m_ulError;
}

const char*  TTPM::ErrorToString()
{
	return TTPM::ErrorToString(m_ulError);
}

const char* TTPM::ErrorToString(unsigned long errorCode)
{
	const char* message = NULL;
	switch(errorCode)
	{
		case TPM_SUCCESS: message = "TPM_SUCCESS"; break;		
		case TPM_AUTHFAIL: message = "TPM_AUTHFAIL"; break;
		case TPM_BADINDEX: message = "TPM_BADINDEX"; break;
		case TPM_BAD_PARAMETER: message = "TPM_BAD_PARAMETER"; break;
		case TPM_AUDITFAILURE: message = "TPM_AUDITFAILURE"; break;
		case TPM_CLEAR_DISABLED: message = "TPM_CLEAR_DISABLED"; break;
		case TPM_DEACTIVATED: message = "TPM_DEACTIVATED"; break;
		case TPM_DISABLED: message = "TPM_DISABLED"; break;
		case TPM_DISABLED_CMD: message = "TPM_DISABLED_CMD"; break;
		case TPM_FAIL: message = "TPM_FAIL"; break;
		case TPM_BAD_ORDINAL: message = "TPM_BAD_ORDINAL"; break;  
		case TPM_INSTALL_DISABLED: message = "TPM_INSTALL_DISABLED"; break;
		case TPM_INVALID_KEYHANDLE: message = "TPM_INVALID_KEYHANDLE"; break;
		case TPM_KEYNOTFOUND: message = "TPM_KEYNOTFOUND"; break;
		case TPM_INAPPROPRIATE_ENC: message = "TPM_INAPPROPRIATE_ENC"; break;
		case TPM_MIGRATEFAIL: message = "TPM_MIGRATEFAIL"; break;
		case TPM_INVALID_PCR_INFO: message = "TPM_INVALID_PCR_INFO"; break;
		case TPM_NOSPACE: message = "TPM_NOSPACE"; break;
		case TPM_NOSRK: message = "TPM_NOSRK"; break;
		case TPM_NOTSEALED_BLOB: message = "TPM_NOTSEALED_BLOB"; break; 
		case TPM_OWNER_SET: message = "TPM_OWNER_SET"; break;
		case TPM_RESOURCES: message = "TPM_RESOURCES"; break;
		case TPM_SHORTRANDOM: message = "TPM_SHORTRANDOM"; break;
		case TPM_SIZE: message = "TPM_SIZE"; break;
		case TPM_WRONGPCRVAL: message = "TPM_WRONGPCRVAL"; break;  
		case TPM_BAD_PARAM_SIZE: message = "TPM_BAD_PARAM_SIZE"; break;
		case TPM_SHA_THREAD: message = "TPM_SHA_THREAD"; break;
		case TPM_SHA_ERROR: message = "TPM_SHA_ERROR"; break;
		case TPM_FAILEDSELFTEST: message = "TPM_FAILEDSELFTEST"; break;             
		case TPM_AUTH2FAIL: message = "TPM_AUTH2FAIL"; break;
		case TPM_BADTAG: message = "TPM_BADTAG"; break;
		case TPM_IOERROR: message = "TPM_IOERROR"; break;
		case TPM_ENCRYPT_ERROR: message = "TPM_ENCRYPT_ERROR"; break;
		case TPM_DECRYPT_ERROR: message = "TPM_DECRYPT_ERROR"; break;
		case TPM_INVALID_AUTHHANDLE: message = "TPM_INVALID_AUTHHANDLE"; break;
		case TPM_NO_ENDORSEMENT: message = "TPM_NO_ENDORSEMENT"; break;
		case TPM_INVALID_KEYUSAGE: message = "TPM_INVALID_KEYUSAGE"; break;
		case TPM_WRONG_ENTITYTYPE: message = "TPM_WRONG_ENTITYTYPE"; break;
		case TPM_INVALID_POSTINIT: message = "TPM_INVALID_POSTINIT"; break;
		case TPM_INAPPROPRIATE_SIG: message = "TPM_INAPPROPRIATE_SIG"; break;
		case TPM_BAD_KEY_PROPERTY: message = "TPM_BAD_KEY_PROPERTY"; break;
		case TPM_BAD_MIGRATION: message = "TPM_BAD_MIGRATION"; break;
		case TPM_BAD_SCHEME: message = "TPM_BAD_SCHEME"; break;
		case TPM_BAD_DATASIZE: message = "TPM_BAD_DATASIZE"; break;
		case TPM_BAD_MODE: message = "TPM_BAD_MODE"; break;
		case TPM_BAD_PRESENCE: message = "TPM_BAD_PRESENCE"; break;
		case TPM_BAD_VERSION: message = "TPM_BAD_VERSION"; break;
		case TPM_NO_WRAP_TRANSPORT: message = "TPM_NO_WRAP_TRANSPORT"; break;
		case TPM_AUDITFAIL_UNSUCCESSFUL: message = "TPM_AUDITFAIL_UNSUCCESSFUL"; break;
		case TPM_AUDITFAIL_SUCCESSFUL: message = "TPM_AUDITFAIL_SUCCESSFUL"; break;
		case TPM_NOTRESETABLE: message = "TPM_NOTRESETABLE"; break;                
		case TPM_NOTLOCAL: message = "TPM_NOTLOCAL"; break;
		case TPM_BAD_TYPE: message = "TPM_BAD_TYPE"; break;
		case TPM_INVALID_RESOURCE: message = "TPM_INVALID_RESOURCE"; break;
		case TPM_NOTFIPS: message = "TPM_NOTFIPS"; break;
		case TPM_INVALID_FAMILY: message = "TPM_INVALID_FAMILY"; break;
		case TPM_NO_NV_PERMISSION: message = "TPM_NO_NV_PERMISSION"; break;
		case TPM_REQUIRES_SIGN: message = "TPM_REQUIRES_SIGN"; break;
		case TPM_KEY_NOTSUPPORTED: message = "TPM_KEY_NOTSUPPORTED"; break;
		case TPM_AUTH_CONFLICT: message = "TPM_AUTH_CONFLICT"; break;
		case TPM_AREA_LOCKED: message = "TPM_AREA_LOCKED"; break;
		case TPM_BAD_LOCALITY: message = "TPM_BAD_LOCALITY"; break;
		case TPM_READ_ONLY: message = "TPM_READ_ONLY"; break;
		case TPM_PER_NOWRITE: message = "TPM_PER_NOWRITE"; break;
		case TPM_FAMILYCOUNT: message = "TPM_FAMILYCOUNT"; break;
		case TPM_WRITE_LOCKED: message = "TPM_WRITE_LOCKED"; break;
		case TPM_BAD_ATTRIBUTES: message = "TPM_BAD_ATTRIBUTES"; break;
		case TPM_INVALID_STRUCTURE: message = "TPM_INVALID_STRUCTURE"; break;
		case TPM_KEY_OWNER_CONTROL: message = "TPM_KEY_OWNER_CONTROL"; break;
		case TPM_BAD_COUNTER: message = "TPM_BAD_COUNTER"; break;
		case TPM_NOT_FULLWRITE: message = "TPM_NOT_FULLWRITE"; break;
		case TPM_CONTEXT_GAP: message = "TPM_CONTEXT_GAP"; break;
		case TPM_MAXNVWRITES: message = "TPM_MAXNVWRITES"; break;
		case TPM_NOOPERATOR: message = "TPM_NOOPERATOR"; break;
		case TPM_RESOURCEMISSING: message = "TPM_RESOURCEMISSING"; break;
		case TPM_DELEGATE_LOCK: message = "TPM_DELEGATE_LOCK"; break;
		case TPM_DELEGATE_FAMILY: message = "TPM_DELEGATE_FAMILY"; break;
		case TPM_DELEGATE_ADMIN: message = "TPM_DELEGATE_ADMIN"; break;
		case TPM_TRANSPORT_NOTEXCLUSIVE: message = "TPM_TRANSPORT_NOTEXCLUSIVE"; break;
		case TPM_OWNER_CONTROL: message = "TPM_OWNER_CONTROL"; break;
		case TPM_DAA_RESOURCES: message = "TPM_DAA_RESOURCES"; break;
		case TPM_DAA_INPUT_DATA0: message = "TPM_DAA_INPUT_DATA0"; break;
		case TPM_DAA_INPUT_DATA1: message = "TPM_DAA_INPUT_DATA1"; break;
		case TPM_DAA_ISSUER_SETTINGS: message = "TPM_DAA_ISSUER_SETTINGS"; break;
		case TPM_DAA_TPM_SETTINGS: message = "TPM_DAA_TPM_SETTINGS"; break;
		case TPM_DAA_STAGE: message = "TPM_DAA_STAGE"; break;
		case TPM_DAA_ISSUER_VALIDITY: message = "TPM_DAA_ISSUER_VALIDITY"; break;
		case TPM_DAA_WRONG_W: message = "TPM_DAA_WRONG_W"; break;
		case TPM_BAD_HANDLE: message = "TPM_BAD_HANDLE"; break;
		case TPM_BAD_DELEGATE: message = "TPM_BAD_DELEGATE"; break;
		case TPM_BADCONTEXT: message = "TPM_BADCONTEXT"; break;
		case TPM_TOOMANYCONTEXTS: message = "TPM_TOOMANYCONTEXTS"; break;
		case TPM_MA_TICKET_SIGNATURE: message = "TPM_MA_TICKET_SIGNATURE"; break;
		case TPM_MA_DESTINATION: message = "TPM_MA_DESTINATION"; break;
		case TPM_MA_SOURCE: message = "TPM_MA_SOURCE"; break;
		case TPM_MA_AUTHORITY: message = "TPM_MA_AUTHORITY"; break;
		case TPM_PERMANENTEK: message = "TPM_PERMANENTEK"; break;
		case TPM_BAD_SIGNATURE: message = "TPM_BAD_SIGNATURE"; break;
		case TPM_NOCONTEXTSPACE: message = "TPM_NOCONTEXTSPACE"; break;
		case TPM_RETRY: message = "TPM_RETRY"; break;
		case TPM_NEEDS_SELFTEST: message = "TPM_NEEDS_SELFTEST"; break;  
		case TPM_DOING_SELFTEST: message = "TPM_DOING_SELFTEST"; break;
		case TPM_DEFEND_LOCK_RUNNING: message = "TPM_DEFEND_LOCK_RUNNING"; break;
		case TPM_TEMPORARY_LOCKED: message = "TPM_TEMPORARY_LOCKED"; break;
		case TPM_COMMAND_BLOCKED: message = "TPM_COMMAND_BLOCKED"; break;
		case TPM_CHANNEL_ERROR_DETECTED: message="CTMP_CHANNEL_ERROR_DETECTED"; break;
		case TPM_BUFFER_TOO_SMALL: message = "TPM_BUFFER_TOO_SMALL"; break;
		case TPM_INVALID_TPM_RESPONSE: message="TPM_INVALID_RESPONSE"; break;
		case TPM_UNKNOWN_SESSION_TYPE: message="TPM_UNKNOWN_SESSION_TYPE"; break;
	}
	return message;
}

bool TTPM::GetPublicKey(unsigned long hKey, unsigned char* pbData, unsigned long* cbData, TTPMAttributeList* props)
{
	unsigned long hParentKey = TPM_KH_EK;

	TPM_DIGEST usageSecret;
	memset(&usageSecret, 0, sizeof(usageSecret.digest));
	if (props!=NULL)
	{
		props->get(TPM_ATTR_PARENT_KEY_HANDLE, hParentKey);

		TTPMAttribute* usageSecretAttr = props->find(TPM_ATTR_USAGE_SECRET);
		if (usageSecretAttr!=NULL)
		{
			unsigned char * pAttrValue = usageSecretAttr->getvalueAsPtr();
			if (pAttrValue!=NULL) memcpy((unsigned char*)&usageSecret.digest, pAttrValue, sizeof(TPM_DIGEST));
		}		
	}

	unsigned char sessionType = TPM_ORD_OIAP;
	if (props!=NULL)
	{
		props->get(TPM_ATTR_SESSION_TYPE, sessionType);
	}

	bool result = false;
	switch(sessionType)
	{
		case TPM_ORD_OSAP:result = SendOSAPAuthentication(TPM_ET_KEY, hParentKey, usageSecret); break;
		case TPM_ORD_OIAP:result = result = SendOIAPAuthentication(); break;
		default:m_ulError = TPM_UNKNOWN_SESSION_TYPE; return false;
	}
	if (!result)
	{
		return false;
	}

	TTPMBuffer requestBuffer;	
	requestBuffer.WriteCommandHeader(TPM_TAG_RQU_AUTH1_COMMAND);
	requestBuffer.WriteUInt32(TPM_ORD_GetPubKey);
	requestBuffer.WriteUInt32(hKey, false);
	switch(sessionType)
	{
		case TPM_ORD_OIAP: WriteOIAPFooter(requestBuffer, usageSecret); break;
		case TPM_ORD_OSAP: WriteOSAPFooter(requestBuffer); break;
	}	

	requestBuffer.UpdateCommandHeaderSize();

	TTPMBuffer responseBuffer(2048);
	result = SendTPMCommand(requestBuffer, responseBuffer);
	if (!result)
	{
		return false;
	}	

	unsigned long realKeySize = responseBuffer.GetDataCount()- 2 - 4 - 4 - 20 - 1 - 20;
	if (*cbData<realKeySize)
	{
		m_ulError = TPM_BUFFER_TOO_SMALL;
		return false;
	}

	result = responseBuffer.ReadBinaryData(pbData, realKeySize);
	if (!result)
	{
		m_ulError = TPM_INVALID_TPM_RESPONSE;
		return false;
	}

	switch(sessionType)
	{
		case TPM_ORD_OIAP: return ReadOIAPResponse(responseBuffer);
		case TPM_ORD_OSAP: return ReadOSAPResponse(responseBuffer);
	}
	return false;
}

/*******************************************************
 *   GetStringDigest
 *   Method generates sha1 from text in the same way as
 *   tpm.msc utitility
 *
 *   pbString       : string
 *   digest			: digest
 *******************************************************/
void TTPM::GetStringDigest(const char* pbString, TPM_DIGEST &digest)
{
	unsigned char zero = 0;

	tpm_sha1_t sha;
	tpm_sha1_init(&sha);
	unsigned long cbString = strlen(pbString); 
	for(unsigned int i =0; i<cbString; i++)
	{
		tpm_sha1_update(&sha, (const uint8_t*)&pbString[0], 1);
		tpm_sha1_update(&sha, (const uint8_t*)&zero, 1);
	}
	tpm_sha1_final(&sha, digest.digest);	
}



void TTPM::GetBlobPassword(TPM_DIGEST &passwordHash)
{
	unsigned char password[14];
	password[0] = 'B';
	password[1] = '!';
	password[2] = 'o';
	password[3] = 'b';
	password[4] = '_';
	password[5] = 'P';
	password[6] = 'a';
	password[7] = 's';
	password[8] = 's';
	password[9] = 'W';
	password[10] = '0';
	password[11] = 'r';
	password[12] = 'd';
	password[13] = '.';
	unsigned long passwordSize = 14;

	tpm_sha1_t sha;
	tpm_sha1_init(&sha);
	tpm_sha1_update(&sha, (const uint8_t*)&password, passwordSize);
	tpm_sha1_final(&sha, passwordHash.digest);
}