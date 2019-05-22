#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include "TTPM.h"
#include "TTPMAttribute.h"
#include "TTPMAttributeList.h"
#include "TTPMChannel.h"
#include "TPM_structures.h"

TTPMChannel* channel=NULL;
TTPM* tpm = NULL;

void GetEK()
{
	printf("Get Endorsement Key:");

	unsigned char pubEK[4096];
	unsigned long pubEKSize = sizeof(pubEK);

	bool result = tpm->ReadPubEK(pubEK, &pubEKSize);
	if (result)
	{
		printf("OK\r\n");
	} else {
		printf("Failed (%s)\r\n", tpm->ErrorToString(tpm->GetCode()));
	}

}

void GenerateKey()
{
	TTPMAttributeList attrsGen;

	printf("\r\nGenerate keys:\r\n");
	
	unsigned char companyKey[2048];
	unsigned long companyKeySize = sizeof(companyKey);

	TPM_DIGEST companyKeyUsageSecret;
	TPM_DIGEST companyKeyMigrationSecret;

	//newUsageSecret will be required to use the key (to bind data or to sign data)
	tpm->GetStringDigest("CompanyKeyPassword", companyKeyUsageSecret);

	//newMigrationSecret will be required to export the key
	tpm->GetStringDigest("CompanyMigrationPassword", companyKeyMigrationSecret);

	attrsGen.set(TPM_ATTR_PARENT_KEY_HANDLE, TPM_KH_SRK); //owner is SRK
	attrsGen.set(TPM_ATTR_USAGE_SECRET, 0); //SRK key requires no password
	attrsGen.set(TPM_ATTR_KEY_USAGE, TPM_KEY_STORAGE);
	attrsGen.set(TPM_ATTR_KEY_FLAGS, 0);// TPM_KEY_FLAG_MIGRATABLE);
	attrsGen.set(TPM_ATTR_KEY_AUTHTYPE, TPM_AUTH_ALWAYS);
	attrsGen.set(TPM_ATTR_KEY_USAGE_SECRET, (unsigned long)&companyKeyUsageSecret.digest);
	attrsGen.set(TPM_ATTR_KEY_MIGRATION_SECRET, (unsigned long)&companyKeyMigrationSecret.digest);

	printf("Main key:");
	bool result = tpm->GenerateKey((unsigned char*)&companyKey, &companyKeySize, &attrsGen);
	if (result)
	{
		printf("OK\r\n");
	} else {
		printf("Failed (%s)\r\n", tpm->ErrorToString(tpm->GetCode()));
		return;
	}

	unsigned long hCompanyKey = 0;

	printf("Load main key:");
	TTPMAttributeList attrsLoad;
	attrsLoad.set(TPM_ATTR_PARENT_KEY_HANDLE, TPM_KH_SRK); //owner is SRK
	attrsLoad.set(TPM_ATTR_USAGE_SECRET, 0); //SRK requires no password
	attrsLoad.set(TPM_ATTR_SESSION_TYPE, TPM_ORD_OSAP);

	result = tpm->ImportKey(&hCompanyKey, companyKey, companyKeySize, &attrsLoad);
	if (result)
	{
		printf("OK (Handle: %i)\r\n", hCompanyKey);
	} else {
		printf("Failed\r\n");
	}

	unsigned char user1SigningKey[2048];
	unsigned long user1SigningKeySize = sizeof(user1SigningKey);

	TPM_DIGEST user1SigningKeyUsageSecret;
	TPM_DIGEST user1SigningKeyMigrationSecret;

	//newUsageSecret will be required to use the key (to bind data or to sign data)
	tpm->GetStringDigest("User1KeyPassword", user1SigningKeyUsageSecret);

	//newMigrationSecret will be required to export the key
	tpm->GetStringDigest("User1MigrationPassword", user1SigningKeyMigrationSecret);

	attrsGen.set(TPM_ATTR_PARENT_KEY_HANDLE, hCompanyKey); //owner is company key
	attrsGen.set(TPM_ATTR_KEY_AUTHTYPE, TPM_AUTH_ALWAYS);
	attrsGen.set(TPM_ATTR_USAGE_SECRET, (unsigned long)&companyKeyUsageSecret.digest); //company storage key requires password
	attrsGen.set(TPM_ATTR_KEY_USAGE, TPM_KEY_SIGNING);
	attrsGen.set(TPM_ATTR_KEY_FLAGS, TPM_KEY_FLAG_MIGRATABLE);
	attrsGen.set(TPM_ATTR_KEY_USAGE_SECRET, (unsigned long)&user1SigningKeyUsageSecret.digest);
	attrsGen.set(TPM_ATTR_KEY_MIGRATION_SECRET, (unsigned long)&user1SigningKeyMigrationSecret.digest);
	attrsGen.set(TPM_ATTR_SESSION_TYPE, TPM_ORD_OSAP);

	printf("User1 signing key:");
    result = tpm->GenerateKey((unsigned char*)&user1SigningKey, &user1SigningKeySize, &attrsGen);
	if (result)
	{
		printf("OK\r\n");
	} else {
		printf("Failed (%s)\r\n", tpm->ErrorToString(tpm->GetCode()));
		return;
	}

	printf("Load user1 signing key:");
	attrsLoad.set(TPM_ATTR_PARENT_KEY_HANDLE, hCompanyKey); //owner is CompanyKey
	attrsLoad.set(TPM_ATTR_USAGE_SECRET, (unsigned long)&companyKeyUsageSecret.digest); //CompanyKey requires password
	attrsLoad.set(TPM_ATTR_SESSION_TYPE, TPM_ORD_OSAP);

	unsigned long hUser1SigningKey = 0;
	result = tpm->ImportKey(&hUser1SigningKey, user1SigningKey, user1SigningKeySize, &attrsLoad);
	if (result)
	{
		printf("OK (Handle: %i)\r\n", hUser1SigningKey);
	} else {
		printf("Failed\r\n");
		return;
	}

	TTPMAttributeList attrsPubKey;
	attrsPubKey.set(TPM_ATTR_USAGE_SECRET, (unsigned long)&user1SigningKeyUsageSecret.digest);

	printf("Get user1 public key:");
	result = tpm->GetPublicKey(hUser1SigningKey, user1SigningKey, &user1SigningKeySize, &attrsPubKey);
	if (result)
	{
		printf("OK\r\n");
	} else {
		printf("Failed (%s)\r\n", tpm->ErrorToString(tpm->GetCode()));
	}


	unsigned char user2EncryptingKey[2048];
	unsigned long user2EncryptingKeySize = sizeof(user2EncryptingKey);

	TPM_DIGEST user2EncryptingKeyUsageSecret;
	TPM_DIGEST user2EncryptingKeyMigrationSecret;

	//newUsageSecret will be required to use the key (to bind data or to sign data)
	tpm->GetStringDigest("User2KeyPassword", user2EncryptingKeyUsageSecret);

	//newMigrationSecret will be required to export the key
	tpm->GetStringDigest("User2MigrationPassword", user2EncryptingKeyMigrationSecret);

	attrsGen.set(TPM_ATTR_PARENT_KEY_HANDLE, hCompanyKey); //owner is company key
	attrsGen.set(TPM_ATTR_KEY_AUTHTYPE, TPM_AUTH_ALWAYS);
	attrsGen.set(TPM_ATTR_USAGE_SECRET, (unsigned long)&companyKeyUsageSecret.digest); //company storage key requires password
	attrsGen.set(TPM_ATTR_KEY_USAGE, TPM_KEY_SIGNING);
	attrsGen.set(TPM_ATTR_KEY_FLAGS, TPM_KEY_FLAG_MIGRATABLE);
	attrsGen.set(TPM_ATTR_KEY_USAGE_SECRET, (unsigned long)&user2EncryptingKeyUsageSecret.digest);
	attrsGen.set(TPM_ATTR_KEY_MIGRATION_SECRET, (unsigned long)&user2EncryptingKeyMigrationSecret.digest);
	attrsGen.set(TPM_ATTR_SESSION_TYPE, TPM_ORD_OSAP);

	printf("User2 encrypting key:");
    result = tpm->GenerateKey((unsigned char*)&user2EncryptingKey, &user2EncryptingKeySize, &attrsGen);
	if (result)
	{
		printf("OK\r\n");
	} else {
		printf("Failed (%s)\r\n", tpm->ErrorToString(tpm->GetCode()));
		return;
	}

	printf("Load user2 encrypt key:");
	attrsLoad.set(TPM_ATTR_PARENT_KEY_HANDLE, hCompanyKey); //owner is CompanyKey
	attrsLoad.set(TPM_ATTR_USAGE_SECRET, (unsigned long)&companyKeyUsageSecret.digest); //CompanyKey requires password
	attrsLoad.set(TPM_ATTR_SESSION_TYPE, TPM_ORD_OSAP);

	unsigned long hUser2EncryptingKey = 0;
	result = tpm->ImportKey(&hUser2EncryptingKey, user2EncryptingKey, user2EncryptingKeySize, &attrsLoad);
	if (result)
	{
		printf("OK (Handle: %i)\r\n", hUser2EncryptingKey);
	} else {
		printf("Failed\r\n");
	}

	unsigned char user3SealingKey[2048];
	unsigned long user3SealingKeySize = sizeof(user3SealingKey);

	TPM_DIGEST user3SealingKeyUsageSecret;
	TPM_DIGEST user3SealingKeyMigrationSecret;

	//newUsageSecret will be required to use the key (to bind data or to sign data)
	tpm->GetStringDigest("User3KeyPassword", user3SealingKeyUsageSecret);

	//newMigrationSecret will be required to export the key
	tpm->GetStringDigest("User3MigrationPassword", user3SealingKeyMigrationSecret);

	attrsGen.set(TPM_ATTR_PARENT_KEY_HANDLE, hCompanyKey); //owner is company key
	attrsGen.set(TPM_ATTR_KEY_AUTHTYPE, TPM_AUTH_ALWAYS);
	attrsGen.set(TPM_ATTR_USAGE_SECRET, (unsigned long)&companyKeyUsageSecret.digest); //company storage key requires password
	attrsGen.set(TPM_ATTR_KEY_USAGE, TPM_KEY_STORAGE);
	attrsGen.set(TPM_ATTR_KEY_FLAGS, 0);//TPM_KEY_FLAG_AUTHORITY);
	attrsGen.set(TPM_ATTR_KEY_USAGE_SECRET, (unsigned long)&user3SealingKeyUsageSecret.digest);
	attrsGen.set(TPM_ATTR_KEY_MIGRATION_SECRET, (unsigned long)&user3SealingKeyMigrationSecret.digest);
	attrsGen.set(TPM_ATTR_SESSION_TYPE, TPM_ORD_OSAP);

	printf("User3 sealing key:");
    result = tpm->GenerateKey((unsigned char*)&user3SealingKey, &user3SealingKeySize, &attrsGen);
	if (result)
	{
		printf("OK\r\n");
	} else {
		printf("Failed (%s)\r\n", tpm->ErrorToString(tpm->GetCode()));
		return;
	}

	printf("Load user3 sealing key:");
	attrsLoad.set(TPM_ATTR_PARENT_KEY_HANDLE, hCompanyKey); //owner is CompanyKey
	attrsLoad.set(TPM_ATTR_USAGE_SECRET, (unsigned long)&companyKeyUsageSecret.digest); //CompanyKey requires password
	attrsLoad.set(TPM_ATTR_SESSION_TYPE, TPM_ORD_OSAP);

	unsigned long hUser3SealingKey = 0;
	result = tpm->ImportKey(&hUser3SealingKey, user3SealingKey, user3SealingKeySize, &attrsLoad);
	if (result)
	{
		printf("OK (Handle: %i)\r\n", hUser2EncryptingKey);
	} else {
		printf("Failed\r\n");
	}


	printf("Sign data with user 1 key:");

	const char* dataToSign = "Hello Dolly!";
	unsigned long  dataToSignSize = strlen(dataToSign)+1;

	TPM_DIGEST dataHash;

	tpm_sha1_t sha;
	tpm_sha1_init(&sha);
	tpm_sha1_update(&sha, (const uint8_t*)dataToSign, dataToSignSize);
	tpm_sha1_final(&sha, dataHash.digest);

	unsigned char  signedData[512];
	unsigned long  signedDataSize = sizeof(signedData);

	TTPMAttributeList attrSign;
	attrSign.set(TPM_ATTR_USAGE_SECRET, (unsigned long)&user1SigningKeyUsageSecret.digest);
	
	result = tpm->Sign(hUser1SigningKey, dataHash.digest, sizeof(dataHash.digest), (unsigned char*)&signedData, &signedDataSize, &attrSign);	
	if (result)
	{
		printf("OK\r\n");
	}
	else 
	{
		printf("Failed\r\n");
	}

	TTPMAttributeList attrDecrypt;
	attrSign.set(TPM_ATTR_USAGE_SECRET, (unsigned long)&user2EncryptingKeyUsageSecret.digest);

	printf("Seal data:");
	const char* dataToEncrypt = "Tajna zasifrovana zprava";
	unsigned long dataToEncryptSize = strlen(dataToEncrypt);	

	TTPMAttributeList attrSeal;
	attrSeal.set(TPM_ATTR_USAGE_SECRET, (unsigned long)&user3SealingKeyUsageSecret.digest);
	

	unsigned char encryptedMessage[2048];
	unsigned long encryptedMessageSize = sizeof(encryptedMessage);

 	result = tpm->Seal(hUser3SealingKey, (unsigned char*) dataToEncrypt, dataToEncryptSize, encryptedMessage, &encryptedMessageSize, &attrSeal);
	if (result)
	{                                                                    
		printf("OK\r\n");
	} else {
		printf("Failed (%s)\r\n", tpm->ErrorToString(tpm->GetCode()));
		return;
	}

	wchar_t*       ownerPassword = L"heslo123";
	unsigned long  ownerPasswordSize = 16;
	TPM_DIGEST     ownerSecret;

	printf("Unseal data:");
	unsigned char decryptedMessage[2048];
	unsigned long decryptedMessageSize = sizeof(encryptedMessage);
	result = tpm->Unseal(hUser3SealingKey, (unsigned char*) encryptedMessage, encryptedMessageSize, decryptedMessage, &decryptedMessageSize, &attrSeal);
	if (result)
	{
		printf("OK\r\n");
	} else {
		printf("Failed (%s)\r\n", tpm->ErrorToString(tpm->GetCode()));
		return;
	}


	//result = tpm->Decrypt(hUser2EncryptingKey, dataToDecrypt, 	
}

void GetPublicKey()
{
	unsigned char key[2048];
	unsigned long keySize = sizeof(key);

	bool result;
	printf("\r\nGetPublicKey(SRK): ");
	result = tpm->GetPublicKey(TPM_KH_SRK, (unsigned char*)&key, &keySize);
	if (result)
	{
		printf("OK");
	} else {
		printf("Failed (%s)", tpm->ErrorToString(tpm->GetCode()));
	}


}

bool GetTPMVersion()
{
	bool result = tpm->Init();
	if (!result)
	{
		return false;
	}

	TTPMAttributeList attrList;
	tpm->GetProperty(&attrList);

	TTPMAttribute* disabled = attrList.find(TPM_PROP_TPM_NOT_ACTIVE);
	TTPMAttribute* noOwner  = attrList.find(TPM_PROP_TPM_OWNER_NOT_SET);
	TTPMAttribute* tpmVersion  = attrList.find(TPM_PROP_TPM_VERSION);
	TTPMAttribute* tmpVendor   = attrList.find(TPM_PROP_TPM_VENDOR);
	unsigned long  tpmVendorValue = tmpVendor->getvalue();

	unsigned char versionH = (tpmVersion->getvalue()&0xFF000000)>>24;
	unsigned char versionL = (tpmVersion->getvalue()&0x00FF0000)>>16;
	unsigned char versionMinorH = (tpmVersion->getvalue()&0x0000FF00)>>8;
	unsigned char versionMinorL = (tpmVersion->getvalue()&0x000000FF);
	unsigned char* vendorString = (unsigned char*)&tpmVendorValue;

	unsigned char iEnabled = disabled->getvalue();
	unsigned char iOwner   = noOwner->getvalue();

	printf("TPM Version: %i.%i.%i.%i\r\n",versionH, versionL, versionMinorH, versionMinorL);
	printf("TPM Vendor: %c%c%c%c\r\n", vendorString[0], vendorString[1], vendorString[2], vendorString[3]);
	printf("Enabled: %i\r\n",iEnabled);
	printf("Owner set: %i\r\n",iOwner);	
	printf("\r\n");

	bool tpmReady = (iEnabled!=0) && (iOwner!=0);
	return tpmReady;
}

void ChangeTPMPassword()
{
	char currentPassword[16];
	currentPassword[0]='h';
	currentPassword[1]=0;
	currentPassword[2]='e';
	currentPassword[3]=0;
	currentPassword[4]='s';
	currentPassword[5]=0;
	currentPassword[6]='l';
	currentPassword[7]=0;
	currentPassword[8]='o';
	currentPassword[9]=0;
	currentPassword[10]='1';
	currentPassword[11]=0;
	currentPassword[12]='2';
	currentPassword[13]=0;
	currentPassword[14]='3';
	currentPassword[15]=0;

	TPM_DIGEST currentPasswordHash;
	tpm_sha1_t sha;
	tpm_sha1_init(&sha);
	tpm_sha1_update(&sha, (const uint8_t*)&currentPassword, sizeof(currentPassword));
	tpm_sha1_final(&sha, currentPasswordHash.digest);

	char newPassword[18];
	newPassword[0] = 'M';
	newPassword[1] = 0;
	newPassword[2] = '0';
	newPassword[3] = 0;
	newPassword[4] = 'n';
	newPassword[5] = 0;
	newPassword[6] = 'e';
	newPassword[7] = 0;
	newPassword[8] = 't';
	newPassword[9] = 0;
	newPassword[10] = '2';
	newPassword[11] = 0;
	newPassword[12] = '0';
	newPassword[13] = 0;
	newPassword[14] = '1';
	newPassword[15] = 0;
	newPassword[16] = '5';
	newPassword[17] = 0;
	
	TPM_DIGEST newPasswordHash;
	tpm_sha1_init(&sha);
	tpm_sha1_update(&sha, (const uint8_t*)&newPassword, sizeof(newPassword));
	tpm_sha1_final(&sha, newPasswordHash.digest);

	TTPMAttributeList attrList;
	attrList.set(TPM_ATTR_USAGE_SECRET, (unsigned long)&currentPasswordHash.digest);
	attrList.set(TPM_ATTR_NEW_USAGE_SECRET, (unsigned long)&newPasswordHash.digest);
	bool result = tpm->ChangePassword(&attrList);
	printf("\r\nChangePassword:");
	if (result)
	{
		printf("OK");
	} else {
	    printf("Failed (%s)", tpm->ErrorToString(tpm->GetCode()));
		return;
	}

	attrList.set(TPM_ATTR_USAGE_SECRET, (unsigned long)&newPasswordHash.digest);
	attrList.set(TPM_ATTR_NEW_USAGE_SECRET, (unsigned long)&currentPasswordHash.digest);
	result = tpm->ChangePassword(&attrList);

	printf("\r\nRevertPasswordChange:");
	if (result)
	{
		printf("OK");
	} else {
		printf("Failed (%s)", tpm->ErrorToString(tpm->GetCode()));
	}
}


void ExportKey()
{
	char currentPassword[16];
	currentPassword[0]='h';
	currentPassword[1]=0;
	currentPassword[2]='e';
	currentPassword[3]=0;
	currentPassword[4]='s';
	currentPassword[5]=0;
	currentPassword[6]='l';
	currentPassword[7]=0;
	currentPassword[8]='o';
	currentPassword[9]=0;
	currentPassword[10]='1';
	currentPassword[11]=0;
	currentPassword[12]='2';
	currentPassword[13]=0;
	currentPassword[14]='3';
	currentPassword[15]=0;

	TPM_DIGEST currentPasswordHash;
	tpm_sha1_t sha;
	tpm_sha1_init(&sha);
	tpm_sha1_update(&sha, (const uint8_t*)&currentPassword, sizeof(currentPassword));
	tpm_sha1_final(&sha, currentPasswordHash.digest);

	TTPMAttributeList attrList;
	attrList.set(TPM_ATTR_USAGE_SECRET, (unsigned long)&currentPasswordHash.digest);

	unsigned char buffer[2048];
	unsigned long bufferSize = sizeof(buffer);

	printf("\r\nExportKey: ");
	bool res = tpm->ExportKey(TPM_KH_SRK, (unsigned char*)&buffer, &bufferSize, &attrList);
	if (res)
	{
		printf("OK");
	} else {
		printf("Failed (%s)", tpm->ErrorToString(tpm->GetCode()));
	}
}

void Reset()
{
	char currentPassword[16];
	currentPassword[0]='h';
	currentPassword[1]=0;
	currentPassword[2]='e';
	currentPassword[3]=0;
	currentPassword[4]='s';
	currentPassword[5]=0;
	currentPassword[6]='l';
	currentPassword[7]=0;
	currentPassword[8]='o';
	currentPassword[9]=0;
	currentPassword[10]='1';
	currentPassword[11]=0;
	currentPassword[12]='2';
	currentPassword[13]=0;
	currentPassword[14]='3';
	currentPassword[15]=0;

	TPM_DIGEST currentPasswordHash;
	tpm_sha1_t sha;
	tpm_sha1_init(&sha);
	tpm_sha1_update(&sha, (const uint8_t*)&currentPassword, sizeof(currentPassword));
	tpm_sha1_final(&sha, currentPasswordHash.digest);

	TTPMAttributeList attrList;
	attrList.set(TPM_ATTR_USAGE_SECRET, (unsigned long)&currentPasswordHash.digest);

	unsigned char buffer[2048];
	unsigned long bufferSize = sizeof(buffer);

	printf("\r\nReset: ");
	bool res = tpm->Reset(&attrList);
	if (res)
	{
		printf("OK");
	} else {
		printf("Failed (%s)", tpm->ErrorToString(tpm->GetCode()));
	}	
}

void SignData()
{
	char currentPassword[16];
	currentPassword[0]='h';
	currentPassword[1]=0;
	currentPassword[2]='e';
	currentPassword[3]=0;
	currentPassword[4]='s';
	currentPassword[5]=0;
	currentPassword[6]='l';
	currentPassword[7]=0;
	currentPassword[8]='o';
	currentPassword[9]=0;
	currentPassword[10]='1';
	currentPassword[11]=0;
	currentPassword[12]='2';
	currentPassword[13]=0;
	currentPassword[14]='3';
	currentPassword[15]=0;

	TPM_DIGEST currentPasswordHash;
	tpm_sha1_t sha;
	tpm_sha1_init(&sha);
	tpm_sha1_update(&sha, (const uint8_t*)&currentPassword, sizeof(currentPassword));
	tpm_sha1_final(&sha, currentPasswordHash.digest);

	TTPMAttributeList attrList;
	//attrList.set(TPM_ATTR_USAGE_SECRET, (unsigned long)&currentPasswordHash.digest);

	unsigned char buffer[2048];
	unsigned long bufferSize = sizeof(buffer);

	printf("\r\nSignData: ");

    unsigned char dataToSign[20];
	unsigned long dataToSignLength = sizeof(dataToSign);

	unsigned char outputData[2048];
	unsigned long outputDataLength = sizeof(outputData);

	bool res = tpm->Sign(TPM_KH_SRK, (unsigned char*)&dataToSign, dataToSignLength, (unsigned char*)outputData, &outputDataLength, &attrList);
	if (res)
	{
		printf("OK");
	} else {
		printf("Failed (%s)", tpm->ErrorToString(tpm->GetCode()));
	}	
}


int _tmain(int argc, _TCHAR* argv[])
{
	channel = new TTPMChannel();

	printf("TPM Init: ");
	bool channelOpened = channel->Open();
	if (!channelOpened)
	{
		//there are two possible reasons:
		// - there is no TPM present or is turned off
		// - application does not have administrator rights
		printf("Failed (%s)", channel->ErrorToString());
		if (channel->GetCode()==TBS_E_INTERNAL_ERROR)
		{
			printf(" - Application needs administrator rights");
		}
		printf("\r\n");
	} else {
		printf("OK\r\n\r\n");

		tpm = new TTPM(channel);

		bool initOK = tpm->Init();
		if (!initOK)
		{
			printf("Failed: %s", tpm->ErrorToString());		
		}
		bool ready = GetTPMVersion();
		if (ready) 
		{
			GetEK();
			GenerateKey();
			GetPublicKey();			
		} else {
			printf("TPM is not ready.\r\n");
		}
	}


	char c;
	scanf("Press any key %c", &c);
	return 0;
}


