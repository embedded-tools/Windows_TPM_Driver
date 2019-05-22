#ifndef TPM_ATTRIBUTE___H
#define TPM_ATTRIBUTE___H

#include "TPM_structures.h"

#define TPM_PROP_TPM_NOT_ACTIVE    0x0001
#define TPM_PROP_TPM_OWNER_NOT_SET 0x0002
#define TPM_PROP_TPM_VENDOR		   0x0003
#define TPM_PROP_TPM_VERSION	   0x0004

#define TPM_ATTR_PARENT_KEY_HANDLE	0x0011
#define TPM_ATTR_USAGE_SECRET		0x0012
#define TPM_ATTR_NEW_USAGE_SECRET	0x0013
#define TPM_ATTR_OWNER_USAGE_SECRET 0x0014

#define TPM_ATTR_KEY_HANDLE	     	0x0021
#define TPM_ATTR_KEY_USAGE		       	0x0022
#define TPM_ATTR_KEY_FLAGS			    0x0023
#define TPM_ATTR_KEY_AUTHTYPE			0x0024
#define TPM_ATTR_KEY_USAGE_SECRET		0x0025
#define TPM_ATTR_KEY_MIGRATION_SECRET	0x0026

#define TPM_ATTR_SESSION_TYPE		0x0030


class TTPMAttribute
{
protected:
	unsigned long m_id;
	unsigned long m_value;

public:
	TTPMAttribute();

	void set(unsigned long id,unsigned long value);
	void setAsString(unsigned long id,const char *value);
	void setvalue(unsigned long value);
	unsigned long getid();
	unsigned long getvalue();
	unsigned char* getvalueAsPtr();
	const char* getvalueAsPChar();

	operator unsigned long () { return m_value; };
	operator unsigned short() { return (unsigned short) m_value; };
	operator unsigned char()  { return (unsigned char) m_value; };
	operator unsigned char*() { return (unsigned char*) m_value; };
	operator const char*()    { return (const char*) m_value; };

};

#endif