#ifndef TMP_ATTRIBUTE_LIST___H
#define TMP_ATTRIBUTE_LIST___H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "TTPMAttribute.h"

class TTPMAttributeList
{
protected:

	TTPMAttribute** m_pAttributes;

	//max buffer size
	unsigned int    m_attributeCapacity;

	//current number of attributes in buffer
	unsigned int    m_attributeCount;	
	
	//iterator position used by first/next function
	unsigned int   m_iteratorPosition;

	static TTPMAttribute* emptyAttribute;

	void setCapacity(unsigned long capacity);

public:
	TTPMAttributeList();
	TTPMAttributeList(const TTPMAttributeList &props);
	~TTPMAttributeList();

	void set(unsigned long id,unsigned long value);
	void setAsString(unsigned long id,const char* value);  
	void setAsPtr(unsigned long id,unsigned char* value);  
	void get(unsigned long id, unsigned long &value);
	void get(unsigned long id, UINT32 &value);
	void get(unsigned long id, UINT16 &value);
	void get(unsigned long id, BYTE &value);
	void getAsPtr(unsigned long id, unsigned char* &value);

	TTPMAttribute* find(unsigned long id);

	TTPMAttribute* first();
	TTPMAttribute* next();
};

#endif