#include "TTPMAttribute.h"

TTPMAttribute::TTPMAttribute()
{
	m_id = 0;
	m_value = 0;
}

void TTPMAttribute::set(unsigned long id,unsigned long value)
{
	m_id = id;
	m_value = value;
}

void TTPMAttribute::setAsString(unsigned long id,const char *value)
{	
	m_id = id;
	m_value = (unsigned long)value;
}

void TTPMAttribute::setvalue(unsigned long value)
{
	m_value = value;
}

unsigned long TTPMAttribute::getid()
{
	return m_id;
}

unsigned long TTPMAttribute::getvalue()
{
	return m_value;
}

unsigned char* TTPMAttribute::getvalueAsPtr()
{
	return (unsigned char*)m_value;
}

const char* TTPMAttribute::getvalueAsPChar()
{
	return (const char*) m_value;
}

