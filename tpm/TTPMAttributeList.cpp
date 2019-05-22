#include "TTPMAttributeList.h"

/*******************************************************
 *   Ctor
 *   Function initializes all class members
 *
 *   Returns        : Nothing
 *******************************************************/
TTPMAttributeList::TTPMAttributeList()
{
	m_pAttributes = NULL;
	m_attributeCount = 0;
	m_attributeCapacity = 0;
	m_iteratorPosition = 0;
}

/*******************************************************
 *   Dtor
 *
 *   Function destroys all TPMAttributes from internal
 *   list and unallocates all used memory
 *
 *   Returns        : Nothing
 *******************************************************/
TTPMAttributeList::~TTPMAttributeList()
{
	if (m_pAttributes!=NULL)
	{
		//destroys all attributes from list
		for(unsigned int i = 0; i<m_attributeCount; i++)
		{
			if (m_pAttributes[i]!=NULL)
			{
				delete m_pAttributes[i];
				m_pAttributes[i]=NULL;
			}
		}
		//unallocates internal buffer
		delete m_pAttributes;

		//sets pointers and counters to zero
		m_pAttributes = NULL;
		m_attributeCount = 0;
		m_attributeCapacity = 0;
	}	
}

/*******************************************************
 *   Copy constructor
 *
 *   Function loads all attributes from another instance of
 *   TPMAttributeList
 *
 *   Returns        : Nothing
 *******************************************************/
TTPMAttributeList::TTPMAttributeList(const TTPMAttributeList &props)
{
	m_pAttributes = NULL;
	m_attributeCount = 0;
	m_attributeCapacity = 0;
	m_iteratorPosition = 0;
	setCapacity(props.m_attributeCapacity);

	for(unsigned long i = 0; i<props.m_attributeCount; i++)
	{
		TTPMAttribute* attr = props.m_pAttributes[i];
		if (attr!=NULL)
		{
			set(attr->getid(), attr->getvalue());
		}		
	}
}

/*******************************************************
 *   setCapactiy
 *
 *   Function sets internal buffer capacity. If capacity
 *   is not big enough, can be increased later without 
 *   loosing data
 *
 *   Returns        : Nothing
 *   newCapacity    : Number of attributes
 *******************************************************/
void TTPMAttributeList::setCapacity(unsigned long newCapacity)
{
	if (m_attributeCapacity>newCapacity)
	{
		return;
	}
	if (m_pAttributes==NULL)
	{		
		m_pAttributes = (TTPMAttribute**)malloc(newCapacity*sizeof(TTPMAttribute*));
	} else {
		m_pAttributes = (TTPMAttribute**)realloc(m_pAttributes, newCapacity*sizeof(TTPMAttribute*));
	}
	if (m_pAttributes!=NULL)
	{
		for(unsigned int i = m_attributeCapacity; i<newCapacity; i++)
		{
			m_pAttributes[i] = NULL;
		}
		m_attributeCapacity = newCapacity;
	} else {
		m_attributeCapacity = 0;
		m_attributeCount = 0;
	}
}

/*******************************************************
 *   set
 *
 *   Function looks for existing attribute. If is found, 
 *   then attribute value is changed. Otherwise new attribute
 *   is created
 *
 *   Returns        : Nothing
 *   id             : attribute id
 *   value          : attribute value
 *******************************************************/
void TTPMAttributeList::set(unsigned long id, unsigned long value)
{
	bool found = false;

	//tries to find existing attribute
	for(unsigned int i = 0; i<m_attributeCount; i++)
	{
		if (m_pAttributes[i]->getid()==id)
		{
			//and modifies value
			m_pAttributes[i]->set(id, value);
			found = true;
		}
	}
	if (!found)
	{
		//otherwise adds new attribute

		//checks internal buffer size if is big enough
		if (m_attributeCount>=m_attributeCapacity)
		{
			//increases internal buffer size
			setCapacity(m_attributeCapacity==0 ? 8 : m_attributeCapacity*2);
		}
		if (m_pAttributes!=NULL)
		{
			//creates new attribute instance
			if (m_pAttributes[m_attributeCount]==NULL)
			{
				m_pAttributes[m_attributeCount]=new TTPMAttribute();
			}
			if (m_pAttributes[m_attributeCount]!=NULL)
			{
				//and sets attribute value
				m_pAttributes[m_attributeCount]->set(id, value);
				m_attributeCount++;
			}			
		}
	}
}

/*******************************************************
 *   setAsString
 *
 *   Function looks for existing attribute. If is found, 
 *   then attribute value is changed. Otherwise new attribute
 *   is created
 *
 *   Returns        : Nothing
 *   id             : attribute id
 *   value          : attribute string value
 *******************************************************/
void TTPMAttributeList::setAsString(unsigned long id, const char *value)
{
	set(id, (unsigned long)value);
}

/*******************************************************
 *   setAsPtr
 *
 *   Function looks for existing attribute. If is found, 
 *   then attribute value is changed. Otherwise new attribute
 *   is created
 *
 *   Returns        : Nothing
 *   id             : attribute id
 *   value          : attribute pointer value
 *******************************************************/
void TTPMAttributeList::setAsPtr(unsigned long id,unsigned char* value)
{
	set(id, (unsigned long)value);
}

/*******************************************************
 *   get
 *
 *   Function looks for existing attribute. If is found, 
 *   then attribute value is changed. Otherwise new attribute
 *   is created
 *
 *   id             : attribute id
 *   value          : returns value if attribute exists
 *******************************************************/
void TTPMAttributeList::get(unsigned long id, unsigned long &value)
{
	TTPMAttribute* pAttribute = find(id);
	if (pAttribute!=NULL)
	{
		value = pAttribute->getvalue();
	}
}

void TTPMAttributeList::get(unsigned long id, UINT32 &value)
{
	TTPMAttribute* pAttribute = find(id);
	if (pAttribute!=NULL)
	{
		value = (UINT32)pAttribute->getvalue();
	}
}

void TTPMAttributeList::get(unsigned long id, UINT16 &value)
{
	TTPMAttribute* pAttribute = find(id);
	if (pAttribute!=NULL)
	{
		value = (UINT16)pAttribute->getvalue();
	}
}

void TTPMAttributeList::get(unsigned long id, BYTE &value)
{
	TTPMAttribute* pAttribute = find(id);
	if (pAttribute!=NULL)
	{
		value = (BYTE)pAttribute->getvalue();
	}
}


/*******************************************************
 *   getAsPtr
 *
 *   Function looks for existing attribute. If is found, 
 *   then attribute value is changed. Otherwise new attribute
 *   is created 
 *   id             : attribute id
 *   value          : returns pointer value if attribute exists
 *******************************************************/
void TTPMAttributeList::getAsPtr(unsigned long id, unsigned char* &value)
{
	TTPMAttribute* pAttribute = find(id);
	if (pAttribute!=NULL)
	{
		value = pAttribute->getvalueAsPtr();
	}
}

/*******************************************************
 *   find
 *
 *   Function looks for existing attribute.
 *
 *   Returns        : existing attribute or NULL if does not 
 *                    exist
 *   id             : attribute id
 *******************************************************/
TTPMAttribute* TTPMAttributeList::find(unsigned long id)
{	
	//iterates attribute list and looks for defined id
	for(unsigned int i = 0; i<m_attributeCount; i++)
	{
		if (m_pAttributes[i]->getid()==id)
		{
			return m_pAttributes[i];
		}
	}	
	return NULL;
}

/*******************************************************
 *   find
 *
 *   Function resets internal iterator and returns first
 *   attribute
 *
 *   Returns        : fisrt attribute or NULL if there are no
 *                    attributes
 *******************************************************/
TTPMAttribute* TTPMAttributeList::first()
{
	m_iteratorPosition = 0;
	if (m_attributeCount>0)
	{
		if (m_iteratorPosition<m_attributeCount)
		{
			return m_pAttributes[m_iteratorPosition];
		}		
	}
	return NULL;
}

/*******************************************************
 *   next
 *
 *   Function returns next attribute. As first is needed to 
 *   call "first" method above
 *
 *   Returns        : next attribute or NULL if there are no
 *                    more attributes
 *******************************************************/
TTPMAttribute* TTPMAttributeList::next()
{
	m_iteratorPosition++;
	if (m_iteratorPosition>=m_attributeCount)
	{
		return NULL;
	}
	return m_pAttributes[m_iteratorPosition];
}
