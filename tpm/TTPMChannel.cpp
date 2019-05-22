#include "TTPMChannel.h"

TTPMChannel::TTPMChannel()
{
	m_hContext = 0;
	m_ulError = 0;
	m_pbResponce = NULL;
	m_cbResponce = 0;
}

TTPMChannel::~TTPMChannel()
{
	if (m_hContext!=0)
	{
		Close();
	}
}

/*******************************************************
 *   Open
 *  Function creates a new context. New context is stored
 *   m_hContext variable (context is always required by 
 *   Execute command).
 *
 *   Returns        : true if context was created successfully
 *                  : false if TPM is disabled, inactive or no owner is set
 *
 *******************************************************/
bool TTPMChannel::Open()
{
	if (m_hContext!=0) return false;

	TBS_CONTEXT_PARAMS contextParams;
	contextParams.version = TBS_CONTEXT_VERSION_ONE;	
	TBS_RESULT result = Tbsi_Context_Create(&contextParams, &m_hContext);
	if (result!=TBS_SUCCESS)
	{
		m_ulError = result;
		return false;
	}
	return true;
}

/*******************************************************
 *   Close
 *   Function closes the context stored in m_hContext variable
 *
 *   Returns : true if context was closed 
 *           : false if TPM is disabled, inactive or no owner is set
 *
 *******************************************************/
bool TTPMChannel::Close()
{
	TBS_RESULT result = Tbsip_Context_Close(m_hContext);
	m_hContext = 0;
	if (result!=TBS_SUCCESS)
	{
		m_ulError = result;
		return false;
	}
	return true;	
}

/*******************************************************
 *   Transmit
 *   Function sends command to TPM chip. TPM chip executes 
 *   command and returns result
 *
 *   Returns        : true if context was closed 
 *                  : false if TPM is disabled, inactive or no owner is set
 *   pbRequest      : binary buffer with TPM command
 *   cbRequest      : length of binary buffer with TPM command
 *   pbResponse     : buffer for result received by TPM chip
 *   cbResponse     : number of bytes received by TPM chip
 *   physicalPresenceCommand: must be TRUE if you want to execute "physical presence command"
 *
 *******************************************************/
bool TTPMChannel::Transmit(const unsigned char* pbRequest, unsigned long cbRequest,unsigned char *pbResponse, unsigned long *cbResponse, bool physicalPresenceCommand)
{
	if (physicalPresenceCommand)
	{
		TBS_RESULT result = Tbsi_Physical_Presence_Command(m_hContext, (const BYTE*)pbRequest, cbRequest, (BYTE*)pbResponse, (PUINT32)cbResponse);
		if (result!=TBS_SUCCESS)
		{
			m_ulError = result;
			return false;
		}		
	} else {
		TBS_COMMAND_LOCALITY locality = TBS_COMMAND_LOCALITY_ZERO;
		TBS_COMMAND_PRIORITY priority = TBS_COMMAND_PRIORITY_NORMAL;
		TBS_RESULT result = Tbsip_Submit_Command(m_hContext, locality, priority, (const BYTE*)pbRequest, cbRequest, (BYTE*)pbResponse, (PUINT32)cbResponse);
		if (result!=TBS_SUCCESS)
		{
			m_ulError = result;
			return false;
		}		
	}
	return true;
}

/*******************************************************
 *   GetCode
 *   Function return last error code.
 *
 *   Returns        : 0 if no error was generated
 *                  : errorCode if some of previous commands 
 *                    failed
 *******************************************************/
unsigned long TTPMChannel::GetCode()
{
	return m_ulError;
}

/*******************************************************
 *   ErrorToString
 *   Function converts error code to text representation of 
 *   errorCode
 *
 *   Returns        : error code converted to string,
 *******************************************************/
const char* TTPMChannel::ErrorToString()
{
	return ErrorToString(m_ulError);
}

/*******************************************************
 *   ErrorToString
 *   Function converts error code to text representation of 
 *   errorCode
 *
 *   Returns : error code converted to string,
 *******************************************************/
const char* TTPMChannel::ErrorToString(unsigned long errorCode)
{
	const char* message = NULL;
	switch (errorCode)
	{
		case TBS_SUCCESS: message = "TBS_SUCCESS"; break;
		case TBS_E_BAD_PARAMETER: message = "TBS_E_BAD_PARAMETER"; break;
		case TBS_E_INTERNAL_ERROR: message = "TBS_E_INTERNAL_ERROR"; break;
		case TBS_E_INVALID_CONTEXT_PARAM: message = "TBS_E_INVALID_CONTEXT_PARAM"; break;
		case TBS_E_INVALID_OUTPUT_POINTER: message = "TBS_E_INVALID_OUTPUT_POINTER"; break;
		case TBS_E_SERVICE_DISABLED: message ="TBS_E_SERVICE_DISABLED"; break;
		case TBS_E_SERVICE_START_PENDING: message = "TBS_E_SERVICE_START_PENDING"; break;
		case TBS_E_TOO_MANY_TBS_CONTEXTS: message = "TBS_E_TOO_MANY_TBS_CONTEXTS"; break;
		case TBS_E_TPM_NOT_FOUND: message = "TBS_E_TPM_NOT_FOUND"; break;
	}
	return message;
}

