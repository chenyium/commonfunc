/******************************************************************************
 * 
 *  File:  safe_string.cpp
 *  -----
 * 
 *  Copyright Statement:
 *  --------------------
 *  This software is protected by Copyright and the information contained
 *  herein is confidential. 
 *  The software could not be copied and the information contained herein
 *  could not be used or disclosed except with the written permission of 
 *  ...
 * 
 *  Project:
 *  --------  
 * 
 *  Description:
 *  ------------
 *  The implementation of the Csafe_string class.
 *
 * 
 *  Modification History:
 *  ---------------------
 *  Date        Version    Author         Details
 *  ----        -------    ------         -------
 *              1.1        ChenYao        Original
 *
 ******************************************************************************
 *
 *
 *
 *****************************************************************************/
#include "safe_string.h"

/*!
 * Includes
 *****************************************************************************/
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <wchar.h>

int _cdecl safe_sprintf(char *buffer, size_t size,
        const char *format, ...)
{
	if (NULL == buffer 
			|| NULL == format
			|| 0 >= size)
		return -1;

	memset(buffer, 0, size * sizeof(char));

	va_list ap;
	va_start(ap, format);

	int res = -1;
	res = _vsnprintf_s(buffer, size, _TRUNCATE,
				format, ap);

	va_end(ap);

	return res;
}

int _cdecl safe_sprintf(wchar_t *buffer, size_t size,
		const wchar_t *format, ...)
{
	if (NULL == buffer 
			|| NULL == format
			|| 0 >= size)
		return -1;

	memset(buffer, 0, size * sizeof(wchar_t));

	va_list ap;
	va_start(ap, format);

	int res = -1;
	res = _vsnwprintf_s(buffer, size, _TRUNCATE,
				format, ap);

	va_end(ap);

	return res;
}

int _cdecl safe_overwrite(char *buffer, size_t size,
        const char *format, ...)
{
	if (NULL == buffer || NULL == format || 0 >= size)
		return -1;

	char *interim = (char*) calloc(size, sizeof(char));

	va_list ap;
	va_start(ap, format);

	int res = -1;
	res = _vsnprintf_s(interim, size, _TRUNCATE,
				format, ap);

	va_end(ap);

	memset(buffer, 0, size * sizeof(char));
	memcpy(buffer, interim, size);

	free(interim), interim = NULL;
	return res;
}

int _cdecl safe_overwrite(wchar_t *buffer, size_t size,
        const wchar_t *format, ...)
{
	if (NULL == buffer || NULL == format || 0 >= size)
		return -1;

	wchar_t *interim = (wchar_t*) calloc(size, sizeof(wchar_t));

	va_list ap;
	va_start(ap, format);

	int res = -1;
	res = _vsnwprintf_s(interim, size, _TRUNCATE,
				format, ap);

	va_end(ap);

	wmemset(buffer, 0, size);
	wmemcpy(buffer, interim, size);

	free(interim), interim = NULL;
	return res;
}
