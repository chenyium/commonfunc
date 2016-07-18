/******************************************************************************
 * 
 *  File:  safe_string.h
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
 *  The declaration of the Csafe_string class.
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
#ifndef _SAFE_STRING_H_ 
#define	_SAFE_STRING_H_ 

template <size_t size>
int _cdecl safe_sprintf(char (&buffer)[size],
		const char *format, ...); // C++ only
template <size_t size>
int _cdecl safe_sprintf(wchar_t (&buffer)[size],
		const wchar_t *format, ...); // C++ only

int _cdecl safe_sprintf(char *buffer, size_t size,
		const char *format, ...);
int _cdecl safe_sprintf(wchar_t *buffer, size_t size,
		const wchar_t *format, ...);

template <size_t size>
int _cdecl safe_overwrite(char (&buffer)[size],
		const char *format, ...); // C++ only
template <size_t size>
int _cdecl safe_overwrite(wchar_t (&buffer)[size],
		const wchar_t *format, ...); // C++ only

int _cdecl safe_overwrite(char *buffer, size_t size,
        const char *format, ...);
int _cdecl safe_overwrite(wchar_t *buffer, size_t size,
        const wchar_t *format, ...);

#include "safe_string.template.cpp"

#endif  _SAFE_STRING_H_
