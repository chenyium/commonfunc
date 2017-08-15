/******************************************************************************
 * 
 *  File:  common_func.h
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
 *  The declaration of the Ccommon_func class.
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
#ifndef _COMMON_FUNC_H_
#define _COMMON_FUNC_H_

#ifdef _UNICODE
#define hexstr2string hexstr2stringw
#define string2hexstr string2hexstrw
#define stringtrim    stringtrimw
#define stringiszero  stringiszerow
#define stringisdiff  stringisdiffw
#define stringissame  stringissamew
#define stringcontain stringcontainw
#define CalculateImeiDigit CalculateImeiDigitW
#else
#define hexstr2string hexstr2stringa
#define string2hexstr string2hexstra
#define stringtrim    stringtrima
#define stringiszero  stringiszeroa
#define stringisdiff  stringisdiffa
#define stringissame  stringissamea
#define stringcontain stringcontaina
#define CalculateImeiDigit CalculateImeiDigitA
#endif

#ifdef __cplusplus
extern "C" {
#endif

//! translate hex string to string
/*!
    \ingroup common_func
    \param hex: input hex string, null-terminated source string buffer
    \param len: the number of hex, can be -1
    \param out: output string
    \return  the number of characters stored in out, not counting the terminating null character,
	           or 0 if an error occurred
*/
unsigned int hexstr2stringa(const char *hex, unsigned int len, 
		unsigned char *out, unsigned int outlen);
unsigned int hexstr2stringw(const wchar_t *hex, unsigned int len, 
		wchar_t *out, unsigned int outlen);

//! translate string to hex string
/*!
    \ingroup common_func
    \param str: input string 
    \param len: the number of str, cannot be -1
    \param out: output hex string
    \return  the number of characters stored in out, not counting the terminating null character,
	           or 0 if an error occurred
*/
unsigned int string2hexstra(const unsigned char *str, unsigned int len,
		char *out, unsigned int outlen);
unsigned int string2hexstrw(const wchar_t *str, unsigned int len,
		wchar_t *out, unsigned int outlen);


char*    stringtrima(char *str);
wchar_t* stringtrimw(wchar_t *str);
bool     stringiszeroa(char *str);
bool     stringiszerow(wchar_t *str);
bool     stringisdiffa(const char *str1, const char *str2);
bool     stringisdiffw(const wchar_t *str1, const wchar_t *str2);
bool     stringissamea(const char *str1, const char *str2);
bool     stringissamew(const wchar_t *str1, const wchar_t *str2);
bool     stringcontaina(const char *src, const char *sub);
bool     stringcontainw(const wchar_t *src, const wchar_t *sub);

char    * stringdeletea(char * source, char * del);
wchar_t * stringdeletew(wchar_t * source, wchar_t * del);

//! Wide char change to multi byte
/*!
    \ingroup common_func
    \param lpWideCharStr: input string, null-terminated source string buffer
    \return  the number of characters stored in out, not counting the terminating null character,
	           or 0 if an error occurred
*/
int WideChar2MultiByte(const wchar_t* lpWideCharStr, 
        char* lpMultiByteStr, int cbMultiByte);

//! Multi byte change to wide char
/*!
    \ingroup common_func
    \param lpMultiByteStr: input string, null-terminated source string buffer
    \return  the number of characters stored in out, not counting the terminating null character,
	           or 0 if an error occurred
*/
int MultiByte2WideChar(const char* lpMultiByteStr, 
        wchar_t* lpWideCharStr, int cchWideChar);

int WideChar2MultiByteHex(const wchar_t* lpWideCharStr, int cchWideChar, 
        unsigned char* lpMultiByteStr, int cbMultiByte);
int MultiByte2WideCharHex(const unsigned char* lpMultiByteStr, int cbMultiByte, 
		wchar_t* lpWideCharStr, int cchWideChar);

#define deletehandle(object) \
	do { if (object) CloseHandle(object), object = NULL; } while(0);
#define deletearrays(object) \
	do { if (object) delete[] object, object = NULL; } while(0);
#define deletepoints(object) \
	do { if (object) delete   object, object = NULL; } while(0);
#define sizeofarrays(object) (sizeof(object) / sizeof(object[0]))

bool CreateDirectoryLoop(const wchar_t *path);
void EmptyDirectory(const wchar_t *path);

char*    CalculateImeiDigitA(char*    imei);
wchar_t* CalculateImeiDigitW(wchar_t* imei);

#ifdef __cplusplus
}
#endif

void _cdecl OutputDebugFormat(const char *prefix, const char *format, ...);
void _cdecl OutputDebugFormat(const wchar_t *prefix, const wchar_t *format, ...);

#include <windows.h>

class CCriticalCreate {
public:
	CCriticalCreate(CRITICAL_SECTION * _critical) { 
		critical = _critical; InitializeCriticalSection(_critical); 
	}
	~CCriticalCreate() { DeleteCriticalSection(critical); }
private:
	CRITICAL_SECTION * critical;
};

class CCriticalCustom {
public:
	CCriticalCustom(CRITICAL_SECTION * _critical) {
		critical = _critical; EnterCriticalSection(critical); 
	}
	~CCriticalCustom() { LeaveCriticalSection(critical); }
private:
	CRITICAL_SECTION * critical;
};

#endif  _COMMON_FUNC_H_
