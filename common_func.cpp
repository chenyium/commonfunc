/******************************************************************************
 * 
 *  File:  common_func.cpp
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
 *  The implementation of the Ccommon_func class.
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
#include "common_func.h"

/*!
 * Includes
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>


/*!
 * author: chenyao
 *****************************************************************************/
unsigned int hexstr2stringa(const char *hex, unsigned int len, 
		unsigned char *out, unsigned int outlen)
{
	if (0 >= len) len = strlen(hex);
	if (0 == len) return 0;

	unsigned int length;
	if (0 == len % 2)
		length = (unsigned int) (len / 2);
	else 
		length = (unsigned int) (len / 2) + 1;

	if (NULL == out || 0 >= outlen)
		return length + 1;

	if (length >= outlen)
		return 0;

	char dest[3] = {0};
	for (unsigned int loop = 0; loop < length; loop++) {
		strncpy_s(dest, _countof(dest), hex + 2*loop, 2);
		memset(out + loop, (unsigned char) 
				strtol(dest, NULL, 16), 1);
	}

	out[length] = '\0';

	return length;
}

unsigned int hexstr2stringw(const wchar_t *hex, unsigned int len, 
		wchar_t *out, unsigned int outlen)
{
	if (0 >= len) len = wcslen(hex);
	if (0 == len) return 0;

	unsigned int length;
	if (0 == len % 2)
		length = (unsigned int) (len / 2);
	else 
		length = (unsigned int) (len / 2) + 1;

	if (NULL == out || 0 >= outlen)
		return length + 1;

	if (length >= outlen)
		return 0;

	wchar_t dest[3] = {0};
	for (unsigned int loop = 0; loop < length; loop++) {
		wcsncpy_s(dest, _countof(dest), hex + 2*loop, 2);
		wmemset(out + loop, (wchar_t) wcstol(dest, NULL, 16), 1);
	}

	out[length] = L'\0';

	return length;
}

unsigned int string2hexstra(const unsigned char *str, unsigned int len,
		char *out, unsigned int outlen)
{
	if (0 >= len) return 0;

	unsigned int length = (unsigned int) (len * 2);

	if (NULL == out || 0 >= outlen)
		return length + 1;

	if (length >= outlen)
		return 0;

	for (unsigned int loop = 0; loop < length; loop+=2) {
		sprintf_s(out + loop, 3, "%02X", *str++);
	}

	out[length] = '\0';

	return length;
}

unsigned int string2hexstrw(const wchar_t *str, unsigned int len,
		wchar_t *out, unsigned int outlen)
{
	if (0 >= len) return 0;

	unsigned int length = (unsigned int) (len * 2);

	if (NULL == out || 0 >= outlen)
		return length + 1;

	if (length >= outlen)
		return 0;

	for (unsigned int loop = 0; loop < length; loop+=2) {
		swprintf_s(out + loop, 3, L"%02X", *str++);
	}

	out[length] = L'\0';

	return length;
}

#define IS_SPACEA(c) \
	((c== ' ' || c== '\t' || c== '\r' || c== '\n' || c== '\v' || c== '\f') ? true : false)
#define IS_SPACEW(c) \
	((c==L' ' || c==L'\t' || c==L'\r' || c==L'\n' || c==L'\v' || c==L'\f') ? true : false)
#define IS_END(c) ((c==0) ? true : false)

char* stringtrima(char *str)
{
	if (NULL == str || IS_END(*str))
		return str;

	char *tail, *head;
	for (tail = str; !IS_END(*tail); tail++);

	for (--tail; tail >= str; tail--) {
		if (!IS_SPACEA(*tail)) 
			break;
	}

	*++tail = 0;

	for (head = str; head < tail; head++) {
		if (!IS_SPACEA(*head)) 
			break;
	}

	if (head != str)
		memmove(str, head, tail - head + 1);

	return str;
}

wchar_t* stringtrimw(wchar_t *str)
{
	if (NULL == str || IS_END(*str))
		return str;

	wchar_t *tail, *head;
	for (tail = str; !IS_END(*tail); tail++);

	for (--tail; tail >= str; tail--) {
		if (!IS_SPACEW(*tail)) 
			break;
	}

	*++tail = 0;

	for (head = str; head < tail; head++) {
		if (!IS_SPACEW(*head)) 
			break;
	}

	if (head != str)
		wmemmove(str, head, tail - head + 1);

	return str;
}

bool stringiszeroa(char *str) 
{
	if (NULL == str) return true;
	return !!IS_END(*str);
}

bool stringiszerow(wchar_t *str) 
{
	if (NULL == str) return true;
	return !!IS_END(*str);
}

bool stringisdiffa(const char *str1, const char *str2)
{
	if (NULL == str1 || NULL == str2) 
		return false;
	return 0 == strcmp(str1, str2) ? false : true;
}

bool stringisdiffw(const wchar_t *str1, const wchar_t *str2)
{
	if (NULL == str1 || NULL == str2) 
		return false;
	return 0 == wcscmp(str1, str2) ? false : true;
}

bool stringissamea(const char *str1, const char *str2)
{
	if (NULL == str1 || NULL == str2) 
		return false;
	return 0 == strcmp(str1, str2) ? true : false;
}

bool stringissamew(const wchar_t *str1, const wchar_t *str2)
{
	if (NULL == str1 || NULL == str2) 
		return false;
	return 0 == wcscmp(str1, str2) ? true : false;
}

bool stringcontaina(const char *src, const char *sub)
{
	if (NULL == src || IS_END(*src))
		return false;
	if (NULL == sub || IS_END(*sub))
		return false;
	return NULL == strstr(src, sub) ? false : true;
}

bool stringcontainw(const wchar_t *src, const wchar_t *sub)
{
	if (NULL == src || IS_END(*src))
		return false;
	if (NULL == sub || IS_END(*sub))
		return false;
	return NULL == wcsstr(src, sub) ? false : true;
}

char * stringdeletea(char * source, char * del)
{
	if (NULL == source || NULL == del)
		return source;

	for (char * index = del; !IS_END(*index); index++) {
		char *head, *tail;

		for (head = tail = source; !IS_END(*head); head++) {
			if (*head != *index) {
				*tail++ = *head;
			}
		}

		*tail = '\0';
	}

	return source;
}

wchar_t * stringdeletew(wchar_t * source, wchar_t * del)
{
	if (NULL == source || NULL == del)
		return source;

	for (wchar_t * index = del; !IS_END(*index); index++) {
		wchar_t *head, *tail;

		for (head = tail = source; !IS_END(*head); head++) {
			if (*head != *index) {
				*tail++ = *head;
			}
		}

		*tail = L'\0';
	}

	return source;
}

/*!
 * author: chenyao
 ******************************************************************************/
#include <windows.h>
int WideChar2MultiByte(const wchar_t* lpWideCharStr, 
        char* lpMultiByteStr, int cbMultiByte)
{
	char* pMultiByteStr = NULL;
	int nLenOfMultiByteStr = 0;

	nLenOfMultiByteStr = WideCharToMultiByte(CP_ACP, 0, 
            lpWideCharStr, -1, NULL, 0, NULL, NULL);
	if (0 == nLenOfMultiByteStr)
		return 0;

	pMultiByteStr = (char*) HeapAlloc(GetProcessHeap(), 0, 
            nLenOfMultiByteStr * sizeof(char));
	if (NULL == pMultiByteStr)
		return 0;

	memset(pMultiByteStr, 0, nLenOfMultiByteStr * sizeof(char));

	int length = WideCharToMultiByte(CP_ACP, 0, 
            lpWideCharStr, -1, pMultiByteStr, nLenOfMultiByteStr,
            NULL, NULL);
	if (0 == length)
        goto Clearup;

	if (length > cbMultiByte) {
		length = 0;
		goto Clearup;
	}

	if (length > 0)
		memcpy_s(lpMultiByteStr, cbMultiByte, pMultiByteStr, length--);

Clearup:
	HeapFree(GetProcessHeap(), 0, (void*) pMultiByteStr);
	return length;
}

int MultiByte2WideChar(const char* lpMultiByteStr, 
        wchar_t* lpWideCharStr, int cchWideChar)
{
	wchar_t* pWideCharStr = NULL;
	int nLenOfWideCharStr = 0;

	/** cbMultiByte = -1, MultiByteToWideChar return the size of buffer 
     *      (counting the terminating null character)
     **/
	nLenOfWideCharStr = MultiByteToWideChar(CP_ACP, 0, 
            lpMultiByteStr, -1, NULL, 0);
	if (0 == nLenOfWideCharStr)
		return 0;

	pWideCharStr = (wchar_t*) HeapAlloc(GetProcessHeap(), 0, 
            nLenOfWideCharStr * sizeof(wchar_t));
	if (NULL == pWideCharStr)
		return 0;

	memset(pWideCharStr, 0, nLenOfWideCharStr * sizeof(wchar_t));

	int length = MultiByteToWideChar(CP_ACP, 0, 
            lpMultiByteStr, -1, pWideCharStr, nLenOfWideCharStr);
	if (0 == length)
        goto Clearup;

	if (length > cchWideChar) {
		length = 0;
		goto Clearup;
	}

	if (length > 0)
		wmemcpy_s(lpWideCharStr, cchWideChar, pWideCharStr, length--);

Clearup:
	HeapFree(GetProcessHeap(), 0, (void*) pWideCharStr);
	return length;
}

int WideChar2MultiByteHex(const wchar_t* lpWideCharStr, int cchWideChar, 
        unsigned char* lpMultiByteStr, int cbMultiByte)
{
	wchar_t* pBufferW = NULL;
	char*    pBufferA = NULL;

	int nLenOfMultiByte = 2 * cchWideChar + 1;

    pBufferW = (wchar_t*) calloc(nLenOfMultiByte, sizeof(wchar_t));
    pBufferA = (char*)    calloc(nLenOfMultiByte, sizeof(char));
    if (NULL == pBufferW || NULL == pBufferA)
        return 0;

    int length = string2hexstrw(lpWideCharStr, cchWideChar, 
            pBufferW, nLenOfMultiByte); 
    if (0 == length)
        goto Clearup;

	length = WideChar2MultiByte(pBufferW, pBufferA, nLenOfMultiByte);
	if (0 == length)
        goto Clearup;

    length = hexstr2stringa(pBufferA, strlen(pBufferA), 
            lpMultiByteStr, cbMultiByte);
    if (0 == length)
        goto Clearup;

Clearup:
    free(pBufferW);
    free(pBufferA);
	return length;
}

int MultiByte2WideCharHex(const unsigned char* lpMultiByteStr, int cbMultiByte, 
		wchar_t* lpWideCharStr, int cchWideChar)
{
	wchar_t* pBufferW = NULL;
	char*    pBufferA = NULL;

	int nLenOfWideChar = 2 * cbMultiByte + 1;

    pBufferW = (wchar_t*) calloc(nLenOfWideChar, sizeof(wchar_t));
    pBufferA = (char*)    calloc(nLenOfWideChar, sizeof(char));
    if (NULL == pBufferW || NULL == pBufferA)
        return 0;

    int length = string2hexstra(lpMultiByteStr, cbMultiByte, 
            pBufferA, nLenOfWideChar); 
    if (0 == length) 
        goto Clearup;

	length = MultiByte2WideChar(pBufferA, pBufferW, nLenOfWideChar);
    if (0 == length)
        goto Clearup;

    length = hexstr2stringw(pBufferW, wcslen(pBufferW), 
            lpWideCharStr, cchWideChar);
    if (0 == length)
        goto Clearup;

Clearup:
    free(pBufferW);
    free(pBufferA);
	return length;
}

/*!
 * author: chenyao
 ******************************************************************************/
#include <vector>
#include <Shlwapi.h>

#pragma warning(push)
#pragma warning(disable: 4127)

bool CreateDirectoryLoop(const wchar_t *path)
{
	if (NULL == path)
		return false;

	wchar_t *lpPath = _wcsdup(path);
	std::vector<std::wstring> vecPath;

	do {
		if (::PathIsDirectoryW(lpPath)) 
            break;
		vecPath.push_back(std::wstring(lpPath));
		::PathRemoveFileSpecW(lpPath);
	} while (1);

	while (!vecPath.empty()) {
		if (!::CreateDirectoryW(vecPath.back().c_str(), NULL)) {
			free(lpPath);
			return false;
		}
		vecPath.pop_back();
	}

	free(lpPath);
	return true;
}

#pragma warning(pop)

void EmptyDirectory(const wchar_t *path)
{
	if (NULL == path)
		return;

	wchar_t szPath[512] = {0};
	wchar_t szName[512] = {0};

	wcscpy_s(szPath, sizeofarrays(szPath), path);
	wcscpy_s(szName, sizeofarrays(szName), path);
	PathAppendW(szName, L"*");

	WIN32_FIND_DATAW findFileData;
	HANDLE hFind = ::FindFirstFileW(szName, &findFileData);
	if (INVALID_HANDLE_VALUE == hFind)
		return;

	do {

		if (findFileData.cFileName[0] == L'.')
			continue;

		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			wcscpy_s(szPath, sizeofarrays(szPath), path);
			PathAppendW(szPath, findFileData.cFileName);
			EmptyDirectory(szPath); // loop
		} else {
			wcscpy_s(szName, sizeofarrays(szName), path);
			PathAppendW(szName, findFileData.cFileName);
			DeleteFileW(szName);
		}

	} while (::FindNextFileW(hFind, &findFileData));

	::FindClose(hFind);
	::RemoveDirectoryW(path);

	return;
}

char* CalculateImeiDigitA(char* imei) 
{
	char *head;

	if (NULL == imei || 14 > strlen(imei))
		return imei;

	imei[14] = 0;

	for (head = imei; head != imei + 14; head++) {
		imei[14] += 0 == (head - imei) % 2 ? *head - 48 : 
				(*head - 48)*2 / 10 + (*head - 48)*2 % 10;
	}

	imei[14] = (char) ((10 - imei[14] % 10) % 10 + 48);
	imei[15] = 0;

	return imei;
}

wchar_t* CalculateImeiDigitW(wchar_t* imei) 
{
	wchar_t *head;

	if (NULL == imei || 14 > wcslen(imei))
		return imei;

	imei[14] = 0;

	for (head = imei; head != imei + 14; head++) {
		imei[14] += 0 == (head - imei) % 2 ? *head - 48 : 
				(*head - 48)*2 / 10 + (*head - 48)*2 % 10;
	}

	imei[14] = (wchar_t) ((10 - imei[14] % 10) % 10 + 48);
	imei[15] = 0;

	return imei;
}

void _cdecl OutputDebugFormat(const wchar_t *prefix, 
		const wchar_t *format, ...) {
    va_list argptr;
    wchar_t buffer[512] = {0};

    va_start(argptr, format);
    _vsnwprintf_s(buffer, _TRUNCATE, format, argptr);
    va_end(argptr);

    wchar_t message[512] = {0};
    _snwprintf_s(message, _TRUNCATE, L"[%s] %s", 
            NULL == prefix ? L"common" : prefix, buffer);
    OutputDebugStringW(message);
}

void _cdecl OutputDebugFormat(const char *prefix, 
		const char *format, ...) {
    va_list argptr;
    char buffer[512] = {0};

    va_start(argptr, format);
    _vsnprintf_s(buffer, _TRUNCATE, format, argptr);
    va_end(argptr);

    char message[512] = {0};
    _snprintf_s(message, _TRUNCATE, "[%s] %s", 
            NULL == prefix ? "common" : prefix, buffer);
    OutputDebugStringA(message);
}
