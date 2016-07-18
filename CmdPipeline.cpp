/******************************************************************************
 * 
 *  File:  CmdPipeline.cpp
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
 *  The implementation of the CCmdPipeline class.
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

/*!
 * Includes
 *****************************************************************************/
#include "CmdPipeline.h"
#include "safe_string.h"
#include "common_func.h"

/*!
 * Includes
 *****************************************************************************/
#include <WinBase.h>
#include <Shlwapi.h>
#include <wchar.h>
#include <tchar.h>

#pragma warning(disable:4127)

/*!
 * Definition
 *****************************************************************************/
namespace pipeline {

namespace vol {
static const int LEN_CMD       = 512;
static const int LEN_REASON    = 256;
static const int LEN_BUFF      = 256;
static const int LEN_BUFFER    = 1024*4;
}

namespace cmd {
static const wchar_t* ADB_COMMAND       = L"adb -s %s %s";
static const wchar_t* ADB_DEVICES       = L"adb devices";
static const wchar_t* ADB_STARTSERVER   = L"adb start-server";
static const wchar_t* ADB_FORWARD       = L"adb -s %s forward tcp:%d tcp:%d";
static const wchar_t* ADB_INSTALL       = L"adb -s %s install -r \"%s\"";
static const wchar_t* ADB_PULL_FILE     = L"adb -s %s pull %s \"%s\"";
static const wchar_t* ADB_PUSH_FILE     = L"adb -s %s push \"%s\" %s";
static const wchar_t* ADB_GET_DESC      = L"adb -s %s get-descriptor";
static const wchar_t* ADB_GET_STATE     = L"adb -s %s get-state";
static const wchar_t* ADB_USB           = L"adb -s %s usb";
}

namespace cmd {
static const wchar_t* ADB_SHELL_S       = L"adb shell %s";
static const wchar_t* ADB_SHELL_M       = L"adb -s %s shell %s";
static const wchar_t* ADB_SHELL_GETPROP = L"adb -s %s shell getprop %s";
static const wchar_t* ADB_SHELL_SETPROP = L"adb -s %s shell setprop %s %s";
static const wchar_t* ADB_SHELL_LS      = L"adb -s %s shell ls %s";
static const wchar_t* ADB_SHELL_PSN     = L"flashcmd 0 getpsn";
}

namespace label {
static const wchar_t* ADB_TOKEN_START   = L"startserver_result";
static const wchar_t* ADB_TOKEN_SHELL   = L"shell_complete";
static const wchar_t* ADB_TOKEN_DEVICES = L"devices_result";
static const wchar_t* ADB_TOKEN_FORWARD = L"forward_result";
static const wchar_t* ADB_TOKEN_PULL    = L"pull_result";
static const wchar_t* ADB_TOKEN_PUSH    = L"push_result";
static const wchar_t* ADB_TOKEN_REBOOT  = L"reboot_result";
static const wchar_t* ADB_TOKEN_INSTALL = L"install_result";
static const wchar_t* ADB_TOKEN_DESC    = L"descriptor_result";
static const wchar_t* ADB_TOKEN_STATE   = L"state_result";
static const wchar_t* ADB_TOKEN_USB     = L"usb";
static const wchar_t* ADB_TOKEN_KBS     = L"KB/s";
static const wchar_t* ADB_TOKEN_OKEY    = L"OKEY";
static const wchar_t* ADB_TOKEN_ROOT    = L"root@";
}

namespace label {
static const wchar_t* ADB_INSTALL       = L"Success";
static const wchar_t* ADB_SUCCESS       = L"success";
static const wchar_t* ADB_FAILURE       = L"failure";
static const wchar_t* DEVICES_LIST      = L"List of devices attached";
static const wchar_t* DEVICE_NOT_FOUND  = L"error: device not found";
static const wchar_t* REBOOT_USB_MODE   = L"restarting in USB mode";
}

namespace wlan {
static const wchar_t* ADB_CONNECT          = L"adb connect %s";
static const wchar_t* ADB_DISCONNECT       = L"adb disconnect %s";
static const wchar_t* ADB_TOKEN            = L"connected to %s:%d";
static const wchar_t* ADB_TOKEN_CONNECT    = L"connect_result";
static const wchar_t* ADB_TOKEN_DISCONNECT = L"disconnect_result";
static const wchar_t* ADB_STATUS           = L"connected to";
const int ADB_PORT = 5555;
}

namespace cmd {
	static const wchar_t* FASTBOOT_COMMAND   = L"fastboot %s";
	static const wchar_t* FASTBOOT_COMMAND_M = L"fastboot -s \"%s\" %s";
	static const wchar_t* FASTBOOT_PSN_R     = L"fastboot %s";
	static const wchar_t* FASTBOOT_PSN_R_M   = L"fastboot -s \"%s\" %s";
}

namespace label {
	static const wchar_t* FASTBOOT_TOKEN = L"finished. total time";
	static const wchar_t* FASTBOOT_PASS  = L"OKAY";
}


namespace cmd {
	static const wchar_t* FLASHCMD_PREPARE = L"flashcmd %d prepare";
	static const wchar_t* FLASHCMD_READ    = L"flashcmd %d read";
	static const wchar_t* FLASHCMD_BURN    = L"flashcmd %d burn";
}

namespace label {
	static const wchar_t* FLASHCMD_TOKEN = L"OKAY";
}
} using namespace pipeline;

/*!
 * Definitions
 *****************************************************************************/
#define DELETE_HANDLE(handle) \
	do { if (NULL != handle) CloseHandle(handle), handle = NULL; } while(0);
#define DELETE_ARRAY(arr) \
	do { if (NULL != arr) delete[] arr, arr = NULL; } while(0);

/*!
 * Definitions
 *****************************************************************************/
#define BUFFER_SIZE    (1024*10)

/*!
 * Class Implement - CCmdPipeline
 *****************************************************************************/
CCmdPipeline::CCmdPipeline(void) 
	: m_function(NULL)
	, m_object(NULL)
	, m_hInputRead(NULL)
	, m_hInputWrite(NULL)
	, m_hOutputRead(NULL)
	, m_hOutputWrite(NULL)
	, m_hErrorWrite(NULL)
 	, m_hProcessCmd(NULL)
{
	wchar_t szModule[MAX_PATH] = {0};
	GetModuleFileNameW(NULL, szModule, MAX_PATH);
	PathRemoveFileSpecW(szModule);
	PathAppendW(szModule, L"");

	memset(m_szModule, 0, sizeof(m_szModule));
	safe_sprintf(m_szModule, L"%s", szModule);

	memset(m_szTokens, 0, sizeof(m_szTokens));
    memset(m_szErrors, 0, sizeof(m_szErrors));
}

/*!
 * Function:    
 * Parameters:  
 * Description: 
 * Inputs:      
 * Outputs:     
 * Return:      
 * Remark:      ChenYao Modify. 2013-12-17 16:45. 
 *****************************************************************************/
CCmdPipeline::~CCmdPipeline(void)
{
	// delete handles
	DELETE_HANDLE(m_hInputRead);
	DELETE_HANDLE(m_hInputWrite);
	DELETE_HANDLE(m_hOutputRead);
	DELETE_HANDLE(m_hOutputWrite);
	DELETE_HANDLE(m_hErrorWrite);

	AbortProcess();
}

/*!
 * Function:    InitializePipeline
 * Parameters:  CString&
 * Description: 
 * Inputs:      
 * Outputs:     
 * Return:      
 * Remark:      ChenYao add. 2014-2-27 16:16. 
 *     m_hInputRead   子进程读出数据
 *     m_hInputWrite  主进程写入数据
 *     m_hOutputWrite 子进程写入数据
 *     m_hOutputRead  主进程读出数据
 *****************************************************************************/
bool CCmdPipeline::Initialize()
{
	HANDLE hOutputReadTmp = NULL;
	HANDLE hInputWriteTmp = NULL;

	// Set the bInheritHandle flag, so pipe handles are inherited. 
	SECURITY_ATTRIBUTES saAttr;
	memset(&saAttr, 0, sizeof(SECURITY_ATTRIBUTES));
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.lpSecurityDescriptor = NULL;
	saAttr.bInheritHandle = TRUE;

	// Create the child output pipe.
	if (!CreatePipe(&hOutputReadTmp, &m_hOutputWrite, &saAttr, 0)) {
		safe_sprintf(m_szErrors, L"create stdout pipe failed");
		return false;
	}

	// Create the child input pipe.
	if (!CreatePipe(&m_hInputRead, &hInputWriteTmp, &saAttr, 0)) {
		safe_sprintf(m_szErrors, L"create stdin pipe failed");
		return false;
	}

	// Create a duplicate of the output write handle for the std error write handle. 
	// This is necessary in case the child application closes one of its std output handles.
	if (!DuplicateHandle(GetCurrentProcess(), m_hOutputWrite, 
				GetCurrentProcess(), &m_hErrorWrite, 
				0, TRUE, DUPLICATE_SAME_ACCESS)) {
		safe_sprintf(m_szErrors, L"DuplicateHandle Error");
		return false;
	}

	// Create new output read handle and the input write handles. Set
	// the Properties to FALSE. Otherwise, the child inherits the
	// properties and, as a result, non-closeable handles to the pipes
	// are created.
	if (!DuplicateHandle(GetCurrentProcess(), hOutputReadTmp,
				GetCurrentProcess(), &m_hOutputRead, // Address of new handle.
				0, FALSE/*Make it uninheritable*/, DUPLICATE_SAME_ACCESS)) {
		safe_sprintf(m_szErrors, L"DuplicateHandle Error");
		return false;
	}

	if (!DuplicateHandle(GetCurrentProcess(), hInputWriteTmp,
				GetCurrentProcess(), &m_hInputWrite, // Address of new handle.
				0, FALSE/*Make it uninheritable*/, DUPLICATE_SAME_ACCESS)) {
		safe_sprintf(m_szErrors, L"DuplicateHandle Error");
		return false;
	}

	DELETE_HANDLE(hOutputReadTmp);
	DELETE_HANDLE(hInputWriteTmp);

	// 设置 OurtputRead 为非阻塞模式
	DWORD dwMode = PIPE_NOWAIT;
	if (!SetNamedPipeHandleState(m_hOutputRead, &dwMode, NULL, NULL)) {
		safe_sprintf(m_szErrors, L"SetNamedPipeHandleState Error");
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 *
 *****************************************************************************/
void CCmdPipeline::SetTokenString(const wchar_t *token) 
{
	safe_sprintf(m_szTokens, L"%s", token);
}

/*!
 * author: chenyao
 *
 *****************************************************************************/
bool CCmdPipeline::CommandExec(const wchar_t *command)
{
	// Set up members of the STARTUPINFO structure. 
	// This structure specifies the STDIN handle for redirection. 
	STARTUPINFO siStartInfo = {sizeof(STARTUPINFO)}; 
	siStartInfo.hStdInput   = m_hInputRead;   // 子进程的标准输入HANDLE
	siStartInfo.hStdOutput  = m_hOutputWrite; // 子进程的标准输出HANDLE
	siStartInfo.hStdError   = m_hErrorWrite;
	siStartInfo.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	siStartInfo.wShowWindow |= SW_HIDE;

	// Set up members of the PROCESS_INFORMATION structure.  
	PROCESS_INFORMATION piProcInfo; 
	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
	
	// Create the child process.   
	wchar_t szCommand[vol::LEN_CMD] = {};
    safe_sprintf(szCommand, L"%s", command);
	if (!CreateProcess(NULL, szCommand,  // command line 
			NULL,             // process security attributes 
			NULL,             // primary thread security attributes 
			TRUE,             // handles are inherited 
			0,                // creation flags 
			NULL,             // use parent's environment 
			m_szModule,       // use parent's current directory 
			&siStartInfo,     // STARTUPINFO pointer 
			&piProcInfo))     // receives PROCESS_INFORMATION 
	{
        safe_sprintf(m_szErrors, L"create command (%d)", GetLastError());
		return false;
	}

    CloseHandle(piProcInfo.hThread), piProcInfo.hThread = NULL;
	m_hProcessCmd = piProcInfo.hProcess;

	return true;
}

/*!
 * author: chenyao
 *
 *****************************************************************************/
bool CCmdPipeline::CommandSend(const wchar_t *command, int cmdlen)
{
	unsigned char *pCommand = NULL;

	if (NULL == command || 0 == cmdlen) {
		safe_sprintf(m_szErrors, _T("command is null"));
		goto _cleanup;
	}

	pCommand = new unsigned char[cmdlen+1]();

    int nLength = WideChar2MultiByteHex(command, cmdlen, pCommand, cmdlen+1);

    if (0 >= nLength) {
		safe_sprintf(m_szErrors, L"WideChar2MultiByteHex failed");
		goto _cleanup;
    }
	
	DWORD dwWriteLength = 0;
	if (!WriteFile(m_hInputWrite, pCommand, nLength, &dwWriteLength, NULL)
            || nLength != (int) dwWriteLength) {
        safe_sprintf(m_szErrors, L"WriteFile failed (%d)", GetLastError());
		goto _cleanup;
	}
	
	delete[] pCommand, pCommand = NULL;
	return true;

_cleanup:
	if (pCommand)
		delete[] pCommand, pCommand = NULL;
	return false;
}

/*!
 * author: chenyao
 *
 *****************************************************************************/
int CCmdPipeline::CommandRead(HANDLE removed, int timeout, 
        wchar_t *result, int reslen)
{
    DWORD nCharsRead = 0;
	DWORD nEndedTime = GetTickCount() + timeout * 1000;
	
	do {
		if (WAIT_OBJECT_0 == WaitForSingleObject(removed, 0)) {
            safe_sprintf(m_szErrors, L"device removed");
			goto _cleanup;
		}

		DWORD dwBytesRead;
		char  szBufferTmp[1] = {0};
		PeekNamedPipe(m_hOutputRead, szBufferTmp, 1, &dwBytesRead, NULL, NULL);

        if (0 >= dwBytesRead) {
            Sleep(100);
            continue;
        }

		char  szBuffer[vol::LEN_BUFF] = {0};
		DWORD nBytesRead = 0;

        while (ReadFile(m_hOutputRead, szBuffer, vol::LEN_BUFF,
                    &nBytesRead, NULL)) {

            if (0 == nBytesRead) {
                safe_sprintf(m_szErrors, L"ReadFile failed (%d)", GetLastError());
                goto _cleanup;
            }

            wchar_t *pWideCharStr = new wchar_t[nBytesRead + 1]();
            int nWideChars = MultiByte2WideCharHex((unsigned char*) szBuffer, nBytesRead, 
                    pWideCharStr, nBytesRead+1);
            if (0 >= nWideChars) {
                safe_sprintf(m_szErrors, L"MultiByte2WideCharHex (%d)", GetLastError());
                delete[] pWideCharStr, pWideCharStr = NULL;
                goto _cleanup;
            }

            if ((int) nCharsRead + nWideChars >= reslen) {
                safe_sprintf(m_szErrors, L"buffer is small");
                delete[] pWideCharStr, pWideCharStr = NULL;
                goto _cleanup;
            }

            wmemcpy_s(result + nCharsRead, reslen - nCharsRead, 
                    pWideCharStr, nWideChars);
            delete[] pWideCharStr, pWideCharStr = NULL;

            nCharsRead += nWideChars;
            memset(szBuffer, 0, sizeof(szBuffer));
            nBytesRead = 0;
		}

		if (NULL != wcsstr(result, m_szTokens)) {
			return nCharsRead; // pass
		}

		Sleep(10);
	} while (GetTickCount() <= nEndedTime);

    safe_sprintf(m_szErrors, L"timeout");

_cleanup:
	AbortProcess();
	return -1; // fail
}

void CCmdPipeline::DeleteProcess()
{
	if (NULL != m_hProcessCmd)
		CloseHandle(m_hProcessCmd), m_hProcessCmd = NULL;
}

void CCmdPipeline::AbortProcess()
{
	if (NULL != m_hProcessCmd) {
		TerminateProcess(m_hProcessCmd, 0);
		CloseHandle(m_hProcessCmd), m_hProcessCmd = NULL;
	}
}

void CCmdPipeline::CleanProcess()
{
	if (NULL != m_hProcessCmd) {
		WaitForSingleObject(m_hProcessCmd, INFINITE);
		TerminateProcess(m_hProcessCmd, 0);
		CloseHandle(m_hProcessCmd), m_hProcessCmd = NULL;
	}
}

void CCmdPipeline::CommandClear(HANDLE removed, int timeout)
{
    wchar_t szResult[vol::LEN_BUFFER] = {0};
	SetTokenString(L"anything_clear");
	CommandRead(removed, timeout, szResult, _countof(szResult));
}

/*!
 * author: chenyao
 *
 *****************************************************************************/
bool CCmdPipeline::CommandCatch(wchar_t *result, int reslen)
{
	if (NULL == m_hOutputRead)
		return false;

	DWORD dwBytesRead;
	char  szBufferTmp[1] = {0};

	PeekNamedPipe(m_hOutputRead, szBufferTmp, 1, &dwBytesRead, NULL, NULL);
	if (0 >= dwBytesRead) {
		log_trace(L"CommandCatch: no data");
		return false; // no data
	}

	char  szBuffer[vol::LEN_BUFF] = {0};
    DWORD nCharsRead = 0;
	DWORD nBytesRead = 0;

	while (ReadFile(m_hOutputRead, szBuffer, _countof(szBuffer),
                &nBytesRead, NULL)) {

		if (0 == nBytesRead)
			return false;

		wchar_t *pWideCharStr = new wchar_t[nBytesRead + 1]();
		int nWideChars = MultiByte2WideCharHex((unsigned char*) szBuffer, nBytesRead, 
				pWideCharStr, nBytesRead+1);
		if (0 >= nWideChars) {
			delete[] pWideCharStr, pWideCharStr = NULL;
			return false;
		}

		if ((int) nCharsRead + nWideChars >= reslen) {
			delete[] pWideCharStr, pWideCharStr = NULL;
			return false;
		}

		wmemcpy_s(result + nCharsRead, reslen - nCharsRead, 
				pWideCharStr, nWideChars);
		delete[] pWideCharStr, pWideCharStr = NULL;

		nCharsRead += nWideChars;
		memset(szBuffer, 0, sizeof(szBuffer));
		nBytesRead = 0;
	}

	return true;
}

/*!
 * author: chenyao
 *
 *****************************************************************************/
bool CCmdPipeline::AnalysisAdbResult(wchar_t *result, int reslen,
        const wchar_t *token, bool check)
{
    wchar_t *pEndding = NULL;

    pEndding = wcsstr(result, token);
	if (NULL == pEndding) {
        safe_sprintf(result, reslen, L"endding is empty");
		return false;
    }

    if (false == check) {
        *pEndding = 0, stringtrimw(result);
        return true;
    }

    wchar_t szTemp[vol::LEN_BUFF] = {0};
    safe_sprintf(szTemp, L"%s", pEndding);

    wchar_t *pTokenTemp = NULL;
    wchar_t *pTokenNext = NULL;

    pTokenTemp = wcstok_s(szTemp, L":", &pTokenNext);
    if (NULL == pTokenTemp) {
        safe_sprintf(result, reslen, L"endding is missing");
        return false;
    }

    if (stringisdiffw(stringtrimw(pTokenTemp), token)) {
        safe_sprintf(result, reslen, L"endding is different");
        return false;
    }

    if (stringisdiffw(stringtrimw(pTokenNext), label::ADB_SUCCESS)) {
        safe_sprintf(result, reslen, L"endding is failure");
        return false;
    }

	*pEndding = 0, stringtrimw(result);
	return true;
}

/*!
 * author: chenyao
 * label::ADB_TOKEN_SHELL
 ******************************************************************************/
bool CCmdPipeline::ExecuteAdbShell(HANDLE removed, int timeout, 
        const wchar_t *command, wchar_t *result, int reslen)
{
	if (NULL == command) {
		safe_sprintf(m_szErrors, L"command is null");
		return false;
	}

	if (false == CommandExec(command)) {
		safe_overwrite(m_szErrors, L"send:%s", m_szErrors);
		return false;
	}

    wchar_t szResult[vol::LEN_BUFFER] = {0};

	SetTokenString(label::ADB_TOKEN_SHELL);
	int nResultLen = CommandRead(removed, timeout, 
			szResult, _countof(szResult));
    log_trace(szResult);
	CleanProcess();

	if (0 >= nResultLen) {
		safe_overwrite(m_szErrors, L"read:%s", m_szErrors);
		return false;
	}

	/** Analysis result */
	if (!AnalysisAdbResult(szResult, _countof(szResult), 
                label::ADB_TOKEN_SHELL, false)) {
		safe_sprintf(m_szErrors, L"%s", szResult);
		return false;
	}

	if (NULL != result && 0 != reslen)
		safe_sprintf(result, reslen, L"%s", stringtrimw(szResult));

	return true;
}

/*!
 * author: chenyao
 *
 ******************************************************************************/
bool CCmdPipeline::ExecuteAdbCommand(HANDLE removed, int timeout, 
		const wchar_t *command, const wchar_t *token, wchar_t *result, int reslen)
{
	if (NULL == command || NULL == token)
		return false;

	if (false == CommandExec(command)) {
		safe_overwrite(m_szErrors, L"send:%s", m_szErrors);
		return false;
	}

    wchar_t szResult[vol::LEN_BUFFER] = {0};

	SetTokenString(token);
	int nResultLen = CommandRead(removed, timeout, 
            szResult, _countof(szResult));
	log_trace(szResult);
	CleanProcess();

	if (0 >= nResultLen) {
		safe_overwrite(m_szErrors, L"read:%s", m_szErrors);
		return false;
	}

	/** Analysis result */
	if (!AnalysisAdbResult(szResult, _countof(szResult), token)) {
		safe_sprintf(m_szErrors, L"%s", szResult);
		return false;
	}

	if (NULL != result && 0 != reslen)
		safe_sprintf(result, reslen, L"%s", stringtrimw(szResult));

	return true;
}

/*!
 * author: chenyao
 *
 ******************************************************************************/
bool CCmdPipeline::ExecuteAdb(HANDLE removed, int timeout, const TCHAR *serial, 
		const TCHAR *command, const TCHAR *token, TCHAR *result, int reslen)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_COMMAND, serial, command);
	log_trace(szCommand);

	if (!ExecuteAdbCommand(removed, timeout, 
				szCommand, token, result, reslen)) {
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 *
 ******************************************************************************/
bool CCmdPipeline::ExecuteAdbWithout(const TCHAR *serial, const TCHAR *command)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_COMMAND, serial, command);
	log_trace(szCommand);

	if (false == CommandExec(szCommand)) {
		return false;
	}

	DeleteProcess();

	return true;
}

/*!
 * author: chenyao
 *
 ******************************************************************************/
bool CCmdPipeline::ExecuteShell(HANDLE removed, int timeout, 
        const TCHAR *serial, const TCHAR *command, TCHAR *result, int reslen)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_SHELL_M, serial, command);
	log_trace(szCommand);

	if (!ExecuteAdbShell(removed, timeout, szCommand, result, reslen)) {
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 *
 ******************************************************************************/
bool CCmdPipeline::ExecuteShellWithout(const TCHAR *serial, const TCHAR *command)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_SHELL_M, serial, command);
	log_trace(szCommand);

	if (false == CommandExec(szCommand)) {
		return false;
	}

	DeleteProcess();

	return true;
}

/*!
 * author: chenyao
 *
 *****************************************************************************/
bool CCmdPipeline::ExecuteShellLs(HANDLE removed, int timeout, 
        const TCHAR *serial, const TCHAR *path)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_SHELL_LS, serial, path);
	log_trace(szCommand);

    wchar_t szResult[vol::LEN_BUFF] = {0};

	if (!ExecuteAdbShell(removed, timeout, szCommand, 
                szResult, _countof(szResult))) {
		return false;
	}

	if (stringiszerow(szResult)) {
		safe_sprintf(m_szErrors, L"result is empty");
		return false;
	}

	if (stringisdiffw(szResult, path)) {
		safe_sprintf(m_szErrors, L"file is not existed");
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 *
 *****************************************************************************/
bool CCmdPipeline::ExecuteShellPsn(HANDLE removed, int timeout, 
        const TCHAR *serial, TCHAR *result, int reslen)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_SHELL_PSN, serial);
	log_trace(szCommand);

	if (!ExecuteFlashcmdBase(removed, timeout, serial, szCommand,
				result, reslen)) {
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 *
 ******************************************************************************/
bool CCmdPipeline::ExecuteShellGetprop(HANDLE removed, int timeout, 
        const TCHAR *serial, const TCHAR *prop, TCHAR *result, int reslen)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_SHELL_GETPROP, serial, prop);
	log_trace(szCommand);

    wchar_t szResult[vol::LEN_BUFF] = {0};

	if (!ExecuteAdbShell(removed, timeout, szCommand, 
				szResult, _countof(szResult))) {
		return false;
	}

	safe_sprintf(result, reslen, _T("%s"), szResult);

	if (stringiszerow(result)) {
		safe_sprintf(m_szErrors, L"prop is null");
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 *
 ******************************************************************************/
bool CCmdPipeline::ExecuteShellSetprop(HANDLE removed, int timeout, 
		const TCHAR *serial, const TCHAR *prop, const TCHAR *value)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_SHELL_SETPROP, serial, prop, value);
	log_trace(szCommand);

	wchar_t szResult[vol::LEN_BUFF] = {0};

	if (!ExecuteAdbShell(removed, timeout, szCommand, 
				szResult, _countof(szResult))) {
		return false;
	}

	if (stringcontainw(szResult, label::ADB_FAILURE)) {
		safe_sprintf(m_szErrors, L"setprop failed");
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 * vol::LEN_BUFF
 ******************************************************************************/
bool CCmdPipeline::ExecuteAdbPull(HANDLE removed, int timeout, 
        const TCHAR *serial, const TCHAR *path, const TCHAR *target)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_PULL_FILE, serial, path, target);
	log_trace(szCommand);

    wchar_t szResult[vol::LEN_BUFF] = {0};

	if (!ExecuteAdbCommand(removed, timeout, szCommand, label::ADB_TOKEN_PULL, 
				szResult, _countof(szResult))) {
		return false;
	}

	if (stringiszerow(szResult)) {
		safe_sprintf(m_szErrors, L"result is empty");
		return false;
	}

	if (false == stringcontainw(szResult, label::ADB_TOKEN_KBS)) {
		safe_sprintf(m_szErrors, L"KBS is missing");
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 * vol::LEN_BUFFER
 ******************************************************************************/
bool CCmdPipeline::ExecuteAdbPullPath(HANDLE removed, int timeout, 
        const TCHAR *serial, const TCHAR *path, const TCHAR *target)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_PULL_FILE, serial, path, target);
	log_trace(szCommand);

    wchar_t szResult[vol::LEN_BUFFER] = {0};

	if (!ExecuteAdbCommand(removed, timeout, szCommand, label::ADB_TOKEN_PULL, 
				szResult, _countof(szResult))) {
		return false;
	}

	if (stringiszerow(szResult)) {
		safe_sprintf(m_szErrors, L"result is empty");
		return false;
	}

	if (false == stringcontainw(szResult, label::ADB_TOKEN_KBS)) {
		safe_sprintf(m_szErrors, L"KBS is missing");
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 *
 ******************************************************************************/
bool CCmdPipeline::ExecuteAdbPush(HANDLE removed, int timeout, 
        const TCHAR *serial, const TCHAR *path, const TCHAR *target)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_PUSH_FILE, serial, path, target);
	log_trace(szCommand);

    wchar_t szResult[vol::LEN_BUFF] = {0};

	if (!ExecuteAdbCommand(removed, timeout, szCommand, label::ADB_TOKEN_PUSH, 
				szResult, _countof(szResult))) {
		return false;
	}

	if (stringiszerow(szResult)) {
		safe_sprintf(m_szErrors, L"result is empty");
		return false;
	}

	if (false == stringcontainw(szResult, label::ADB_TOKEN_KBS)) {
		safe_sprintf(m_szErrors, L"KBS is missing");
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 *
 ******************************************************************************/
bool CCmdPipeline::ExecuteAdbForward(HANDLE removed, int timeout, 
        const TCHAR *serial, int client, int remote)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_FORWARD, serial, client, remote);
	log_trace(szCommand);

	if (!ExecuteAdbCommand(removed, timeout, 
                szCommand, label::ADB_TOKEN_FORWARD)) {
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 *
 ******************************************************************************/
bool CCmdPipeline::ExecuteAdbDescription(HANDLE removed, int timeout, 
        const TCHAR *serial, TCHAR *result, int reslen)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_GET_DESC, serial);
	log_trace(szCommand);

    wchar_t szResult[vol::LEN_BUFF] = {0};
	
	if (!ExecuteAdbCommand(removed, timeout, szCommand, label::ADB_TOKEN_DESC, 
                szResult, _countof(szResult))) {
		return false;
	}

	if (stringiszerow(szResult)) {
		safe_sprintf(m_szErrors, L"result is empty");
		return false;
	}

	wchar_t szTemp[vol::LEN_BUFF] = {0};
	wchar_t *pTokenTemp = NULL;
	wchar_t *pTokenNext = NULL;

	wcscpy_s(szTemp, _countof(szTemp), szResult);
	pTokenTemp = wcstok_s(szTemp, L":", &pTokenNext);
	if (NULL == pTokenTemp) {
		safe_sprintf(m_szErrors, L"result is missing");
		return false;
	}

	if (stringisdiffw(stringtrimw(pTokenTemp), label::ADB_TOKEN_USB)) {
		safe_sprintf(m_szErrors, L"usb is missing");
		return false;
	}

	safe_sprintf(result, reslen, _T("%s"), stringtrimw(pTokenNext));

	if (stringiszerow(result)) {
		safe_sprintf(m_szErrors, L"usb version is null");
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 *
 ******************************************************************************/
bool CCmdPipeline::ExecuteAdbState(HANDLE removed, int timeout, 
        const TCHAR *serial, TCHAR *result, int reslen)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_GET_STATE, serial);
	log_trace(szCommand);

    wchar_t szResult[vol::LEN_BUFF] = {0};

	if (!ExecuteAdbCommand(removed, timeout, szCommand, label::ADB_TOKEN_STATE, 
				szResult, _countof(szResult))) {
		return false;
	}

	safe_sprintf(result, reslen, _T("%s"), szResult);

	if (stringiszerow(result)) {
		safe_sprintf(m_szErrors, L"state is null");
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 *
 ******************************************************************************/
bool CCmdPipeline::ExecuteAdbInstall(HANDLE removed, int timeout, 
        const TCHAR *serial, const TCHAR *path)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_INSTALL, serial, path);
	log_trace(szCommand);

    wchar_t szResult[vol::LEN_BUFF] = {0};

	if (!ExecuteAdbCommand(removed, timeout, szCommand, label::ADB_TOKEN_INSTALL, 
				szResult, _countof(szResult))) {
		return false;
	}

	if (stringiszerow(szResult)) {
		safe_sprintf(m_szErrors, L"result is empty");
		return false;
	}

	if (false == stringcontainw(szResult, label::ADB_INSTALL)) {
		safe_sprintf(m_szErrors, L"install failed");
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 *
 ******************************************************************************/
bool CCmdPipeline::ExecuteAdbDevices(HANDLE removed, int timeout, 
		TCHAR *result, int reslen)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_DEVICES);
	log_trace(szCommand);

    wchar_t szResult[vol::LEN_BUFFER] = {0};

	if (!ExecuteAdbCommand(removed, timeout, szCommand, label::ADB_TOKEN_DEVICES, 
				szResult, _countof(szResult))) {
		return false;
	}

	if (stringiszerow(szResult)) {
		safe_sprintf(m_szErrors, L"result is empty");
		return false;
	}

	if (false == stringcontainw(szResult, label::DEVICES_LIST)) {
		safe_sprintf(m_szErrors, L"list is missing");
		return false;
	}

	safe_overwrite(szResult, _T("%s"), szResult + wcslen(label::DEVICES_LIST));
	safe_sprintf(result, reslen, _T("%s"), szResult);

	if (stringiszerow(stringtrimw(result))) {
		safe_sprintf(m_szErrors, L"device is empty");
		return false;
	}

	return true;
}

/*!
* author: chenyao
*
******************************************************************************/
bool CCmdPipeline::ExecuteAdbUsb(HANDLE removed, int timeout, const TCHAR *serial)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_USB, serial);
	log_trace(szCommand);

    wchar_t szResult[vol::LEN_BUFF] = {0};

	if (!ExecuteAdbCommand(removed, timeout, szCommand, label::ADB_TOKEN_REBOOT, 
				szResult, _countof(szResult))) {
		return false;
	}

	if (stringisdiffw(szResult, label::REBOOT_USB_MODE)) 
		return false;

	return true;
}

bool CCmdPipeline::ExecuteAdbStartServer(HANDLE removed, int timeout)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::ADB_STARTSERVER);
	log_trace(szCommand);

	if (!ExecuteAdbCommand(removed, timeout, szCommand, 
				label::ADB_TOKEN_START)) {
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 *
 ******************************************************************************/
bool CCmdPipeline::ExecuteWlanConnect(HANDLE removed, int timeout, 
		const TCHAR *serial, TCHAR *result, int reslen)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, wlan::ADB_CONNECT, serial);
	log_trace(szCommand);

    wchar_t szResult[vol::LEN_BUFFER] = {0};

	if (!ExecuteAdbCommand(removed, timeout, szCommand, wlan::ADB_TOKEN_CONNECT, 
				szResult, _countof(szResult))) {
		return false;
	}

	if (stringiszerow(szResult)) {
		safe_sprintf(m_szErrors, L"result is empty");
		return false;
	}

	if (stringcontainw(szResult, label::ADB_FAILURE)) {
		safe_sprintf(m_szErrors, L"connect failure");
		return false;
	}

	if (!stringcontainw(szResult, wlan::ADB_STATUS)) {
		safe_sprintf(m_szErrors, L"connect failure");
		return false;
	}

	safe_sprintf(result, reslen, _T("%s:%d"), serial, wlan::ADB_PORT);

	return true;
}

/*!
 * author: chenyao
 *
 ******************************************************************************/
bool CCmdPipeline::ExecuteWlanDisconnect(HANDLE removed, int timeout, 
		const TCHAR *serial)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, wlan::ADB_DISCONNECT, serial);
	log_trace(szCommand);

    wchar_t szResult[vol::LEN_BUFFER] = {0};

	if (!ExecuteAdbCommand(removed, timeout, szCommand, wlan::ADB_TOKEN_DISCONNECT, 
				szResult, _countof(szResult))) {
		return false;
	}

	if (stringcontainw(szResult, label::ADB_FAILURE)) {
		safe_sprintf(m_szErrors, L"disconnect failure");
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 * fastboot
 ******************************************************************************/
bool CCmdPipeline::AnalysisFastbootResult(wchar_t *result, int reslen,
        const wchar_t *token, bool check)
{
    wchar_t *pEndding = NULL;

    pEndding = wcsstr(result, token);
	if (NULL == pEndding) {
        safe_sprintf(result, reslen, L"endding is missing");
		return false;
    }

    if (false == check) {
        *pEndding = 0, stringtrimw(result);
        return true;
    }

	pEndding = wcsstr(result, label::FASTBOOT_PASS);
	if (NULL == pEndding) {
        safe_sprintf(result, reslen, L"endding is failure");
		return false;
	}

	*pEndding = 0, stringtrimw(result);
	return true;
}

bool CCmdPipeline::ExecuteFastbootCommand(HANDLE removed, int timeout, const wchar_t *command, 
            const wchar_t *token, wchar_t *result, int reslen)
{	
	if (NULL == command) {
		safe_sprintf(m_szErrors, L"command is null");
		return false;
	}

	if (false == CommandExec(command)) {
		safe_overwrite(m_szErrors, L"send:%s", m_szErrors);
		return false;
	}

    wchar_t szResult[vol::LEN_BUFFER] = {0};

	SetTokenString(token);
	int nResultLen = CommandRead(removed, timeout, 
			szResult, _countof(szResult));
    log_trace(szResult);
	CleanProcess();

	if (0 >= nResultLen) {
		safe_overwrite(m_szErrors, L"read:%s", m_szErrors);
		return false;
	}

	if (NULL != result && 0 != reslen)
		safe_sprintf(result, reslen, L"%s", stringtrimw(szResult));

	return true;
}

bool CCmdPipeline::ExecuteFastboot(HANDLE removed, int timeout,
			const TCHAR *command, TCHAR *result, int reslen, bool check)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::FASTBOOT_COMMAND, command);
	log_trace(szCommand);

	if (!ExecuteFastbootCommand(removed, timeout, 
				szCommand, label::FASTBOOT_TOKEN, result, reslen)) {
		return false;
	}

	if (!AnalysisFastbootResult(result, reslen, 
				label::FASTBOOT_TOKEN, check)) {
		safe_sprintf(m_szErrors, result);
		return false;
	}

	return true;
}

bool CCmdPipeline::ExecuteFastboot(HANDLE removed, int timeout, const TCHAR *serial, 
			const TCHAR *command, TCHAR *result, int reslen, bool check)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::FASTBOOT_COMMAND_M, serial, command);
	log_trace(szCommand);

	if (!ExecuteFastbootCommand(removed, timeout, 
				szCommand, label::FASTBOOT_TOKEN, result, reslen)) {
		return false;
	}

	if (!AnalysisFastbootResult(result, reslen, 
				label::FASTBOOT_TOKEN, check)) {
		safe_sprintf(m_szErrors, result);
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 * flashcmd
 ******************************************************************************/
bool CCmdPipeline::ExecuteFlashcmdBase(HANDLE removed, int timeout, 
		const TCHAR *serial, const TCHAR *command, TCHAR *result, int reslen)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	if (NULL == serial || 0 == _tcslen(serial))
		safe_sprintf(szCommand, cmd::ADB_SHELL_S, command);
	else
		safe_sprintf(szCommand, cmd::ADB_SHELL_M, serial, command);

	log_trace(szCommand);

	TCHAR szResult[vol::LEN_BUFF] = {0};

	if (!ExecuteAdbShell(removed, timeout, szCommand, 
				szResult, _countof(szResult))) {
		return false;
	}

	if (stringiszerow(szResult)) {
		safe_sprintf(m_szErrors, L"result is empty");
		return false;
	}

	wchar_t *pTokenTemp = NULL;
	wchar_t *pTokenNext = NULL;

	pTokenTemp = wcstok_s(szResult, L":", &pTokenNext);
	if (NULL == pTokenTemp) {
		safe_sprintf(m_szErrors, L"OKEY is missing");
		return false;
	}

	if (stringisdiffw(stringtrimw(pTokenTemp), label::ADB_TOKEN_OKEY)) {
		safe_sprintf(m_szErrors, L"OKEY is missing");
		return false;
	}

	if (NULL != result && 0 != reslen) {
		pTokenTemp = wcstok_s(NULL, L"\r\n", &pTokenNext);
		if (NULL == pTokenTemp) {
			safe_sprintf(m_szErrors, L"result is missing");
			return false;
		}

		safe_sprintf(result, reslen, stringtrimw(pTokenTemp));

		if (stringiszero(result)) {
			safe_sprintf(m_szErrors, L"result is null");
			return false;
		}
	}

	return true;
}

/*!
 * author: chenyao
 * flashcmd
 ******************************************************************************/
bool CCmdPipeline::ExecuteFlashcmdPrep(HANDLE removed, int timeout, 
		const TCHAR *serial, int slot, TCHAR *result, int reslen)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::FLASHCMD_PREPARE, slot);
	log_trace(szCommand);

	if (!ExecuteFlashcmdBase(removed, timeout, 
				serial, szCommand, result, reslen))
		return false;

	return true;
}

/*!
 * author: chenyao
 * 
 ******************************************************************************/
bool CCmdPipeline::ExecuteFlashcmdBurn(HANDLE removed,
            const TCHAR *serial, int slot)
{
	wchar_t szCommand[vol::LEN_CMD] = {0};

	if (NULL == serial || 0 == _tcslen(serial))
		safe_sprintf(szCommand, cmd::ADB_SHELL_S, _T(""));
	else
		safe_sprintf(szCommand, cmd::ADB_SHELL_M, serial, _T(""));
	log_trace(szCommand);

	if (false == CommandExec(szCommand))
		return false;

	TCHAR szResult[vol::LEN_BUFF] = {0};

	SetTokenString(label::ADB_TOKEN_ROOT);
	int nResultLen = CommandRead(removed, 5, szResult, _countof(szResult));
	log_trace(szResult);

	if (0 >= nResultLen) {
		safe_overwrite(m_szErrors, L"read:%s", m_szErrors);
		return false;
	}

	safe_sprintf(szCommand, cmd::FLASHCMD_BURN, slot);
	log_trace(szCommand);
	safe_overwrite(szCommand, L"%s\n", szCommand);

	if (!CommandSend(szCommand, wcslen(szCommand)))
		return false;

	memset(szResult, 0, sizeof(szResult));
	SetTokenString(stringtrimw(szCommand));
	nResultLen = CommandRead(removed, 5, szResult, _countof(szResult));
	log_trace(szResult);

	if (0 >= nResultLen) {
		safe_overwrite(m_szErrors, L"wait:%s", m_szErrors);
		return false;
	}

	return true;
}

/*!
 * author: chenyao
 * 
 ******************************************************************************/
bool CCmdPipeline::ExecuteFlashcmdRead(HANDLE removed, int timeout, 
		const TCHAR *serial, int slot, TCHAR *result, int reslen)
{
	TCHAR szCommand[vol::LEN_CMD] = {0};

	safe_sprintf(szCommand, cmd::FLASHCMD_READ, slot);
	log_trace(szCommand);

	if (!ExecuteFlashcmdBase(removed, timeout, 
				serial, szCommand, result, reslen))
		return false;

	return true;
}

/*!
 * author: chenyao
 * 
 ******************************************************************************/
bool CCmdPipeline::ExecuteRead(HANDLE removed, int timeout, 
			const wchar_t *token, wchar_t *result, int reslen)
{
	TCHAR szResult[vol::LEN_BUFFER] = {0};

	SetTokenString(token);
	int nResultLen = CommandRead(removed, timeout, 
				szResult, _countof(szResult));
	log_trace(szResult);
	AbortProcess();

	if (0 >= nResultLen) {
		safe_overwrite(m_szErrors, L"read:%s", m_szErrors);
		return false;
	}

	if (NULL != reslen && 0 != reslen)
		safe_sprintf(result, reslen, szResult);

	return true;
}

/*!
 * author: chenyao
 * 
 ******************************************************************************/
bool CCmdPipeline::ExecuteSend(const wchar_t *command, int cmdlen)
{
	if (NULL == command || 0 == cmdlen) {
		safe_sprintf(m_szErrors, _T("command is null"));
		goto _cleanup;
	}

	if (!CommandSend(command, cmdlen)) {
		goto _cleanup;
	}

	return true;

_cleanup:
	AbortProcess();
	return false;
}

/*!
 * author: chenyao
 * 
 ******************************************************************************/
bool CCmdPipeline::ExecuteSend(const unsigned char *command, int cmdlen)
{
	wchar_t *pCommand = NULL;

	if (NULL == command || 0 == cmdlen) {
		safe_sprintf(m_szErrors, _T("command is null"));
		goto _cleanup;
	}

	pCommand = new wchar_t[cmdlen+1]();
	int nLength = MultiByte2WideCharHex(command, cmdlen, pCommand, cmdlen+1);

	if (0 >= nLength) {
		safe_sprintf(m_szErrors, _T("MultiByte2WideCharHex failed"));
		goto _cleanup;
	}

	if (!CommandSend(pCommand, nLength)) {
		goto _cleanup;
	}

	delete[] pCommand, pCommand = NULL;
	return true;

_cleanup:
	if (pCommand)
		delete[] pCommand, pCommand = NULL;
	AbortProcess();
	return false;
}
