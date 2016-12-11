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
	static const wchar_t* FASTBOOT_ERROR = L"error: cannot load";
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

		if (NULL != wcsstr(result, label::FASTBOOT_ERROR)) {
			safe_sprintf(m_szErrors, label::FASTBOOT_ERROR);
			goto _cleanup;
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

CPipeline::CPipeline()
	: m_pathModule  (L"")
	, m_process     (nullptr)
	, m_removed     (nullptr)
	, m_inputRead   (nullptr)
	, m_inputWrite  (nullptr)
	, m_outputRead  (nullptr)
	, m_outputWrite (nullptr)
	, m_errorWrite  (nullptr)
	, m_function    (nullptr)
	, m_object      (nullptr)
{
	memset(m_errormsg, 0, sizeof(m_errormsg));
}

CPipeline::~CPipeline()
{ }

bool CPipeline::Initialize()
{
	HANDLE outputRead = nullptr;
	HANDLE inputWrite = nullptr;

	// Set the bInheritHandle flag, so pipe handles are inherited. 
	SECURITY_ATTRIBUTES saAttr;
	memset(&saAttr, 0, sizeof(SECURITY_ATTRIBUTES));

	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.lpSecurityDescriptor = nullptr;
	saAttr.bInheritHandle = TRUE;

	// Create the child output pipe.
	if (!CreatePipe(&outputRead, &m_outputWrite, &saAttr, 0)) {
		safe_sprintf(m_errormsg, L"create stdout pipe failed");
		return false;
	}

	// Create the child input pipe.
	if (!CreatePipe(&m_inputRead, &inputWrite, &saAttr, 0)) {
		safe_sprintf(m_errormsg, L"create stdin pipe failed");
		return false;
	}

	// Create a duplicate of the output write handle for the std error write handle. 
	// This is necessary in case the child application closes one of its std output handles.
	if (!DuplicateHandle(GetCurrentProcess(), m_outputWrite, 
				GetCurrentProcess(), &m_errorWrite, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
		safe_sprintf(m_errormsg, L"DuplicateHandle Error");
		return false;
	}

	// Create new output read handle and the input write handles. Set
	// the Properties to FALSE. Otherwise, the child inherits the
	// properties and, as a result, non-closeable handles to the pipes
	// are created.
	if (!DuplicateHandle(GetCurrentProcess(), outputRead, GetCurrentProcess(), &m_outputRead, 
				0, FALSE/*Make it uninheritable*/, DUPLICATE_SAME_ACCESS)) {
		safe_sprintf(m_errormsg, L"DuplicateHandle Error");
		return false;
	}

	if (!DuplicateHandle(GetCurrentProcess(), inputWrite, GetCurrentProcess(), &m_inputWrite, 
				0, FALSE/*Make it uninheritable*/, DUPLICATE_SAME_ACCESS)) {
		safe_sprintf(m_errormsg, L"DuplicateHandle Error");
		return false;
	}

	CloseHandle(outputRead), outputRead = nullptr;
	CloseHandle(inputWrite), inputWrite = nullptr;

	// set outputRead non-block
	DWORD dwMode = PIPE_NOWAIT;
	if (!SetNamedPipeHandleState(m_outputRead, &dwMode, NULL, NULL)) {
		safe_sprintf(m_errormsg, L"SetNamedPipeHandleState Error");
		return false;
	}

	return true;
}

void CPipeline::Release()
{
	ProcessAbort();

	CloseHandle(m_inputRead),   m_inputRead   = nullptr;
	CloseHandle(m_inputWrite),  m_inputWrite  = nullptr;
	CloseHandle(m_outputRead),  m_outputRead  = nullptr;
	CloseHandle(m_outputWrite), m_outputWrite = nullptr;
	CloseHandle(m_errorWrite),  m_errorWrite  = nullptr;

	SetRouterFunc(nullptr, nullptr);
}

bool CPipeline::CommandExec(const wchar_t *command)
{
	// Set up members of the STARTUPINFO structure. 
	// This structure specifies the STDIN handle for redirection. 
	STARTUPINFO startupInfo  = {sizeof(STARTUPINFO)}; 

	startupInfo.hStdInput    = m_inputRead;
	startupInfo.hStdOutput   = m_outputWrite;
	startupInfo.hStdError    = m_errorWrite;
	startupInfo.dwFlags      = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	startupInfo.wShowWindow |= SW_HIDE;

	// Set up members of the PROCESS_INFORMATION structure.  
	PROCESS_INFORMATION processInfo; 
	memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));
	
	wchar_t commandLocal[vol::LEN_CMD] = {0};
    safe_sprintf(commandLocal, L"%s", command);

	// create the child process.   
	if (!CreateProcessW(NULL, commandLocal, NULL, NULL, TRUE, 0, NULL,
				m_pathModule.empty() ? NULL : m_pathModule.c_str(), 
				&startupInfo, &processInfo)) {
        safe_sprintf(m_errormsg, L"create command (%d)", GetLastError());
		return false;
	}

    CloseHandle(processInfo.hThread), processInfo.hThread = nullptr;
	m_process = processInfo.hProcess;

	return true;
}

bool CPipeline::CommandSend(const wchar_t *command, int cmdlen)
{
	if (NULL == command || 0 == cmdlen) {
		safe_sprintf(m_errormsg, L"command is null");
		return false;
	}

	CArrayPoint<unsigned char> commandLocal(cmdlen + 1);

    int length = WideChar2MultiByteHex(command, cmdlen, 
			commandLocal, commandLocal.capacity());

    if (0 >= length) {
		safe_sprintf(m_errormsg, L"WideChar2MultiByteHex (%d)", GetLastError());
		return false;
    }
	
	DWORD writeLength = 0;

	if (!WriteFile(m_inputWrite, commandLocal, length, &writeLength, NULL)
			|| length != static_cast<int>(writeLength)) {
        safe_sprintf(m_errormsg, L"WriteFile failed (%d)", GetLastError());
		return false;
	}
	
	return true;
}

int CPipeline::CommandRead(int timeout_ms, wchar_t *result, int reslen)
{
	HANDLE handleArray[2] = { m_removed, m_process };

	switch (WaitForMultipleObjects(_countof(handleArray), handleArray, 
				FALSE, timeout_ms)) {
	case WAIT_OBJECT_0:
		safe_sprintf(m_errormsg, L"device removed");
		goto _cleanup;
	case WAIT_OBJECT_0 + 1:
		ProcessClose();
		break;
	default:
		safe_sprintf(m_errormsg, L"read timeout");
		goto _cleanup;
	}

    unsigned long charsRead = 0;
	unsigned long bytesRead = 0;
	unsigned char buffer[vol::LEN_BUFF] = {0};

	while (PeekNamedPipe(m_outputRead, buffer, 1, &bytesRead, NULL, NULL)
				&& 0 < bytesRead) {
		memset(buffer, 0, sizeof(buffer));
		bytesRead = 0;

		ReadFile(m_outputRead, buffer, _countof(buffer), &bytesRead, NULL);
		if (0 == bytesRead) {
			safe_sprintf(m_errormsg, L"ReadFile failed (%d)", GetLastError());
			goto _cleanup;
		}

		CArrayPoint<wchar_t> bufferArray(bytesRead + 1);

		int wideChars = MultiByte2WideCharHex(buffer, bytesRead, 
				bufferArray, bufferArray.capacity());

		if (0 >= wideChars) {
			safe_sprintf(m_errormsg, L"MultiByte2WideCharHex (%d)", GetLastError());
			goto _cleanup;
		}

		if (static_cast<int>(charsRead) + wideChars >= reslen) {
			safe_sprintf(m_errormsg, L"buffer is small");
			goto _cleanup;
		}

		wmemcpy_s(result + charsRead, reslen - charsRead, bufferArray, wideChars);
		charsRead += wideChars;
	}

	return charsRead;

_cleanup:
	ProcessAbort();
	return -1; // fail
}

int CPipeline::CommandRead(const wchar_t *token, int timeout_ms, wchar_t *result, int reslen)
{    
	unsigned long charsRead = 0;
	unsigned long endedTime = GetTickCount() + timeout_ms;
	
	do {
		switch(WaitForSingleObject(m_removed, 10)) {
		case WAIT_OBJECT_0:
            safe_sprintf(m_errormsg, L"device removed");
			goto _cleanup;
		}

		unsigned long bytesRead = 0;
		unsigned char buffer[vol::LEN_BUFF] = {0};

		PeekNamedPipe(m_outputRead, buffer, 1, &bytesRead, NULL, NULL);

        if (0 >= bytesRead)
            continue;

		memset(buffer, 0, sizeof(buffer));
		bytesRead = 0;

        while (ReadFile(m_outputRead, buffer, vol::LEN_BUFF, &bytesRead, NULL)) {
            if (0 == bytesRead) {
				safe_sprintf(m_errormsg, L"ReadFile failed (%d)", GetLastError());
                goto _cleanup;
            }

			CArrayPoint<wchar_t> bufferArray(bytesRead + 1);

			int wideChars = MultiByte2WideCharHex(buffer, bytesRead, 
				bufferArray, bufferArray.capacity());

			if (0 >= wideChars) {
				safe_sprintf(m_errormsg, L"MultiByte2WideCharHex (%d)", GetLastError());
				goto _cleanup;
			}

			if (static_cast<int>(charsRead) + wideChars >= reslen) {
				safe_sprintf(m_errormsg, L"buffer is small");
				goto _cleanup;
			}

			wmemcpy_s(result + charsRead, reslen - charsRead, bufferArray, wideChars);
			charsRead += wideChars;

            memset(buffer, 0, sizeof(buffer));
            bytesRead = 0;
		}

		if (nullptr != wcsstr(result, token)) {
			return charsRead; // pass
        }
	} while (GetTickCount() <= endedTime);

	safe_sprintf(m_errormsg, L"read timeout");

_cleanup:
	ProcessAbort();
	return -1; // fail
}

bool CPipeline::ExecuteCatch(wchar_t *result, int reslen)
{	
    unsigned long charsRead = 0;
	unsigned long bytesRead = 0;
	unsigned char buffer[vol::LEN_BUFF] = {0};

	PeekNamedPipe(m_outputRead, buffer, 1, &bytesRead, NULL, NULL);

	if (0 >= bytesRead) {
		log_trace(L"CommandCatch: no data");
		return false; // no data
	}

	memset(buffer, 0, sizeof(buffer));
	bytesRead = 0;

	while (ReadFile(m_outputRead, buffer, _countof(buffer), &bytesRead, NULL)) {
		if (0 == bytesRead)
			return false;

		CArrayPoint<wchar_t> bufferArray(bytesRead + 1);

		int wideChars = MultiByte2WideCharHex(buffer, bytesRead, 
                bufferArray, bufferArray.capacity());

		if (0 >= wideChars)
			return false;

		if (static_cast<int>(charsRead) + wideChars >= reslen)
			return false;

		wmemcpy_s(result + charsRead, reslen - charsRead, bufferArray, wideChars);
		charsRead += wideChars;

		memset(buffer, 0, sizeof(buffer));
		bytesRead = 0;
	}

	return true;
}

bool CPipeline::ExecuteRead(const wchar_t *token, int timeout_ms, wchar_t *result, int reslen)
{
	wchar_t resultLocal[vol::LEN_BUFFER] = {0};

	int resultLen = CommandRead(token, timeout_ms, resultLocal, _countof(resultLocal));
	log_trace(resultLocal);

	ProcessAbort();

	if (0 >= resultLen) {
		safe_overwrite(m_errormsg, L"read:%s", m_errormsg);
		return false;
	}

	if (nullptr != result && 0 != reslen)
		safe_sprintf(result, reslen, stringtrimw(resultLocal));

	return true;
}

bool CPipeline::ExecuteSend(const wchar_t *command, int cmdlen)
{
	if (nullptr == command || 0 == cmdlen) {
		safe_sprintf(m_errormsg, L"command is null");
		goto _cleanup;
	}

	if (false == CommandSend(command, cmdlen))
		goto _cleanup;

	return true;

_cleanup:
	ProcessAbort();
	return false;
}

bool CPipeline::ExecuteSend(const unsigned char *command, int cmdlen)
{
	CArrayPoint<wchar_t> bufferArray(cmdlen + 1);

	if (nullptr == command || 0 == cmdlen) {
		safe_sprintf(m_errormsg, L"command is null");
		goto _cleanup;
	}

	int length = MultiByte2WideCharHex(command, cmdlen, 
			bufferArray, bufferArray.capacity());

	if (0 >= length) {
		safe_sprintf(m_errormsg, L"MultiByte2WideCharHex failed");
		goto _cleanup;
	}

	if (false == CommandSend(bufferArray, length))
		goto _cleanup;

	return true;

_cleanup:
	ProcessAbort();
	return false;
}

void CPipeline::ProcessClose()
{
	if (nullptr == m_process)
		return;

	CloseHandle(m_process), m_process = nullptr;
}

void CPipeline::ProcessAbort()
{
	if (nullptr == m_process)
		return;

	TerminateProcess(m_process, static_cast<unsigned int>(-1));
	CloseHandle(m_process), m_process = nullptr;
}

void CPipeline::ProcessClean()
{
	if (nullptr == m_process)
		return;

	WaitForSingleObject(m_process, INFINITE);
	CloseHandle(m_process), m_process = nullptr;
}

bool CShellAdb::ExecuteShell(const wchar_t *command, int timeout_ms, const wchar_t *token,  
			bool check, wchar_t *result, int reslen)
{
	if (nullptr == command || 0 == wcslen(command)) {
		safe_sprintf(m_errormsg, L"command is null");
		return false;
	}

	if (false == CommandExec(command)) {
		safe_overwrite(m_errormsg, L"send:%s", m_errormsg);
		return false;
	}

    wchar_t resultLocal[vol::LEN_BUFFER] = {0};

	int resultLen = CommandRead(timeout_ms, resultLocal, _countof(resultLocal));
    log_trace(resultLocal);

	if (0 >= resultLen) {
		safe_overwrite(m_errormsg, L"read:%s", m_errormsg);
		return false;
	}

	if (false == AnalysisResult(resultLocal, token, check))
		return false;

	if (nullptr != result && 0 != reslen)
		safe_sprintf(result, reslen, L"%s", stringtrimw(resultLocal));

	return true;
}

bool CShellAdb::AnalysisResult(wchar_t *result, const wchar_t *token, bool check)
{
    wchar_t * endding = nullptr;

    endding = wcsstr(result, token);
	if (nullptr == endding) {
        safe_sprintf(m_errormsg, L"endding is empty");
		return false;
    }

    if (true == check) {
		wchar_t buffer[vol::LEN_BUFF] = {0};
		safe_sprintf(buffer, L"%s", endding);

		wchar_t * tokenThis = nullptr;
		wchar_t * tokenNext = nullptr;

		tokenThis = wcstok_s(buffer, L":", &tokenNext);
		if (nullptr == tokenThis) {
			safe_sprintf(m_errormsg, L"endding is missing");
			return false;
		}

		if (stringisdiffw(stringtrimw(tokenThis), token)) {
			safe_sprintf(m_errormsg, L"endding is different");
			return false;
		}

		if (stringisdiffw(stringtrimw(tokenNext), label::ADB_SUCCESS)) {
			safe_sprintf(m_errormsg, L"endding is failure");
			return false;
		}
	}

	*endding = L'\0';
	stringtrimw(result);

	return true;
}

bool CShellAdb::ExecuteCommand(const wchar_t *command, int timeout_ms, 
        wchar_t *result, int reslen)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, cmd::ADB_SHELL_M, m_serial.c_str(), command);
	log_trace(commandLocal);

	return ExecuteShell(commandLocal, timeout_ms, label::ADB_TOKEN_SHELL, false, result, reslen);
}

bool CShellAdb::ExecuteCommand(const wchar_t *command, int timeout_ms, const wchar_t *token, 
        wchar_t *result, int reslen)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, cmd::ADB_COMMAND, m_serial.c_str(), command);
	log_trace(commandLocal);

	return ExecuteShell(commandLocal, timeout_ms, token, true, result, reslen);
}

bool CShellAdb::ExecuteCommand(const wchar_t *command)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, cmd::ADB_SHELL_M, m_serial.c_str(), command);
	log_trace(commandLocal);

	if (false == CommandExec(commandLocal))
		return false;

	ProcessClose();

	return true;
}

bool CShellAdb::ExecutePSN(int timeout_ms, wchar_t *result, int reslen)
{
	return ExecuteFlashcmdBase(cmd::ADB_SHELL_PSN, timeout_ms, result, reslen);
}

bool CShellAdb::ExecuteLS(int timeout_ms, const wchar_t *path)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, cmd::ADB_SHELL_LS, m_serial.c_str(), path);
	log_trace(commandLocal);

    wchar_t resultLocal[vol::LEN_BUFF] = {0};

	if (!ExecuteShell(commandLocal, timeout_ms, label::ADB_TOKEN_SHELL, 
                false, resultLocal, _countof(resultLocal))) {
        return false;
    }

	if (stringiszerow(resultLocal)) {
		safe_sprintf(m_errormsg, L"result is empty");
		return false;
	}

	if (stringisdiffw(resultLocal, path)) {
		safe_sprintf(m_errormsg, L"file is not existed");
		return false;
	}

	return true;
}

bool CShellAdb::ExecuteGetProp(int timeout_ms, const wchar_t *prop, 
        wchar_t *result, int reslen)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, cmd::ADB_SHELL_GETPROP, m_serial.c_str(), prop);
	log_trace(commandLocal);

    wchar_t resultLocal[vol::LEN_BUFF] = {0};

	if (!ExecuteShell(commandLocal, timeout_ms, label::ADB_TOKEN_SHELL, 
                false, resultLocal, _countof(resultLocal))) {
        return false;
    }

	safe_sprintf(result, reslen, L"%s", resultLocal);

	if (stringiszerow(result)) {
		safe_sprintf(m_errormsg, L"prop is null");
		return false;
	}

	return true;
}

bool CShellAdb::ExecuteSetProp(int timeout_ms, const wchar_t *prop, const wchar_t *value)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, cmd::ADB_SHELL_SETPROP, m_serial.c_str(), prop, value);
	log_trace(commandLocal);

    wchar_t resultLocal[vol::LEN_BUFF] = {0};

	if (!ExecuteShell(commandLocal, timeout_ms, label::ADB_TOKEN_SHELL, 
                false, resultLocal, _countof(resultLocal))) {
        return false;
    }

	if (stringcontainw(resultLocal, label::ADB_FAILURE)) {
		safe_sprintf(m_errormsg, L"setprop failed");
		return false;
	}

	return true;
}

bool CShellAdb::ExecuteDevices(int timeout_ms, wchar_t *result, int reslen)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, cmd::ADB_DEVICES);
	log_trace(commandLocal);

    wchar_t resultLocal[vol::LEN_BUFFER] = {0};

	if (!ExecuteShell(commandLocal, timeout_ms, label::ADB_TOKEN_DEVICES, 
				true, resultLocal, _countof(resultLocal))) {
		return false;
	}

	if (stringiszerow(resultLocal)) {
		safe_sprintf(m_errormsg, L"result is empty");
		return false;
	}

	if (false == stringcontainw(resultLocal, label::DEVICES_LIST)) {
		safe_sprintf(m_errormsg, L"list is missing");
		return false;
	}

	safe_overwrite(resultLocal, L"%s", resultLocal + wcslen(label::DEVICES_LIST));
	safe_sprintf(result, reslen, _T("%s"), resultLocal);

	if (stringiszerow(stringtrimw(result))) {
		safe_sprintf(m_errormsg, L"device is empty");
		return false;
	}

	return true;
}

bool CShellAdb::ExecuteForward(int timeout_ms, int client, int remote)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, cmd::ADB_FORWARD, m_serial.c_str(), client, remote);
	log_trace(commandLocal);

	return ExecuteShell(commandLocal, timeout_ms, label::ADB_TOKEN_FORWARD);
}

bool CShellAdb::ExecuteStartServer(int timeout_ms)
{
	return ExecuteShell(cmd::ADB_STARTSERVER, timeout_ms, label::ADB_TOKEN_START);
}

bool CShellAdb::ExecutePull(int timeout_ms, const wchar_t *path, const wchar_t *target)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, cmd::ADB_PULL_FILE, m_serial.c_str(), path, target);
	log_trace(commandLocal);

    // large buffer
    wchar_t resultLocal[vol::LEN_BUFFER] = {0};

	if (!ExecuteShell(commandLocal, timeout_ms, label::ADB_TOKEN_PULL, 
				true, resultLocal, _countof(resultLocal))) {
		return false;
	}

	if (stringiszerow(resultLocal)) {
		safe_sprintf(m_errormsg, L"result is empty");
		return false;
	}

	if (false == stringcontainw(resultLocal, label::ADB_TOKEN_KBS)) {
		safe_sprintf(m_errormsg, L"KBS is missing");
		return false;
	}

	return true;
}

bool CShellAdb::ExecutePush(int timeout_ms, const wchar_t *path, const wchar_t *target)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, cmd::ADB_PUSH_FILE, m_serial.c_str(), path, target);
	log_trace(commandLocal);

    wchar_t resultLocal[vol::LEN_BUFFER] = {0};

	if (!ExecuteShell(commandLocal, timeout_ms, label::ADB_TOKEN_PUSH, 
				true, resultLocal, _countof(resultLocal))) {
		return false;
	}

	if (stringiszerow(resultLocal)) {
		safe_sprintf(m_errormsg, L"result is empty");
		return false;
	}

	if (false == stringcontainw(resultLocal, label::ADB_TOKEN_KBS)) {
		safe_sprintf(m_errormsg, L"KBS is missing");
		return false;
	}

	return true;
}

bool CShellAdb::ExecuteDescription(int timeout_ms, wchar_t *result, int reslen)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, cmd::ADB_GET_DESC, m_serial.c_str());
	log_trace(commandLocal);

    wchar_t resultLocal[vol::LEN_BUFF] = {0};

	if (!ExecuteShell(commandLocal, timeout_ms, label::ADB_TOKEN_DESC, 
				true, resultLocal, _countof(resultLocal))) {
		return false;
	}

	if (stringiszerow(resultLocal)) {
		safe_sprintf(m_errormsg, L"result is empty");
		return false;
	}

	wchar_t buffer[vol::LEN_BUFF] = {0};
	wchar_t * tokenThis = nullptr;
	wchar_t * tokenNext = nullptr;

	wcscpy_s(buffer, _countof(buffer), resultLocal);
	tokenThis = wcstok_s(buffer, L":", &tokenNext);

	if (nullptr == tokenThis) {
		safe_sprintf(m_errormsg, L"result is missing");
		return false;
	}

	if (stringisdiffw(stringtrimw(tokenThis), label::ADB_TOKEN_USB)) {
		safe_sprintf(m_errormsg, L"usb is missing");
		return false;
	}

	safe_sprintf(result, reslen, L"%s", stringtrimw(tokenNext));

	if (stringiszerow(result)) {
		safe_sprintf(m_errormsg, L"usb version is null");
		return false;
	}

	return true;
}

bool CShellAdb::ExecuteState(int timeout_ms, wchar_t *result, int reslen)
{	
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, cmd::ADB_GET_STATE, m_serial.c_str());
	log_trace(commandLocal);

    wchar_t resultLocal[vol::LEN_BUFF] = {0};

	if (!ExecuteShell(commandLocal, timeout_ms, label::ADB_TOKEN_STATE, 
				true, resultLocal, _countof(resultLocal))) {
		return false;
	}

	safe_sprintf(result, reslen, L"%s", stringtrimw(resultLocal));

	if (stringiszerow(result)) {
		safe_sprintf(m_errormsg, L"state is null");
		return false;
	}

	return true;
}

bool CShellAdb::ExecuteInstall(int timeout_ms, const wchar_t *path)
{	
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, cmd::ADB_INSTALL, m_serial.c_str(), path);
	log_trace(commandLocal);

    wchar_t resultLocal[vol::LEN_BUFF] = {0};

	if (!ExecuteShell(commandLocal, timeout_ms, label::ADB_TOKEN_INSTALL, 
				true, resultLocal, _countof(resultLocal))) {
		return false;
	}

	if (stringiszerow(resultLocal)) {
		safe_sprintf(m_errormsg, L"result is empty");
		return false;
	}

	if (false == stringcontainw(resultLocal, label::ADB_INSTALL)) {
		safe_sprintf(m_errormsg, L"install failed");
		return false;
	}

	return true;
}

bool CShellAdb::ExecuteUSB(int timeout_ms)
{
	wchar_t command[vol::LEN_CMD] = {0};

	safe_sprintf(command, cmd::ADB_USB, m_serial.c_str());
	log_trace(command);

    wchar_t resultLocal[vol::LEN_BUFF] = {0};

	if (!ExecuteShell(command, timeout_ms, label::ADB_TOKEN_REBOOT, 
				true, resultLocal, _countof(resultLocal))) {
		return false;
	}

	if (stringisdiffw(resultLocal, label::REBOOT_USB_MODE))  {
		safe_sprintf(m_errormsg, L"restart usb failed");
		return false;
	}

	return true;
}

bool CShellAdb::ExecuteFlashcmdBase(const wchar_t *command, int timeout_ms, 
			wchar_t *result, int reslen)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	if (m_serial.empty())
		safe_sprintf(commandLocal, cmd::ADB_SHELL_S, command);
	else
		safe_sprintf(commandLocal, cmd::ADB_SHELL_M, m_serial.c_str(), command);

	log_trace(commandLocal);

	wchar_t resultLocal[vol::LEN_BUFF] = {0};

	if (!ExecuteShell(commandLocal, timeout_ms, label::ADB_TOKEN_SHELL, 
				false, resultLocal, _countof(resultLocal))) {
		return false;
    }

	if (stringiszerow(resultLocal)) {
		safe_sprintf(m_errormsg, L"result is empty");
		return false;
	}

	wchar_t * tokenThis = nullptr;
	wchar_t * tokenNext = nullptr;

	tokenThis = wcstok_s(resultLocal, L":", &tokenNext);
	if (nullptr == tokenThis) {
		safe_sprintf(m_errormsg, L"OKEY is missing");
		return false;
	}

	if (stringisdiffw(stringtrimw(tokenThis), label::ADB_TOKEN_OKEY)) {
		safe_sprintf(m_errormsg, L"OKEY is missing");
		return false;
	}

	if (nullptr != result && 0 != reslen) {
		tokenThis = wcstok_s(NULL, L"\r\n", &tokenNext);

		if (nullptr == tokenThis) {
			safe_sprintf(m_errormsg, L"result is missing");
			return false;
		}

		safe_sprintf(result, reslen, stringtrimw(tokenThis));

		if (stringiszero(result)) {
			safe_sprintf(m_errormsg, L"result is null");
			return false;
		}
	}

	return true;
}

bool CShellAdb::ExecuteFlashcmdPrep(int timeout_ms, int slot, wchar_t *result, int reslen)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, cmd::FLASHCMD_PREPARE, slot);
	log_trace(commandLocal);

	return ExecuteFlashcmdBase(commandLocal, timeout_ms, result, reslen);
}

bool CShellAdb::ExecuteFlashcmdBurn(int slot)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	if (m_serial.empty())
		safe_sprintf(commandLocal, cmd::ADB_SHELL_S, L"");
	else
		safe_sprintf(commandLocal, cmd::ADB_SHELL_M, m_serial.c_str(), L"");

	log_trace(commandLocal);

	if (false == CommandExec(commandLocal))
		return false;

	wchar_t resultLocal[vol::LEN_BUFF] = {0};

	int resultLen = CommandRead(label::ADB_TOKEN_ROOT, 5000, 
			resultLocal, _countof(resultLocal));
	log_trace(resultLocal);

	if (0 >= resultLen) {
		safe_overwrite(m_errormsg, L"read:%s", m_errormsg);
		return false;
	}

	safe_sprintf(commandLocal, cmd::FLASHCMD_BURN, slot);
	log_trace(commandLocal);
	safe_overwrite(commandLocal, L"%s\n", commandLocal);

	if (false == CommandSend(commandLocal, wcslen(commandLocal)))
		return false;

	memset(resultLocal, 0, sizeof(resultLocal));
	resultLen = CommandRead(stringtrimw(resultLocal), 5000, 
			resultLocal, _countof(resultLocal));
	log_trace(resultLocal);

	if (0 >= resultLen) {
		safe_overwrite(m_errormsg, L"wait:%s", m_errormsg);
		return false;
	}

	return true;
}

bool CShellAdb::ExecuteFlashcmdRead(int timeout_ms, int slot, wchar_t *result, int reslen)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, cmd::FLASHCMD_READ, slot);
	log_trace(commandLocal);

	return ExecuteFlashcmdBase(commandLocal, timeout_ms, result, reslen);
}

bool CShellAdb::ExecuteWlanConnect(int timeout_ms, wchar_t *result, int reslen)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, wlan::ADB_CONNECT, m_serial.c_str());
	log_trace(commandLocal);

    wchar_t resultLocal[vol::LEN_BUFFER] = {0};

	if (!ExecuteShell(commandLocal, timeout_ms, wlan::ADB_TOKEN_CONNECT, 
				true, resultLocal, _countof(resultLocal))) {
		return false;
	}

	if (stringiszerow(resultLocal)) {
		safe_sprintf(m_errormsg, L"result is empty");
		return false;
	}

	if (stringcontainw(resultLocal, label::ADB_FAILURE)) {
		safe_sprintf(m_errormsg, L"connect failure");
		return false;
	}

	if (!stringcontainw(resultLocal, wlan::ADB_STATUS)) {
		safe_sprintf(m_errormsg, L"connect failure");
		return false;
	}

	safe_sprintf(result, reslen, L"%s:%d", m_serial.c_str(), wlan::ADB_PORT);

	return true;
}

bool CShellAdb::ExecuteWlanDisconnect(int timeout_ms)
{
	wchar_t commandLocal[vol::LEN_CMD] = {0};

	safe_sprintf(commandLocal, wlan::ADB_DISCONNECT, m_serial.c_str());
	log_trace(commandLocal);

    wchar_t resultLocal[vol::LEN_BUFFER] = {0};

	if (!ExecuteShell(commandLocal, timeout_ms, wlan::ADB_TOKEN_DISCONNECT, 
				true, resultLocal, _countof(resultLocal))) {
		return false;
	}

	if (stringcontainw(resultLocal, label::ADB_FAILURE)) {
		safe_sprintf(m_errormsg, L"disconnect failure");
		return false;
	}

	return true;
}
