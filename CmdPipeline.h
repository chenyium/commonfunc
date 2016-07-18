/******************************************************************************
 * 
 *  File:  CmdPipeline.h
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
 *  The declaration of the CCmdPipeline class.
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
#pragma once

#include <Windows.h>

/*!
 * Class Declare - CCmdPipeline
 *****************************************************************************/
class CCmdPipeline
{
public:
	CCmdPipeline(void);
	virtual ~CCmdPipeline(void);

public:
	CCmdPipeline(CCmdPipeline&);
	CCmdPipeline& operator = (CCmdPipeline&);

public:
	bool Initialize();
	void SetTokenString(const wchar_t *token);
    void CommandClear(HANDLE removed, int timeout = 10);
    bool CommandCatch(wchar_t *result, int reslen);

private:
    bool CommandExec(const wchar_t *command);
    bool CommandSend(const wchar_t *command, int cmdlen);
    int  CommandRead(HANDLE removed, int timeout, wchar_t *result, int reslen);
	void AbortProcess();
	void CleanProcess();
	void DeleteProcess();

public:
    wchar_t* geterrors() { return m_szErrors; }

private:
	bool AnalysisAdbResult(wchar_t *result, int reslen, 
			const wchar_t *token, bool check = true);
	bool ExecuteAdbCommand(HANDLE removed, int timeout, const wchar_t *command, 
            const wchar_t *token, wchar_t *result = NULL, int reslen = 0);
	bool ExecuteAdbShell(HANDLE removed, int timeout, 
            const wchar_t *command, wchar_t *result = NULL, int reslen = 0);

public: // adb shell
	bool ExecuteShell(HANDLE removed, int timeout, 
            const TCHAR *serial, const TCHAR *command, TCHAR *result = NULL, int reslen = 0);
	bool ExecuteShellWithout(const TCHAR *serial, const TCHAR *command);
	bool ExecuteShellLs(HANDLE removed, int timeout, 
            const TCHAR *serial, const TCHAR *path);
	bool ExecuteShellPsn(HANDLE removed, int timeout, 
            const TCHAR *serial, TCHAR *result, int reslen);
	bool ExecuteShellGetprop(HANDLE removed, int timeout, 
			const TCHAR *serial, const TCHAR *prop, TCHAR *result, int reslen);
	bool ExecuteShellSetprop(HANDLE removed, int timeout, 
			const TCHAR *serial, const TCHAR *prop, const TCHAR *value);

public: // adb
	bool ExecuteAdb(HANDLE removed, int timeout, const TCHAR *serial, 
			const TCHAR *command, const TCHAR *token, TCHAR *result = NULL, int reslen = 0);
	bool ExecuteAdbWithout(const TCHAR *serial, const TCHAR *command);
	bool ExecuteAdbPull(HANDLE removed, int timeout, 
            const TCHAR *serial, const TCHAR *path, const TCHAR *target);
	bool ExecuteAdbPullPath(HANDLE removed, int timeout, 
            const TCHAR *serial, const TCHAR *path, const TCHAR *target);
	bool ExecuteAdbPush(HANDLE removed, int timeout, 
            const TCHAR *serial, const TCHAR *path, const TCHAR *target);
	bool ExecuteAdbForward(HANDLE removed, int timeout, 
            const TCHAR *serial, int client, int remote);
	bool ExecuteAdbDescription(HANDLE removed, int timeout, 
            const TCHAR *serial, TCHAR *result, int reslen);
	bool ExecuteAdbState(HANDLE removed, int timeout, 
            const TCHAR *serial, TCHAR *result, int reslen);
	bool ExecuteAdbInstall(HANDLE removed, int timeout, 
            const TCHAR *serial, const TCHAR *path);
	bool ExecuteAdbDevices(HANDLE removed, int timeout, TCHAR *result, int reslen);
	bool ExecuteAdbUsb(HANDLE removed, int timeout, const TCHAR *serial);
	bool ExecuteAdbStartServer(HANDLE removed, int timeout);

public: // wlan
	bool ExecuteWlanConnect(HANDLE removed, int timeout, 
			const TCHAR *serial, TCHAR *result, int reslen);
	bool ExecuteWlanDisconnect(HANDLE removed, int timeout, 
			const TCHAR *serial);

public: // fastboot
	bool AnalysisFastbootResult(wchar_t *result, int reslen, 
			const wchar_t *token, bool check = true);
	bool ExecuteFastbootCommand(HANDLE removed, int timeout, const wchar_t *command, 
            const wchar_t *token, wchar_t *result = NULL, int reslen = 0);
	bool ExecuteFastboot(HANDLE removed, int timeout,
			const TCHAR *command, TCHAR *result = NULL, int reslen = 0, bool check = true);
	bool ExecuteFastboot(HANDLE removed, int timeout, const TCHAR *serial, 
			const TCHAR *command, TCHAR *result = NULL, int reslen = 0, bool check = true);

public: // flashcmd
	bool ExecuteFlashcmdBase(HANDLE removed, int timeout, 
            const TCHAR *serial, const TCHAR *command, TCHAR *result = NULL, int reslen = 0);
	bool ExecuteFlashcmdPrep(HANDLE removed, int timeout, 
            const TCHAR *serial, int slot, TCHAR *result, int reslen);
	bool ExecuteFlashcmdBurn(HANDLE removed, const TCHAR *serial, int slot);
	bool ExecuteFlashcmdRead(HANDLE removed, int timeout, 
            const TCHAR *serial, int slot, TCHAR *result, int reslen);

public:
	bool ExecuteRead(HANDLE removed, int timeout, 
				const wchar_t *token, wchar_t *result = NULL, int reslen = 0);
	bool ExecuteSend(const wchar_t *command, int cmdlen);
	bool ExecuteSend(const unsigned char *command, int cmdlen);

public:
	void SetRouterFunc(void *object, void *func) { 
		m_object   = object;
		m_function = static_cast<PROUTERMESSAGE>(func); 
	}
	void log_trace(wchar_t *message) {
		if (NULL != m_function) m_function(m_object, message); 
	}

private:
	typedef void (*PROUTERMESSAGE)(void*, wchar_t*);
	PROUTERMESSAGE m_function;
	void* m_object;

private:
	HANDLE m_hInputRead;
	HANDLE m_hInputWrite;
	HANDLE m_hOutputRead;
	HANDLE m_hOutputWrite;
	HANDLE m_hErrorWrite;
	HANDLE m_hProcessCmd;

private:
	wchar_t m_szTokens[ 32];
	wchar_t m_szModule[256];
    wchar_t m_szErrors[256];

};

