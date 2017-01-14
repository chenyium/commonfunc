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
#include <Windows.h>
#include "common_unit.h"

#ifndef __CMD_PIPELINE_H__
#define __CMD_PIPELINE_H__

//! pipeline
class CPipeline 
{
public:
	CPipeline();
	virtual ~CPipeline();

private:
	CPipeline(CPipeline&);
	CPipeline& operator = (CPipeline&);

public:
	bool Initialize();
	void Release();

public:
	inline void SetPathModule(const wchar_t * path) { m_pathModule = path; }
	inline void SetHandleRemoved(HANDLE handle) { m_removed = handle; }

public:
	bool ExecuteCatch(wchar_t *result, int reslen);
	bool ExecuteRead(const wchar_t *token, int timeout_ms, 
			wchar_t *result = nullptr, int reslen = 0);
	bool ExecuteSend(const wchar_t *command, int cmdlen);
	bool ExecuteSend(const unsigned char *command, int cmdlen);

protected:
	bool CommandExec(const wchar_t *command);
	bool CommandSend(const wchar_t *command, int cmdlen);
    int  CommandRead(int timeout_ms, wchar_t *result, int reslen);
    int  CommandRead(const wchar_t *token, int timeout_ms, wchar_t *result, int reslen);

protected:
	void ProcessAbort();
	void ProcessClean();
	void ProcessClose();

public:
	inline void SetRouterFunc(void *object, void *func) { 
		m_object   = object;
		m_function = static_cast<PROUTERMESSAGE>(func); 
	}
	inline void log_trace(wchar_t *message) {
		if (m_function) 
			m_function(m_object, message); 
	}

public:
    const wchar_t* ErrorMessage() { return m_errormsg; }

private:
	typedef void (*PROUTERMESSAGE)(void*, wchar_t*);
	PROUTERMESSAGE m_function;
	void * m_object;

protected:
	wchar_t m_errormsg[256];

private:
	std::wstring m_pathModule;

private:
	HANDLE m_process;
	HANDLE m_removed;
	HANDLE m_inputRead;
	HANDLE m_inputWrite;
	HANDLE m_outputRead;
	HANDLE m_outputWrite;
	HANDLE m_errorWrite;
};

//! interface
class CShellContext 
{
protected:
	CShellContext() {}
	virtual ~CShellContext() {}

protected:
	virtual bool ExecuteShell(const wchar_t *command, int timeout_ms, const wchar_t *token,  
			bool check = true, wchar_t *result = nullptr, int reslen = 0) = 0;
	virtual bool AnalysisResult(wchar_t *result, const wchar_t *token, bool check = true) = 0;

public:
	inline void SetSerial(const wchar_t * serial) { m_serial = serial; }

protected:
	std::wstring m_serial;
};

//! adb shell
class CShellAdb : public CShellContext, public CPipeline
{
protected:
	virtual bool ExecuteShell(const wchar_t *command, int timeout_ms, const wchar_t *token,  
			bool check = true, wchar_t *result = nullptr, int reslen = 0);
	virtual bool AnalysisResult(wchar_t *result, const wchar_t *token, bool check = true);

public:
	bool ExecuteCommand(const wchar_t *command, int timeout_ms,
            wchar_t *result = nullptr, int reslen = 0);
	bool ExecuteCommand(const wchar_t *command, int timeout_ms, const wchar_t *token, 
			wchar_t *result = nullptr, int reslen = 0);
	bool ExecuteCommand(const wchar_t *command);

public:
	bool ExecutePSN(int timeout_ms, wchar_t *result, int reslen);
	bool ExecuteLS(int timeout_ms, const wchar_t *path);
	bool ExecuteGetProp(int timeout_ms, const wchar_t *prop, wchar_t *result, int reslen);
	bool ExecuteSetProp(int timeout_ms, const wchar_t *prop, const wchar_t *value);

public:
	bool ExecuteDevices(int timeout_ms, wchar_t *result, int reslen);
	bool ExecuteForward(int timeout_ms, int client, int remote);
	bool ExecuteStartServer(int timeout_ms);
	bool ExecutePull(int timeout_ms, const wchar_t *path, const wchar_t *target);
	bool ExecutePush(int timeout_ms, const wchar_t *path, const wchar_t *target);
	bool ExecuteDescription(int timeout_ms, wchar_t *result, int reslen);
	bool ExecuteState(int timeout_ms, wchar_t *result, int reslen);
	bool ExecuteInstall(int timeout_ms, const wchar_t *path);
	bool ExecuteUSB(int timeout_ms);

public:
	bool ExecuteFlashcmdBase(const wchar_t *command, int timeout_ms, 
			wchar_t *result, int reslen);
	bool ExecuteFlashcmdPrep(int timeout_ms, int slot, wchar_t *result, int reslen);
	bool ExecuteFlashcmdBurn(int slot);
	bool ExecuteFlashcmdRead(int timeout_ms, int slot, wchar_t *result, int reslen);

public:
	bool ExecuteWlanConnect(int timeout_ms, wchar_t *result, int reslen);
	bool ExecuteWlanDisconnect(int timeout_ms);
};

//! fastboot shell
class CShellFastboot : public CShellContext, public CPipeline
{
protected:
	virtual bool ExecuteShell(const wchar_t *command, int timeout_ms, const wchar_t *token,  
			bool check = true, wchar_t *result = nullptr, int reslen = 0);
	virtual bool AnalysisResult(wchar_t *result, const wchar_t *token, bool check = true);
	
public:
	bool ExecuteCommand(const wchar_t *command, int timeout_ms,
            bool check = true, wchar_t *result = nullptr, int reslen = 0);
};

#endif