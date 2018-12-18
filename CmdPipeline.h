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

class CEventDef {
public:
	CEventDef() : m_event(nullptr) {
		m_default = CreateEvent(NULL, TRUE, FALSE, NULL);
	}
	~CEventDef() {
		CloseHandle(m_default), m_default = nullptr;
	}

private:
	CEventDef(const CEventDef &);
	CEventDef & operator =(const CEventDef &);

public:
	void operator=(const HANDLE & handle) { m_event = handle; }
	operator HANDLE() { return nullptr == m_event ? m_default : m_event ; }

private:
	HANDLE m_default;
	HANDLE m_event;
};

//! pipeline
class CPipeline 
{
public:
	CPipeline();
	virtual ~CPipeline();

private:
	CPipeline(const CPipeline &);
	CPipeline & operator =(const CPipeline &);

public:
	bool Initialize();
	void Release();

public:
	inline void SetPathCurrent(const wchar_t * path) { m_pathCurrent = path; }
	inline void SetPathModule (const wchar_t * path) { m_pathModule  = path; }
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
	int  CommandRead(int timeout_ms, const wchar_t * signle);
    int  CommandRead(int timeout_ms, wchar_t *result, int reslen);
    int  CommandRead(const wchar_t *token, int timeout_ms, wchar_t *result, int reslen);

protected:
	void ProcessAbort();
	void ProcessClean();
	void ProcessClose();

public:
	inline void SetCallbackMessage(void * object, void * func) { 
		m_handleMessage = object;
		m_callbackMessage = static_cast<PCALLBACKMESSAGE>(func); 
	}
	inline void SetCallbackProcess(void * object, void * func) { 
		m_handleProcess = object;
		m_callbackProcess = static_cast<PCALLBACKPROCESS>(func); 
	}
	inline void log_trace(wchar_t * message) {
		if (m_callbackMessage) m_callbackMessage(m_handleMessage, message); 
	}

public:
    const wchar_t* ErrorMessage() { return m_errormsg; }

private:
	typedef void (_stdcall * PCALLBACKMESSAGE)(void *, wchar_t *);
	typedef void (_stdcall * PCALLBACKPROCESS)(void *, const wchar_t *, unsigned int);
	void * m_handleMessage;
	void * m_handleProcess;
	PCALLBACKMESSAGE m_callbackMessage;
	PCALLBACKPROCESS m_callbackProcess;

protected:
	wchar_t m_errormsg[256];

private:
	std::wstring m_pathModule;
	std::wstring m_pathCurrent;

private:
	CEventDef m_removed;
	HANDLE m_process;
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
	virtual bool ExecuteShell(const wchar_t *command, int timeout_ms, wchar_t *result = nullptr, int reslen = 0);
	virtual bool ExecuteShell(const wchar_t *command, int timeout_ms, const wchar_t *token,  
			bool check = true, wchar_t *result = nullptr, int reslen = 0);
	virtual bool AnalysisResult(wchar_t *result, const wchar_t *token, bool check = true);

public:
	bool ExecuteCommand(const wchar_t *command, int timeout_ms,
            wchar_t *result = nullptr, int reslen = 0);
#if 0
	bool ExecuteCommand(const wchar_t *command, int timeout_ms, const wchar_t *token, 
			wchar_t *result = nullptr, int reslen = 0);
#endif
	bool ExecuteCommand(const wchar_t *command);

public:
	bool ExecutePSN(int timeout_ms, wchar_t *result, int reslen);
	bool ExecuteLS(int timeout_ms, const wchar_t *path);
	bool ExecuteGetProp(int timeout_ms, const wchar_t *prop, wchar_t *result, int reslen);
	bool ExecuteSetProp(int timeout_ms, const wchar_t *prop, const wchar_t *value);
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
	bool ExecuteFlashcmdBurn(int slot, const wchar_t * token);
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

//! qualcomm shell

class CShellQualcomm : public CShellContext, public CPipeline
{
protected:
	virtual bool ExecuteShell(const wchar_t *command, int timeout_ms, const wchar_t *token,  
			bool check = true, wchar_t *result = nullptr, int reslen = 0);
	virtual bool AnalysisResult(wchar_t *result, const wchar_t *token, bool check = true);
	
public:
	bool ExecuteSahara(const wchar_t * command, int timeout_ms,
            wchar_t * result = nullptr, int reslen = 0);
	bool ExecuteFirehose(const wchar_t * command, int timeout_ms);

private:
	static const wchar_t * PROCESS_SAHARA;
	static const wchar_t * PROCESS_FHLOADER;
};

//! execute process

class CExecuteProcess : public CPipeline
{
public:
	bool execute(const wchar_t * command, int timeout_ms);
	const std::wstring & result() { return m_result; }

private:
	std::wstring m_result;
};

#endif