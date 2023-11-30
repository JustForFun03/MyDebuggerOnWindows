#pragma once
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include "CommandTransLate.h"
#include "CBreakPoint.h"

typedef struct _stackData {
	DWORD OEP_Esp;
	DWORD Current_Esp;
	DWORD Current_Ebp;

}StackData,*PStackData;
class CDebugger :public CBreakPoint
{
	
public:
	//~CDebugger();
	DEBUG_EVENT ObjDebugEcvent;
	HANDLE hProcess;
	HANDLE hThread;
	BOOL IsSysInt;
	BOOL AntiDebug;


	//BOOL IsUserOnceInt;
	LPTHREAD_START_ROUTINE OEP;
	StackData Stack{};

	BOOL init();
	BOOL Open();
	BOOL Load();
	void openHandle();
	void closeHandle();
	void Run();
	DWORD DisPatchEvent(DEBUG_EVENT*);
	DWORD DisPatchException(DEBUG_EVENT* pDbgEvent);
	void UpdateStack(BOOL Start=0);
	//用户处理

	vector<HMODULE>vechModule;
	BOOL UserInput();
	//BOOL ResumeExecute(CommandTransLate& objCmdEnter);

	BOOL OperateDebugInfo(CommandTransLate& objCmdEnter);
	//反汇编读取
	BOOL UnassemblyRead(CommandTransLate& objCmdEnter);
	//反汇编写入
	BOOL UnassemblyWrite(CommandTransLate& objCmdEnter);
	//遍历模块信息
	BOOL GetModuleInfo(DWORD);
	//下面两个函数弃用
	void get_export_information(HANDLE hProcess,char* buff);
	void get_import_information(HANDLE hProcess,char* buff);

};


