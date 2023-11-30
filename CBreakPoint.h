#pragma once
#include <windows.h>
#include<vector>
using std::vector;


typedef struct _DBG_REG7 {
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;
	unsigned : 6;// 保留的无效空间
	unsigned RW0 : 2; unsigned LEN0 : 2;
	unsigned RW1 : 2; unsigned LEN1 : 2;
	unsigned RW2 : 2; unsigned LEN2 : 2;
	unsigned RW3 : 2; unsigned LEN3 : 2;
} R7, * PR7;


typedef struct _StcBp {
	int type;
	LPVOID BpAddr;
	BOOL FlagAllow;
	char OldOpcode[2];
}StcBp,*PStcBp;

typedef struct _ConditionBp {
	LPVOID BpAddr;
	DWORD BpValue;
	BOOL flag;
}ConditionBp, * PConditionBp;

struct PreviousboInfo {
	//int previousIsBp = 0;
	//int whichbp = -1;
	LPVOID previousAddr;
	int type;
	int len;
};

struct SetMemBpInfo {
	LPVOID UserSetMemAddr;
	int UserSetType;
	DWORD dwUserOldProtected;
};

struct RecordBpInfo {
	LPVOID MemAddrToReset;
	int TypeToReset;
	DWORD dwOldProtected;
};

class CBreakPoint
{
public:
	//硬件断点
	PreviousboInfo bpInfo;
	void SetHwBreakPoint(HANDLE hThread, LPVOID addr, int type, int len);
	BOOL FixHwBreakPoint(HANDLE hThread, LPVOID addr);


	//内存断点
	SetMemBpInfo UserSetMemInfo;
	RecordBpInfo RecordMemBpInfo;
	void SetMmBreakPoint(HANDLE hProcess, LPVOID addr, int type);
	void FixMmBreakPoint(HANDLE hProcess, HANDLE hThread, LPVOID addr, int type);


	//单步步入断点
	void FixTfBreakPoint(HANDLE hThread);
	void SetTfBreakPoint(HANDLE hThread);
	BOOL Int3TriggerTF;
	BOOL HardBpTriggerTF;
	BOOL MemBpTriggerTF;
	BOOL UserSetTF;
	BOOL StepOverSetTF;
	BYTE PreviousTF;
	
	//Int3断点
	LPVOID Int3Infinite;
	vector<StcBp>vecInt3;
	char OnceInt3OldOpcode[2];
	void SetInt3BreakPoint(HANDLE hProcess,LPVOID addr,BOOL Once=0);
	int GetVectorIndex(LPVOID addr);
	int FixInt3BreakPoint(HANDLE hProcess, HANDLE hThread, LPVOID addr);
	void UserCancelInt3BreakPoint(HANDLE, LPVOID, int index=-1);

	//条件断点
	ConditionBp StcConditionBp;


	//寄存器
	CONTEXT RegContext;
	void UpdateRegister(HANDLE);

	void UserShowInt3BreakPoint();//bl

};

