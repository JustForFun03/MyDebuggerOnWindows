#include "CBreakPoint.h"


void CBreakPoint::SetHwBreakPoint(HANDLE hThread, LPVOID addr, int type, int len)//默认参数为0
{
	CONTEXT context{ CONTEXT_ALL };
	GetThreadContext(hThread, &context);
	PR7 Dr7 = (PR7)&context.Dr7;

	//区分执行和读写
	if (!type) //执行断点
	{
		//不需要操作，此时传进来的参数len应该也为0
		len = 0;
	}
	else //读写断点  //type==1写   type==3读写
	{
		if (len == 0) //1个字节
		{
			//对地址长度没有要求
		}
		else if (len == 1)//两个字节
		{
			addr = (LPVOID)((DWORD)addr - ((DWORD)addr)% 2);
		}
		else if (len == 3) //四个字节
		{
			addr = (LPVOID)((DWORD)addr - ((DWORD)addr) % 4);
		}
		else if (len == 2) //八个字节
		{
			addr = (LPVOID)((DWORD)addr - ((DWORD)addr) % 8);
		}
		else
		{
			printf("hp 长度参数 Error\n");
		}
	}
	


	if (Dr7->L0 == 0)
	{
		Dr7->L0 = 1;
		Dr7->LEN0 = len;
		Dr7->RW0 = type;
		context.Dr0 = (DWORD)addr;
	}
	else if (Dr7->L1 == 0)
	{
		Dr7->L1 = 1;
		Dr7->LEN1 = len;
		Dr7->RW1 = type;
		context.Dr1 = (DWORD)addr;
	}
	else if (Dr7->L2 == 0)
	{
		Dr7->L2 = 1;
		Dr7->LEN2 = len;
		Dr7->RW2 = type;
		context.Dr2 = (DWORD)addr;
	}
	else if (Dr7->L3 == 0)
	{
		Dr7->L3 = 1;
		Dr7->LEN3 = len;
		Dr7->RW3 = type;
		context.Dr3 = (DWORD)addr;
	}
	else
	{
		printf("没有可用的硬件寄存器了!");
	}
	SetThreadContext(hThread, &context);
}

BOOL  CBreakPoint::FixHwBreakPoint(HANDLE hThread, LPVOID addr)
{
	CONTEXT context{ CONTEXT_ALL };
	GetThreadContext(hThread, &context);
	PR7 Dr7 = (PR7)&context.Dr7;
	LPVOID addrMem = 0;
	switch (context.Dr6 & 0xF)
	{
	case 1:
		Dr7->L0 = 0; 
		bpInfo.type = Dr7->RW0; 
		bpInfo.len = Dr7->LEN0;
		addrMem = (LPVOID)context.Dr0;
		break;
	case 2:
		Dr7->L1 = 0;
		bpInfo.type = Dr7->RW1;
		bpInfo.len = Dr7->LEN1; 
		addrMem = (LPVOID)context.Dr1;

		break;
	case 4:
		Dr7->L2 = 0; 
		bpInfo.type = Dr7->RW2;
		bpInfo.len = Dr7->LEN2; 
		addrMem = (LPVOID)context.Dr2;

		break;
	case 8:
		Dr7->L3 = 0;
		bpInfo.type = Dr7->RW3; 
		bpInfo.len = Dr7->LEN3;
		addrMem = (LPVOID)context.Dr3;

		break;
	default:
		return -1;
		break;
	}
	//bpInfo.previousIsBp = 1;
	//bpInfo.whichbp = 1;//

	//判断是否是执行断点
	if (bpInfo.type==0)//是执行断点
	{
		bpInfo.previousAddr = addr;
		SetThreadContext(hThread, &context);
		SetTfBreakPoint(hThread);
		return 1;
	}
	else //1,3
	{
		bpInfo.previousAddr = addrMem;
		SetThreadContext(hThread, &context);
		SetTfBreakPoint(hThread);
		return 0;

	}
}



//extern LPVOID g_dWMemAddr;
//extern int nIsGo;
void CBreakPoint::SetMmBreakPoint(HANDLE hProcess, LPVOID addr, int type)
{
	//记录修复的信息
	RecordMemBpInfo.MemAddrToReset = addr;
	RecordMemBpInfo.TypeToReset = type;
	if (type == 8) //执行断点 
	{

		VirtualProtectEx(hProcess, addr, 1, PAGE_READWRITE, &RecordMemBpInfo.dwOldProtected);
	}
	else if (type==1) //写
	{
		VirtualProtectEx(hProcess, addr, 1, PAGE_EXECUTE_READ, &RecordMemBpInfo.dwOldProtected);
	}
	else if (type==0) //读
	{
		VirtualProtectEx(hProcess, addr, 1, PAGE_NOACCESS, &RecordMemBpInfo.dwOldProtected);
	}
	else
	{
		printf("SetMemBp Error");
	}
}

void CBreakPoint::FixMmBreakPoint(HANDLE hProcess, HANDLE hThread, LPVOID addr, int type)
{

	if (type == 8)
	{
		VirtualProtectEx(hProcess, addr, 1, 
			UserSetMemInfo.dwUserOldProtected, &RecordMemBpInfo.dwOldProtected);
	}
	else if (type==1)
	{
		VirtualProtectEx(hProcess, addr, 1,
			UserSetMemInfo.dwUserOldProtected, &RecordMemBpInfo.dwOldProtected);
	}
	else if (type==0)
	{
		VirtualProtectEx(hProcess, addr, 1,
			UserSetMemInfo.dwUserOldProtected, &RecordMemBpInfo.dwOldProtected);
	}
	SetTfBreakPoint(hThread);
	//bpInfo.previousIsBp = 1;
	//bpInfo.whichbp = 2;
}





void CBreakPoint::FixTfBreakPoint(HANDLE hThread) {
	//恢复TF寄存器值
	CONTEXT context{ CONTEXT_ALL };
	GetThreadContext(hThread, &context);
	if (PreviousTF==1)
	{
		context.EFlags |= 0x00000100;
	}
	else
	{
		context.EFlags &= 0xFFFFFEFF;
	}

	SetThreadContext(hThread, &context);

	return;
}

//t主动触发，以及永久断点被动触发
void CBreakPoint::SetTfBreakPoint(HANDLE hThread) {
	//设置TF寄存器值
	CONTEXT context{CONTEXT_ALL};
	GetThreadContext(hThread, &context);
	context.EFlags |= 0x00000100;
	SetThreadContext(hThread, &context);
	return;
}

//设置Int3断点 参数3为0时为永久断点，才加入vector,为1时为一次性断点
void CBreakPoint::SetInt3BreakPoint(HANDLE hProcess,LPVOID addr,BOOL Once) {

	StcBp StcBpInt3{};

	StcBpInt3.FlagAllow = 1;
	StcBpInt3.type = 0;
	StcBpInt3.BpAddr=addr;
	DWORD dwRead = 0;
	ReadProcessMemory(hProcess, addr, (LPVOID)&StcBpInt3.OldOpcode, 1, &dwRead);
	DWORD dwWrite = 0;
	WriteProcessMemory(hProcess, addr,"\xCC", 1, &dwWrite);

	if (Once==0)//永久断点
	{
		//增加到软件断点列表
		vecInt3.push_back(StcBpInt3); 
	}
	else if(Once==1 )  //一次性断点，不加入vec
	{
		//存到一次性断点Opcode中
		strcpy_s(OnceInt3OldOpcode,2,StcBpInt3.OldOpcode);
	}
	else if (Once==2)
	{

	}

	return;
}
//获得断点vector中特定地址对应的索引
int CBreakPoint::GetVectorIndex(LPVOID addr) {
	size_t length = vecInt3.size();
	for (size_t index = 0; index < length; index++)
	{
		if (addr == vecInt3[index].BpAddr)
		{
			return index;
		}
	}
	return -1;
}

//修复Int3断点  
int CBreakPoint::FixInt3BreakPoint(HANDLE hProcess, HANDLE hThread,LPVOID addr) 
{
	LPVOID OldOpcode=NULL;
	auto index = GetVectorIndex(addr);//根据地址得到vector索引
	DWORD dwWrite = 0;
	if (index == -1) //表明一次性断点
	{
		OldOpcode = OnceInt3OldOpcode;
		WriteProcessMemory(hProcess, addr, OldOpcode, 1, &dwWrite);
		return 1;
	}
	else //永久断点
	{
		OldOpcode = vecInt3[index].OldOpcode;
		WriteProcessMemory(hProcess, addr, OldOpcode, 1, &dwWrite);
		return 0;
	}

	
}

//bc 取消断点 参数索引或者地址
void CBreakPoint::UserCancelInt3BreakPoint(HANDLE hProcess,LPVOID addr, int index) {

	size_t vecIndex = 0;
	if (index==-1)//通过地址
	{
		vecIndex = GetVectorIndex(addr);//根据地址得到vector索引
		
	}
	else //通过索引，此时地址参数无效
	{
		vecIndex = index;
	}
	auto BpAddr = vecInt3[vecIndex].BpAddr;
	auto OldOpcode = vecInt3[vecIndex].OldOpcode;
	DWORD dwRead = 0;
	WriteProcessMemory(hProcess, BpAddr, (LPVOID)OldOpcode, 1, &dwRead);
	
	//删除软件断点
	vecInt3.erase(vecIndex + vecInt3.begin());
	return;

}

void CBreakPoint::UpdateRegister(HANDLE hThread)
{
	RegContext = { CONTEXT_ALL };
	GetThreadContext(hThread, &RegContext);
}
//bl显示断点
void CBreakPoint::UserShowInt3BreakPoint() {
	auto length = vecInt3.size();
	for (size_t i = 0; i < length; i++)
	{
		printf("%u,%u,%d\n",i, (DWORD)vecInt3[i].BpAddr, vecInt3[i].FlagAllow);
	}
}

