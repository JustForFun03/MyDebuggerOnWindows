
#include "CDebugger.h"
#include "CDisassembly.h"

#include <stdio.h>

#include <TlHelp32.h> //用于遍历文件
#include <tchar.h>
//#include<processthreadsapi.h>
#include <iostream>  //用于控制台打印正常
#include <atlstr.h> //用于CString
#include "XEDParse.h" //这两个反汇编引擎
#pragma comment(lib,"XEDParse.lib")

#define PlugInBasePath L"D:\\Files_and_doc\\visual_studio2017\\Debugger"
#define testExe L"D:\\Files_and_doc\\visual_studio2017\\Debugger\\Debugger\\111.exe"
#define DefaultPrintLine 20

typedef  void (*PlugInFun)(HANDLE);
void FilePathCollection(const WCHAR* BasePath, vector<WCHAR*>& vec_FilePath) {

	//获取给定文件夹中所有文件路径信息

	WIN32_FIND_DATA  wfd = {};
	//setlocale(LC_ALL, "CHS"); // 设置字符编码格式
	TCHAR szDirtoryPath[MAX_PATH * 2] = { 0 };
	_stprintf_s(szDirtoryPath, MAX_PATH * 2, _T("%s\\%s"), BasePath, _T("*"));
	HANDLE hFindFile = FindFirstFile(szDirtoryPath, &wfd);
	if (hFindFile != INVALID_HANDLE_VALUE) {
		do {

			if ((wcscmp(wfd.cFileName, L".")) != 0 && (wcscmp(wfd.cFileName, L"..")) != 0) {


				if ((wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
				{
					CString temp;
					temp.Format(_T("%s\\%s"), BasePath, wfd.cFileName);
					FilePathCollection(temp, vec_FilePath);
				}

				else
				{
					//挑选dll文件放入
					BOOL flag = 0;
					int LenFilename = wcslen(wfd.cFileName);
					for (int i = 0; i < LenFilename; i++)
					{
						if (_wcsicmp((wfd.cFileName + i), L".dll") == 0)
						{
							flag= 1;
							break;
						}
					}

					if (flag)
					{
						CString temp;
						temp.Format(_T("%s\\%s"), BasePath, wfd.cFileName);
						WCHAR* pTemp = new WCHAR[wcslen(temp.GetBuffer()) + 1];
						wcscpy_s(pTemp, wcslen(temp.GetBuffer()) + 1, temp.GetBuffer());
						vec_FilePath.push_back(pTemp);
					}
				}

			}


		} while (FindNextFile(hFindFile, &wfd));
	}
}

BOOL CDebugger::init() {
	//获得插件路径列表
	vector<WCHAR*>vecPluginDll;
	FilePathCollection(PlugInBasePath, vecPluginDll);

	//加载插件dll
	for (auto& ele:vecPluginDll)
	{
		LoadLibrary(ele);
	}

	//加载插件dll
	for (auto& ele : vecPluginDll)
	{
		delete []ele;
	}
	printf("是否开启反调试？1开启 0不开启:");
	
	AntiDebug = _getch();;
	return 0;
}
//
//CDebugger::~CDebugger() {
//}
BOOL CDebugger::Open() {

	HWND hConsoleWnd = FindWindow(L"ConsoleWindowClass", NULL);
	WCHAR FilePathName[MAX_PATH*2]{};
	
	//获取文件路径名
	OPENFILENAME file = { 0 };
	file.hwndOwner = hConsoleWnd;
	file.lStructSize = sizeof(file);
	file.lpstrFilter = L"所有文件(*.*)\0*.*\0Exe文件(*.exe)\0*.exe\0\0";//要选择的文件后缀 
	file.lpstrInitialDir = L"";//默认的文件路径 
	file.lpstrFile = FilePathName;//存放文件名称的缓冲区 
	file.nMaxFile = _countof(FilePathName);
	file.nFilterIndex = 0;
	file.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;//标志如果是多选要加上OFN_ALLOWMULTISELECT
	BOOL bSel = GetOpenFileName(&file);
	CString filePath = file.lpstrFile;
	
	STARTUPINFO si{};         //启动信息结构体
	PROCESS_INFORMATION pi{}; //进程信息结构体
	si.cb = sizeof(STARTUPINFO);  //初始化启动信息结构体大小
	BOOL Ret = CreateProcess(filePath.GetBuffer(), NULL,
		NULL, NULL,
		FALSE,                
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, NULL, NULL,
		&si,&pi);
	if (!Ret) 
{
		printf("Error on CreateProcess");
		return 1;
	}
	
	IsSysInt = 1;

	return 0;
}

BOOL CDebugger::Load() {
	
	printf("请输入pid\n");
	//管理员权限
	DWORD Pid = 0;
	scanf_s("%u",&Pid);
	return DebugActiveProcess(Pid);

}
void CDebugger::openHandle() {
	hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,ObjDebugEcvent.dwProcessId);
	hThread = OpenThread(PROCESS_ALL_ACCESS,FALSE,ObjDebugEcvent.dwThreadId);
}
 
void CDebugger::closeHandle() {
	CloseHandle(hProcess);
	CloseHandle(hThread);
}
void CDebugger::Run() {
	//调试事件循环
	ObjDebugEcvent = { 0 };
	while (true)
	{
		WaitForDebugEvent(&ObjDebugEcvent,INFINITE);
		//打开句柄
		openHandle();

		DWORD dwRet = DisPatchEvent(&ObjDebugEcvent);//进入第二层分发异常
		//指示调试目标进程
		ContinueDebugEvent(
			ObjDebugEcvent.dwProcessId,
			ObjDebugEcvent.dwThreadId,
			dwRet  
		);
		closeHandle();
	}
}
DWORD CDebugger::DisPatchEvent(DEBUG_EVENT* pDbgEvent) {
	DWORD dwRet = 0;

	//根据调试事件类型返回不同的处理信号
	switch (pDbgEvent->dwDebugEventCode)
	{
	case EXCEPTION_DEBUG_EVENT:
	{
		dwRet = DisPatchException(pDbgEvent);//进入第三层分发异常
		return dwRet;
	}
		break;
	case CREATE_PROCESS_DEBUG_EVENT: //系统调试中断事件，在此设置OEP断点
	{
		//设置OEP软件断点
		OEP = pDbgEvent->u.CreateProcessInfo.lpStartAddress;
		//SetTfBreakPoint();
		return DBG_CONTINUE; 
	}
		break;
	default:
		printf("DebugEvent Error\n");
		return DBG_CONTINUE;
		break;
	}


}

DWORD CDebugger::DisPatchException(DEBUG_EVENT* pDbgEvent) {
	//这里是异常分发的第三层，需要处理异常
	auto DbgInfo = pDbgEvent->u.Exception.ExceptionRecord;
	auto ExceptionCode = DbgInfo.ExceptionCode;
	auto ExceptionAddr = DbgInfo.ExceptionAddress;
	
	UpdateRegister(hThread);
	switch (ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT://软件断点
	{
		if (IsSysInt==1)
		{
			IsSysInt = 0;
			//设置OEP软件断点
			SetInt3BreakPoint(hProcess, OEP,1);
			printf("系统中断异常\n");
			if (AntiDebug=='1')//开启反调试
			{
				//反反调试
				HMODULE hModule = GetModuleHandle(L"AntiDebug1.dll");
				if (hModule == nullptr)
				{
					printf("Error\n");
				}
				//调用反反调试插件函数
				PlugInFun pPlugInFun = (PlugInFun)GetProcAddress(hModule, "AntiAntiDebugByBeingDebugged");
				pPlugInFun(hProcess);
				printf("反反调试已完成\n");
			}
			
		}//处理一般软件断点
		else //非系统断点
		{
			//栈和寄存器更新
			if (ExceptionAddr == OEP) //初始化
			{
				//初始化栈底
				UpdateStack(1);
			}
			else
			{
				UpdateStack();
			}

			//修复Eip
			RegContext.Eip -= 1;
			SetThreadContext(hThread, &RegContext);

			//修复CC处
			int Ret = FixInt3BreakPoint(hProcess, hThread, (LPVOID)ExceptionAddr);
			if (Ret)//一次性断点
			{
				printf("一次性断点异常\n");
			}
			else //永久断点
			{
				printf("永久性断点异常\n");
				Int3TriggerTF = 1;//设置触发TF标志位

				//设置TF
				//先保存之前的TF
				CONTEXT context{ CONTEXT_ALL };
				GetThreadContext(hThread, &context);
				PreviousTF = ((context.EFlags >>= 0x8) &= 0x00000001);
				SetTfBreakPoint(hThread);

				Int3Infinite = ExceptionAddr;
				printf("触发单步步入\n");

				if (/*StcConditionBp.flag == 1 &&*/ StcConditionBp.BpAddr == ExceptionAddr)//条件断点引发
				{
					if (StcConditionBp.BpValue != RegContext.Eax)//不满足条件
					{
						return DBG_CONTINUE;
					}
					//StcConditionBp.flag = 0;
				}
			}
		}
		
	}
	break;
	case EXCEPTION_SINGLE_STEP://硬件断点和TF断点
	{
		//以下是被动触发异常
		if (Int3TriggerTF) //INT3触发的TF
		{
			//重置CC
			SetInt3BreakPoint(hProcess, Int3Infinite, 2);
			Int3TriggerTF = 0;

			//下面也可以利用previousTF是否等于1来判断
			if (UserSetTF ==1) //用户设置了单步步入
			{

			}
			else //用户没有设置单步步入
			{
				return DBG_CONTINUE;
			}

		}
		else if (StepOverSetTF) //stepover触发
		{
			StepOverSetTF = 0;
			//设置一次性断点
			UpdateStack();

			LPVOID UAddr = (LPVOID)Stack.Current_Esp;
			//读取内存内容
			DWORD dwRead = 0;
			char Esp[5] = { 0 };
			ReadProcessMemory(hProcess, (LPVOID)UAddr, Esp, 4, &dwRead);


			SetInt3BreakPoint(hProcess, (LPVOID)(*(DWORD*)Esp), 1);
			//UserSetTF = 0;
			return DBG_CONTINUE;
		}
		else if (HardBpTriggerTF) //硬件断点触发单步步入
		{
			HardBpTriggerTF = 0;

			//重设HardBp
			SetHwBreakPoint(hThread,bpInfo.previousAddr ,bpInfo.type ,bpInfo.len);
			//下面也可以利用previousTF是否等于1来判断
			if (UserSetTF ==1) //用户设置了单步步入
			{

			}
			else //用户没有设置单步步入
			{
				return DBG_CONTINUE;
			}
		}
		else if (MemBpTriggerTF)//内存断点触发单步步入
		{
			MemBpTriggerTF = 0;
			//再次设置分页属性,使用record结构体
			SetMmBreakPoint(hProcess,RecordMemBpInfo.MemAddrToReset,RecordMemBpInfo.TypeToReset);
			if (UserSetTF == 1) //用户设置了单步步入
			{
			}
			else //用户没有设置单步步入
			{
				return DBG_CONTINUE;
			}
		}

		if (UserSetTF ==1)//用户设置的TF异常
		{
			UserSetTF = 0;
		}
		else if(FixHwBreakPoint(hThread, ExceptionAddr)>=0)//硬件断点
		{
			//修复硬件断点
			//区分执行和读写,修改Eip
			//PR7 Dr7 = (PR7)&RegContext.Dr7;
			//BOOL IsHpExe = 
			//if (!IsHpExe)//不是硬件断点需要修改Eip,陷阱指向下一条指令地址
			//{
			//	//修复Eip
			//	RegContext.Eip =-1;
			//	SetThreadContext(hThread, &RegContext);
			//}
			//设置TF
			//先保存之前的TF
			CONTEXT context{CONTEXT_ALL};
			GetThreadContext(hThread,&context);
			PreviousTF=((context.EFlags>>=0x8)&=0x00000001);
			SetTfBreakPoint(hThread);
			HardBpTriggerTF = 1;
		}
	}
	break;
	case EXCEPTION_ACCESS_VIOLATION://访问断点
	{
		auto ExceptionType = DbgInfo.ExceptionInformation[0];//用于内存断点类型
		auto ExceptionMemAddr = DbgInfo.ExceptionInformation[1];//用于内存断点地址
		//恢复页面属性
		FixMmBreakPoint(hProcess,hThread, (LPVOID)ExceptionMemAddr, ExceptionType);//注意区分指令地址和内存地址
		MemBpTriggerTF = 1;

		//判断是不是我们设置的地址和类型
		if ((LPVOID)ExceptionMemAddr==UserSetMemInfo.UserSetMemAddr
			&& ExceptionType== UserSetMemInfo.UserSetType
			)//是的话 ，截断显示汇编
		{
		}
		else //不是，直接跳过
		{
			return DBG_CONTINUE;
		}
	}
	break;
	default://其它异常不做处理，交给调试程序本身的异常处理机制
		return DBG_EXCEPTION_NOT_HANDLED;
		break;
	}

	//反汇编显示，默认20行
	Capstone::DisAsm(hProcess,  ExceptionAddr, DefaultPrintLine);
	//用户交互
	UserInput();

	return DBG_CONTINUE;
}

void CDebugger::UpdateStack(BOOL Start) {
	UpdateRegister(hThread);
	Stack.Current_Ebp = RegContext.Ebp;
	Stack.Current_Esp = RegContext.Esp;
	if (Start)
	{
		Stack.OEP_Esp = RegContext.Esp;
	}
}
BOOL CDebugger::UserInput() {
	while (true)
	{
		CommandTransLate objCmdEnter;
		//得到用户输入
		objCmdEnter.GetEnterStr();
		//命令切割
		DWORD NumParam = objCmdEnter.DivideCmdParam();
		if (!NumParam)
		{
			printf("Input is not valid\n");
		}
		else
		{
			//执行命令
			//特定条件下跳出用户操作的循环，恢复目标活动进程
			if (OperateDebugInfo(objCmdEnter))
			{
				break;
			}
			//原地取消断点
			auto ExceptionAddr= ObjDebugEcvent.u.Exception.ExceptionRecord.ExceptionAddress;
			int CheckIsOnceInt3 = GetVectorIndex(ExceptionAddr);
			if ((CheckIsOnceInt3 == -1) && Int3TriggerTF) //已经从永久断点中删除，撤销TF触发和重置CC
			{
				Int3TriggerTF = 0;//触发TF标志位
				//恢复原来的TF
				FixTfBreakPoint(hThread);
				//修复原先的
				printf("取消触发单步步入\n");
			}
		}
	}
	return 0;
}
//BOOL CDebugger::ResumeExecute(CommandTransLate& objCmdEnter)
//{
//	char* CmdType = objCmdEnter.vec_ParamArr[0];
//	if (strlen(CmdType)==1)
//	{
//		switch (*CmdType)
//		{
//		case 'g':
//		{
//			return 1;
//		}
//		case 'p':
//		{
//			return 1;
//		}
//		case 't'://单步步入
//		{
//			SetTfBreakPoint();
//			return 1;
//		}
//		break;
//		default:
//			printf("Execute Not Work\n");
//			return 0;
//			break;
//		}
//	}
//	else
//	{
//		printf("ExecuteChar long\n");
//		return 0;
//	}
//	
//};

//用户操作
BOOL CDebugger::OperateDebugInfo(CommandTransLate& objCmdEnter) {

	char* CmdType = objCmdEnter.vec_ParamArr[0];
	switch (CmdType[0])
	{
	case 'u'://反汇编
	{
		UnassemblyRead(objCmdEnter);
	}
	break;
	case 'a'://编辑汇编
	{
		UnassemblyWrite(objCmdEnter);
	}
	break;
	case 'd'://内存
	{
		switch (CmdType[1])
		{
		case 'd'://dd
		{
			if (objCmdEnter.vec_ParamArr.size() == 2) //默认数量80 只支持地址
			{
				LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);

				//读取内存内容
				size_t Count = 80;
				DWORD dwRead = 0;
				BYTE MemBuffer[80 * 4+1]{0};
				ReadProcessMemory(hProcess, UAddr, MemBuffer, Count *4, &dwRead);

				for (size_t i = 0; i < Count; i++)
				{
					if (i % 0x8 == 0)
					{
						printf("0x%08x\t", (DWORD)((DWORD*)UAddr +i));
					}
					BYTE temp1 = *( (PCHAR)((DWORD*)MemBuffer + i) + 0);
					BYTE temp2 = *( (PCHAR)((DWORD*)MemBuffer + i) + 1);
					BYTE temp3 = *( (PCHAR)((DWORD*)MemBuffer + i) + 2);
					BYTE temp4 = *( (PCHAR)((DWORD*)MemBuffer + i) + 3);
					printf("%02x%02x%02x%02x  ", temp1, temp2, temp3, temp4);
					
					if ((i+1)%0x8== 0)
					{
						printf("\n");
					}
				}
			}
			else if (objCmdEnter.vec_ParamArr.size() == 3)//自定义数量
			{
				//SetInt3BreakPoint(hProcess, );
			}
			else
			{
				printf("dd error\n");
			}
		}
		break;
		case 'w'://dw
		{

		}
		break;
		case 'b'://db
		{

		}
		break;
		default:
			printf("d Cmd invalid\n");
			break;
		}

	}
	break;
	case 'e'://修改内存
	{
		if (objCmdEnter.vec_ParamArr.size() == 3) //默认 e 地址  value 
		{

			LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
			DWORD HexNUmber=strlen(objCmdEnter.vec_ParamArr[2]);
			DWORD ByteNUmber = HexNUmber/2;

			LPVOID SetValue = objCmdEnter.SetValuerCharToHex(objCmdEnter.vec_ParamArr[2]);
			//写入内存内容
			DWORD dwWrite = 0;
			//BYTE MemBuffer[80*4]{ 0 };

			//memcpy(MemBuffer, (char*)SetValue, ByteNUmber);
			WriteProcessMemory(hProcess, UAddr, SetValue, ByteNUmber, &dwWrite);
			//WriteProcessMemory(hProcess, UAddr, MemBuffer, ByteNUmber, &dwWrite);
			printf("Write Mem sucess\n");
		}
	}
	break;
	case 'r'://寄存器
	{
		UpdateRegister(hThread);
		if (objCmdEnter.vec_ParamArr.size() == 1) //查看所有寄存器
		{
			
			printf("Eax = %08x\tEax = %08x\n",RegContext.Eax, RegContext.Ebx);
			printf("Ecx = %08x\tEdx = %08x\n",RegContext.Ecx, RegContext.Edx);
			printf("Esp = %08x\tEbp = %08x\n",RegContext.Esp, RegContext.Ebp);
			printf("Esi = %08x\tEdi = %08x\n",RegContext.Esi, RegContext.Edi);
			printf("Eip = %08x\tEfg = %08x\n",RegContext.Eip, RegContext.EFlags);
		}
		else if (objCmdEnter.vec_ParamArr.size() == 2) //查看特定寄存器
		{
			if (!_stricmp(objCmdEnter.vec_ParamArr[1],"eip"))
			{
				printf("Eip = %08x\n", RegContext.Eip);
			}
			else if (!_stricmp(objCmdEnter.vec_ParamArr[1], "Efg"))
			{
				printf("Efg = %08x\n", RegContext.EFlags);
			}
			else if (!_stricmp(objCmdEnter.vec_ParamArr[1], "Eax"))
			{
				printf("Eax = %08x\n", RegContext.Eax);
			}
			//...
		}
		else if (objCmdEnter.vec_ParamArr.size() == 3)//修改寄存器  只支持修改一个
		{
			if (!_stricmp(objCmdEnter.vec_ParamArr[1], "eip"))
			{
				LPVOID UserSetValue=objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[2]);
				RegContext.Eip = (DWORD)UserSetValue;
			}
			else if(!_stricmp(objCmdEnter.vec_ParamArr[1], "efg"))
			{
				LPVOID UserSetValue = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[2]);
				RegContext.EFlags = (DWORD)UserSetValue;
			}
			else if (!_stricmp(objCmdEnter.vec_ParamArr[1], "eax"))
			{
				LPVOID UserSetValue = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[2]);
				RegContext.Eax = (DWORD)UserSetValue;
			}
			//...
			SetThreadContext(hThread,&RegContext);
		}

	}
	break;
	case 'k'://查看堆栈
	{
		//OEP->当前Esp
		UpdateStack(); 

		DWORD Startk = Stack.OEP_Esp;
		DWORD Cunrentk = Stack.Current_Esp;
		size_t length = (Startk- Cunrentk) / 4+1;

		//读取内存内容
		DWORD dwRead = 0;
		DWORD* StackBuffer = new DWORD[length];
		ReadProcessMemory(hProcess, (LPVOID)Cunrentk, StackBuffer, length * 4, &dwRead);

		for (size_t i = 0; i < length; i++)
		{
			printf("0x%08x\t\t%08x", Cunrentk +i*4, *(StackBuffer +i));
			if (Cunrentk + i * 4==RegContext.Ebp)
			{
				printf("<--Ebp");
			}
			printf("\n");
		}
		delete[]StackBuffer;
	}
	break;
	case 'm'://查看模块信息
	{
		if (objCmdEnter.vec_ParamArr.size() == 1)
		{
			GetModuleInfo(GetProcessId(hProcess));
		}
		else if (objCmdEnter.vec_ParamArr.size() == 3)
		{
			//获得对应模块
			LPVOID VecModuleIndex = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
			HMODULE hModule= vechModule[(DWORD)VecModuleIndex];//特定的模块句柄，即加载基址
			
			//获得 导入还是导出
			LPVOID IsImport = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[2]);


			if (IsImport ==0)
			{
				//导出表
				//get_export_information(hProcess,(char*)hModule);
			}
			else
			{
				//导入表
				//get_import_information(hProcess,(char*)hModule);
			}
			
		}
		
	}
	break;
	case 'b'://断点命令
	{
		switch (CmdType[1])
		{
		case 'p'://bp
		{
			if (objCmdEnter.vec_ParamArr.size() == 2)
			{
				LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
				SetInt3BreakPoint(hProcess, UAddr);
			}
			else if (objCmdEnter.vec_ParamArr.size() == 1)//当前下断点
			{
				//SetInt3BreakPoint(hProcess, );
			}
			else if (objCmdEnter.vec_ParamArr.size() == 3)//条件断点 只支持eax
			{
				LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
				LPVOID BpValue = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[2]);//输入得是16进制				StcConditionBp.BpAddr = UAddr; 
				StcConditionBp.BpValue =(BOOL)BpValue;
				StcConditionBp.BpAddr =UAddr;
				//StcConditionBp.flag = 1;
				SetInt3BreakPoint(hProcess, UAddr);
			}
			else
			{
				printf("bp error\n");
			}
		}
		break;
		case 'c'://bc
		{
			if (objCmdEnter.vec_ParamArr.size() == 2) //bc + vector 索引
			{
				LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
				//修复删除断点的CC
				FixInt3BreakPoint(hProcess, hThread, vecInt3[(DWORD)UAddr].BpAddr);
				vecInt3.erase(vecInt3.begin()+ (DWORD)UAddr);
				printf("删除软件断点成功\n");

			}
			else
			{
				printf("bc Error\n");
			}
		}
		break;
		case 'l'://bl 显示断点列表
		{   
			size_t length = vecInt3.size();
			if (length)
			{
				for (size_t i = 0; i < length; i++)
				{
					printf("%u\t%08x\n", i, vecInt3[i].BpAddr);
				}
			}
			else
			{
				printf("断点列表为空");
			}
			printf("\n");
		}
		break;
		case 'h'://bh硬件断点
		{
			if (objCmdEnter.vec_ParamArr.size() == 4) //bh + 地址 + type +Len
			{
				//得到地址
				LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
				int Type = (int)objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[2]);
				int Len = (int)objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[3]);

				if (!Type)
				{
					if (Len == 1)
					{
						Len = 0;
					}
					else if (Len == 2)
					{
						Len = 1;
					}
					else if (Len == 4)
					{
						Len = 3;
					}
					else if (Len == 8)
					{
						Len = 2;
					}
				}
				

				SetHwBreakPoint(hThread, UAddr,Type,Len);
				printf("设置硬件断点成功\n");

			}
			else
			{
				printf("bh Error\n");
			}
		}
		break;
		case 'm'://bm硬件断点
		{
			if (objCmdEnter.vec_ParamArr.size() == 3) //bm + 地址 + type 
			{
				//得到地址
				LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
				int Type = (int)objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[2]);
				
				UserSetMemInfo.UserSetMemAddr=UAddr;
				UserSetMemInfo.UserSetType=Type;
				SetMmBreakPoint(hProcess, UAddr,Type);
				UserSetMemInfo.dwUserOldProtected=RecordMemBpInfo.dwOldProtected;
				printf("设置内存断点成功\n");

			}
			else
			{
				printf("bm Error\n");
			}
		}
		break;
		default:
			printf("bp Cmd invalid\n");
			break;
		}
	}
	break;
	//执行相关
	case 'g': //直接运行  参数：地址  g 0x12345678
	{
		if (objCmdEnter.vec_ParamArr.size() == 1) //
		{
		}
		else if (objCmdEnter.vec_ParamArr.size() == 2) //运行到某处停下
		{
			LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
			SetInt3BreakPoint(hProcess, UAddr,1);
		}
		else if (objCmdEnter.vec_ParamArr.size() == 2)//错误
		{
			printf("g Error\n");
		}
		return 1;
	}
	case 'p'://单步步过
	{
		//获取当前指令的首个Opcode
		auto CurAddr=ObjDebugEcvent.u.Exception.ExceptionRecord.ExceptionAddress;
		size_t Count = 1;
		DWORD dwRead = 0;
		BYTE Opcode=0;
		ReadProcessMemory(hProcess, CurAddr, &Opcode, Count, &dwRead);

		static vector<BYTE>vecOpcode{(BYTE)'\xE8'};
		BOOL Flag = 0;
		for (auto& ele: vecOpcode)
		{
			if (ele== Opcode)
			{
				Flag = 1;
				break;
			}
		}
		//设置TF
		SetTfBreakPoint(hThread);
		UserSetTF = 1;
		if (Flag)//特定的Opcode 
		{
			StepOverSetTF = 1;
		}
		else //不是
		{

		}
		return 1;
	}
	case 't'://单步步入
	{
		//后面可考虑设置参数：数字 t 10
		SetTfBreakPoint(hThread);
		UserSetTF = 1;
		return 1;
	}
	break;
	default:
		printf("Command Error\n");	//非标准输入命令
		break;
	}
	return 0;
}
//u+地址
BOOL CDebugger::UnassemblyRead(CommandTransLate& objCmdEnter) {
	//得到地址
	LPVOID UAddr = 0;
	if (objCmdEnter.vec_ParamArr.size()==1)
	{
		UpdateRegister(hThread);
		UAddr=(LPVOID)RegContext.Eip;
		Capstone::DisAsm(hProcess, UAddr, DefaultPrintLine);//0需要修改
	}
	else if(objCmdEnter.vec_ParamArr.size() == 2)
	{
		//得到地址
		 UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
		Capstone::DisAsm(hProcess, UAddr, DefaultPrintLine);
	}
	else if (objCmdEnter.vec_ParamArr.size() == 3)
	{
	}
	return 0;
}
//写入Opcode
BOOL CDebugger::UnassemblyWrite(CommandTransLate& objCmdEnter) {
	
	LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
	// 接受生成opcode的的初始地址
	if (objCmdEnter.vec_ParamArr.size() == 2)
	{
		// 创建一个对象，用于操作汇编引擎.
		XEDPARSE xed = { 0 };
		//xed.cip = (ULONGLONG)UAddr;
		// 接收指令
		// 使用  gets_s()  函数接收整行输入，包含空格等字符
		gets_s(xed.instr, XEDPARSE_MAXBUFSIZE);
		// 使用 XEDParseAssemnle() 函数将汇编指令转换成 OPCODE
		if (XEDPARSE_OK != XEDParseAssemble(&xed))
		{
			printf("指令错误：%s\n", xed.error);
		}
		else
		{
			printf("翻译后的Opcode为：\t");
			for (int i = 0; i < xed.dest_size; i++)
			{
				printf("%x ", xed.dest[i]);
			}
		}
		//写入Opcode
		DWORD dwWrite = 0;
		WriteProcessMemory(hProcess, UAddr, xed.dest, xed.dest_size, &dwWrite);
		printf("\n写入Opcode成功\n");
		return 0;
	}
	else if (objCmdEnter.vec_ParamArr.size() == 3)
	{
		PCHAR POpcode=objCmdEnter.SetValuerCharToHex(objCmdEnter.vec_ParamArr[2]);
		//写入Opcode
		DWORD dwWrite = 0;
		WriteProcessMemory(hProcess, UAddr, POpcode, strlen(POpcode), &dwWrite);
		printf("写入Opcode成功\n");
		return 0;
	}
	printf("参数错误\n");
	return 1;
}
//模块信息
BOOL CDebugger::GetModuleInfo(DWORD Pid) {
	//用于正常输出中文的
	setlocale(LC_ALL, "chs");
	//1. 定义一些变量
	HANDLE hProcessSnapshot = 0;
	MODULEENTRY32 me = {};
	me.dwSize = sizeof(MODULEENTRY32);
	//2. 创建模块快照
	hProcessSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE,  //创建的是模块快照
		Pid            //进程ID，只有在创建模块，堆快照的时候，指定进程
	);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	//3. 获取第一个模块的信息，如果获取成功，就可以继续往后获取
	BOOL bSuccess = Module32First(
		hProcessSnapshot,//快照的句柄
		&me              //第一个模块的信息
	);
	//4. 循环遍历，所有的模块信息

	if (bSuccess == TRUE)
	{
		do
		{
			printf("模块信息：%S          %S\n", me.szModule, me.szExePath);

			/*WCHAR* p = new WCHAR[wcslen(me.szModule) + 2]{0};
			wcscpy_s(p, wcslen(me.szModule) + 2, me.szModule);*/
			vechModule.push_back(me.hModule);
		} while (Module32Next(hProcessSnapshot, &me));
	}
	return 1;
}

//模块导出表
void CDebugger::get_export_information(HANDLE hProcess, char* ObjProcessbuff) {

	DWORD dwRead = 0;
	// 先将缓冲区转换成 dos 头
	PIMAGE_DOS_HEADER dos_head_buffer{0};
	ReadProcessMemory(hProcess, (LPVOID)ObjProcessbuff, &dos_head_buffer, sizeof(PIMAGE_DOS_HEADER), &dwRead);

	// 根据 dos 头找到 nt 头
	DWORD dwOldPage = 0;
	VirtualProtectEx(hProcess, (ObjProcessbuff + dos_head_buffer->e_lfanew), sizeof(PIMAGE_NT_HEADERS),PAGE_EXECUTE_READWRITE ,&dwOldPage);
	dwRead = 0;
	PIMAGE_NT_HEADERS nt_head_buffer{ 0 };
	ReadProcessMemory(hProcess, (LPVOID)(ObjProcessbuff + dos_head_buffer->e_lfanew), &nt_head_buffer, sizeof(PIMAGE_NT_HEADERS), &dwRead);
	VirtualProtectEx(hProcess, (ObjProcessbuff + dos_head_buffer->e_lfanew), sizeof(PIMAGE_NT_HEADERS), dwOldPage, &dwOldPage);

	
	// 获取文件头
	dwRead = 0;
	PIMAGE_OPTIONAL_HEADER optional_head_buffer{ 0 };
	ReadProcessMemory(hProcess, (LPVOID)(&nt_head_buffer->OptionalHeader), &optional_head_buffer, sizeof(PIMAGE_OPTIONAL_HEADER), &dwRead);
	 
	//获得需要设置的读取大小
	DWORD dwSize=optional_head_buffer->SizeOfImage;
	
	//读取到本进程中
	dwRead = 0;
	char* buff=new char[dwSize]{0};
	ReadProcessMemory(hProcess, (LPVOID)ObjProcessbuff, buff, dwSize, &dwRead);

	PIMAGE_DOS_HEADER dos_head = (PIMAGE_DOS_HEADER)buff;
	PIMAGE_NT_HEADERS nt_head =PIMAGE_NT_HEADERS(buff + dos_head_buffer->e_lfanew);
	PIMAGE_OPTIONAL_HEADER optional_head = &nt_head->OptionalHeader;

	// 导出表在数据目录表的第 0 项
	DWORD export_rva = optional_head->DataDirectory[0].VirtualAddress;
	//DWORD export_foa = rva_to_foa(buff, export_rva);

	// 获取到导出表的数据
	PIMAGE_EXPORT_DIRECTORY export_table =
		(PIMAGE_EXPORT_DIRECTORY)(export_rva + (DWORD)buff);

	// 解析内容
	//DWORD name_foa = rva_to_foa(buff, export_table->Name);
	PCHAR name = (PCHAR)((export_table->Name)+(DWORD)buff);
	printf("导出模块的名称：%s\n", name);

	// 获取到序号的基址
	DWORD base = export_table->Base;
	// 获取到两张表的数量
	DWORD address_count = export_table->NumberOfFunctions;
	DWORD name_count = export_table->NumberOfNames;
	// 遍历三张表，获取数据，如果哪张表没有内容了代表遍历完成？
	// 【地址表】，名称表，名称序号表
	// 得到函数地址表
	DWORD func_table_rva = export_table->AddressOfFunctions;
	PDWORD func_table = PDWORD(func_table_rva + DWORD(buff));
	// 得到函数名称表
	DWORD name_table_rva = export_table->AddressOfNames;
	PDWORD name_table = PDWORD(name_table_rva + DWORD(buff));
	// 得到名称序号表// 我们可以自己实现 GetProcAddress 这个函数
	DWORD ordinal_table_rva = export_table->AddressOfNameOrdinals;
	PWORD ordinal_table = PWORD(ordinal_table_rva + DWORD(buff));

	// 开始遍历,因为地址表中的内容多，所以用他遍历
	for (int i = 0; i < address_count; i++)
	{
		if (func_table[i] == 0)
		{
			// 如果地址表的内容为 0 就是无效函数
			continue;
		}
		// 判断函数是否在名称表中，如果在就是名称导出，否则就是序号导出
		// 标志位，如果为假，就说明不在名称表中
		bool is_find = false;
		for (int j = 0; j < name_count; j++)
		{
			// i 是从 0 开始遍历，序号表也就不需要加 base 了
			// 如果地址表的索引和名称序号表的内容一致，就说明名称导出
			// printf("%d %d\n", i, ordinal_table[j]);
			if (i == ordinal_table[j])
			{
				is_find = true;
				PCHAR fun_name =
					(PCHAR)(name_table[j]+ (DWORD)buff);
				printf("函数地址: %p  函数名称: %s  名称序号: %d \n",
					func_table[i], fun_name, ordinal_table[j] + base);
				break;
			}
		}
		if (is_find == false)
		{
			printf("函数地址: %p  函数名称: NULL  函数序号 %d \n",
				func_table[i], i + base);
		}

	}

}

//模块导入表
void CDebugger::get_import_information(HANDLE hProcess,char* buff) {

	// 先将缓冲区转换成 dos 头
	PIMAGE_DOS_HEADER dos_head = (PIMAGE_DOS_HEADER)buff;
	// 根据dos头找到nt头
	PIMAGE_NT_HEADERS nt_head =
		PIMAGE_NT_HEADERS(buff + dos_head->e_lfanew);
	// 获取文件头
	PIMAGE_OPTIONAL_HEADER optional_head = &nt_head->OptionalHeader;

	// 导出表在数据目录表的第 1 项
	DWORD import_rva = optional_head->DataDirectory[1].VirtualAddress;
	if (import_rva==NULL)
	{
		printf("No import data\n"); 
		return;
	}

		// 获取到导入表的数据
	PIMAGE_IMPORT_DESCRIPTOR import_table =
		(PIMAGE_IMPORT_DESCRIPTOR)(import_rva + (DWORD)buff);

	// 0x8464 == 0x00008464 -> 最高位就是0了 0x80000000 -> 10000000000000...
	// 导入表是以 全0 结构为结尾
	while (import_table->Name != 0)
	{
		// 先获取到导入模块的名称
		//DWORD name_foa = rva_to_foa(buff, import_table->Name);
		PCHAR name = (PCHAR)(import_table->Name + (DWORD)buff);
		printf("%s \n", name);
		// 获取到导入地址表 IMAGE_THUNK_DATA
		//DWORD iat_foa = rva_to_foa(buff, import_table->FirstThunk);
		PIMAGE_THUNK_DATA iat =
			(PIMAGE_THUNK_DATA)(import_table->FirstThunk + (DWORD)buff);
		//接下来应该是在遍历某个PE模块中导入的函数，以全0结尾
		while (iat->u1.AddressOfData != 0)
		{
			BOOL is_only_ordinal = IMAGE_SNAP_BY_ORDINAL(iat->u1.Ordinal);
			if (!is_only_ordinal)
			{
				// 否则就是名称导入
				//DWORD name_table_foa =rva_to_foa(buff, iat->u1.AddressOfData);
				PIMAGE_IMPORT_BY_NAME name_table =
					(PIMAGE_IMPORT_BY_NAME)(iat->u1.AddressOfData + (DWORD)buff);

				//读取内存内容
				DWORD dwOldPage1 = 0;
				DWORD dwOldPage2 = 0;
				DWORD dwOldPage3 = 0;
				DWORD dwRead = 0;
				DWORD HintBuffer[3]={0};
				DWORD NameBuffer[1000]={0};
				VirtualProtectEx(hProcess, (LPVOID)name_table, sizeof(PIMAGE_IMPORT_BY_NAME), PAGE_EXECUTE_READWRITE, &dwOldPage1);
				VirtualProtectEx(hProcess, (LPVOID)name_table->Hint,2, PAGE_EXECUTE_READWRITE,&dwOldPage2);
				VirtualProtectEx(hProcess, (LPVOID)name_table->Name,1000, PAGE_EXECUTE_READWRITE,&dwOldPage3);
				//ReadProcessMemory(hProcess, (LPVOID)name_table->Hint, HintBuffer, 2 ,&dwRead);
				//dwRead = 0;
				//ReadProcessMemory(hProcess, (LPVOID)name_table->Name, NameBuffer, 2 ,&dwRead);
				printf("序号：%02X, 函数名 : %s \n",
					name_table->Hint,
					name_table->Name);
				VirtualProtectEx(hProcess, (LPVOID)name_table->Hint, 2, dwOldPage1, &dwOldPage1);
				VirtualProtectEx(hProcess, (LPVOID)name_table->Name, 1000, dwOldPage2, &dwOldPage2);
				VirtualProtectEx(hProcess, (LPVOID)name_table, sizeof(PIMAGE_IMPORT_BY_NAME), dwOldPage3, &dwOldPage3);
			}
			// 判断最高位是否为1，如果为1就是序号导入
			else
			{
				printf("导入序号为 %02x \n",
					iat->u1.Ordinal & 0x7FFFFFFF);
			}
			iat++;
		}
		import_table++;
	}
}