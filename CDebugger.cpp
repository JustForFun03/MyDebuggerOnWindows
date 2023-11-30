
#include "CDebugger.h"
#include "CDisassembly.h"

#include <stdio.h>

#include <TlHelp32.h> //���ڱ����ļ�
#include <tchar.h>
//#include<processthreadsapi.h>
#include <iostream>  //���ڿ���̨��ӡ����
#include <atlstr.h> //����CString
#include "XEDParse.h" //���������������
#pragma comment(lib,"XEDParse.lib")

#define PlugInBasePath L"D:\\Files_and_doc\\visual_studio2017\\Debugger"
#define testExe L"D:\\Files_and_doc\\visual_studio2017\\Debugger\\Debugger\\111.exe"
#define DefaultPrintLine 20

typedef  void (*PlugInFun)(HANDLE);
void FilePathCollection(const WCHAR* BasePath, vector<WCHAR*>& vec_FilePath) {

	//��ȡ�����ļ����������ļ�·����Ϣ

	WIN32_FIND_DATA  wfd = {};
	//setlocale(LC_ALL, "CHS"); // �����ַ������ʽ
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
					//��ѡdll�ļ�����
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
	//��ò��·���б�
	vector<WCHAR*>vecPluginDll;
	FilePathCollection(PlugInBasePath, vecPluginDll);

	//���ز��dll
	for (auto& ele:vecPluginDll)
	{
		LoadLibrary(ele);
	}

	//���ز��dll
	for (auto& ele : vecPluginDll)
	{
		delete []ele;
	}
	printf("�Ƿ��������ԣ�1���� 0������:");
	
	AntiDebug = _getch();;
	return 0;
}
//
//CDebugger::~CDebugger() {
//}
BOOL CDebugger::Open() {

	HWND hConsoleWnd = FindWindow(L"ConsoleWindowClass", NULL);
	WCHAR FilePathName[MAX_PATH*2]{};
	
	//��ȡ�ļ�·����
	OPENFILENAME file = { 0 };
	file.hwndOwner = hConsoleWnd;
	file.lStructSize = sizeof(file);
	file.lpstrFilter = L"�����ļ�(*.*)\0*.*\0Exe�ļ�(*.exe)\0*.exe\0\0";//Ҫѡ����ļ���׺ 
	file.lpstrInitialDir = L"";//Ĭ�ϵ��ļ�·�� 
	file.lpstrFile = FilePathName;//����ļ����ƵĻ����� 
	file.nMaxFile = _countof(FilePathName);
	file.nFilterIndex = 0;
	file.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;//��־����Ƕ�ѡҪ����OFN_ALLOWMULTISELECT
	BOOL bSel = GetOpenFileName(&file);
	CString filePath = file.lpstrFile;
	
	STARTUPINFO si{};         //������Ϣ�ṹ��
	PROCESS_INFORMATION pi{}; //������Ϣ�ṹ��
	si.cb = sizeof(STARTUPINFO);  //��ʼ��������Ϣ�ṹ���С
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
	
	printf("������pid\n");
	//����ԱȨ��
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
	//�����¼�ѭ��
	ObjDebugEcvent = { 0 };
	while (true)
	{
		WaitForDebugEvent(&ObjDebugEcvent,INFINITE);
		//�򿪾��
		openHandle();

		DWORD dwRet = DisPatchEvent(&ObjDebugEcvent);//����ڶ���ַ��쳣
		//ָʾ����Ŀ�����
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

	//���ݵ����¼����ͷ��ز�ͬ�Ĵ����ź�
	switch (pDbgEvent->dwDebugEventCode)
	{
	case EXCEPTION_DEBUG_EVENT:
	{
		dwRet = DisPatchException(pDbgEvent);//���������ַ��쳣
		return dwRet;
	}
		break;
	case CREATE_PROCESS_DEBUG_EVENT: //ϵͳ�����ж��¼����ڴ�����OEP�ϵ�
	{
		//����OEP����ϵ�
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
	//�������쳣�ַ��ĵ����㣬��Ҫ�����쳣
	auto DbgInfo = pDbgEvent->u.Exception.ExceptionRecord;
	auto ExceptionCode = DbgInfo.ExceptionCode;
	auto ExceptionAddr = DbgInfo.ExceptionAddress;
	
	UpdateRegister(hThread);
	switch (ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT://����ϵ�
	{
		if (IsSysInt==1)
		{
			IsSysInt = 0;
			//����OEP����ϵ�
			SetInt3BreakPoint(hProcess, OEP,1);
			printf("ϵͳ�ж��쳣\n");
			if (AntiDebug=='1')//����������
			{
				//��������
				HMODULE hModule = GetModuleHandle(L"AntiDebug1.dll");
				if (hModule == nullptr)
				{
					printf("Error\n");
				}
				//���÷������Բ������
				PlugInFun pPlugInFun = (PlugInFun)GetProcAddress(hModule, "AntiAntiDebugByBeingDebugged");
				pPlugInFun(hProcess);
				printf("�������������\n");
			}
			
		}//����һ������ϵ�
		else //��ϵͳ�ϵ�
		{
			//ջ�ͼĴ�������
			if (ExceptionAddr == OEP) //��ʼ��
			{
				//��ʼ��ջ��
				UpdateStack(1);
			}
			else
			{
				UpdateStack();
			}

			//�޸�Eip
			RegContext.Eip -= 1;
			SetThreadContext(hThread, &RegContext);

			//�޸�CC��
			int Ret = FixInt3BreakPoint(hProcess, hThread, (LPVOID)ExceptionAddr);
			if (Ret)//һ���Զϵ�
			{
				printf("һ���Զϵ��쳣\n");
			}
			else //���öϵ�
			{
				printf("�����Զϵ��쳣\n");
				Int3TriggerTF = 1;//���ô���TF��־λ

				//����TF
				//�ȱ���֮ǰ��TF
				CONTEXT context{ CONTEXT_ALL };
				GetThreadContext(hThread, &context);
				PreviousTF = ((context.EFlags >>= 0x8) &= 0x00000001);
				SetTfBreakPoint(hThread);

				Int3Infinite = ExceptionAddr;
				printf("������������\n");

				if (/*StcConditionBp.flag == 1 &&*/ StcConditionBp.BpAddr == ExceptionAddr)//�����ϵ�����
				{
					if (StcConditionBp.BpValue != RegContext.Eax)//����������
					{
						return DBG_CONTINUE;
					}
					//StcConditionBp.flag = 0;
				}
			}
		}
		
	}
	break;
	case EXCEPTION_SINGLE_STEP://Ӳ���ϵ��TF�ϵ�
	{
		//�����Ǳ��������쳣
		if (Int3TriggerTF) //INT3������TF
		{
			//����CC
			SetInt3BreakPoint(hProcess, Int3Infinite, 2);
			Int3TriggerTF = 0;

			//����Ҳ��������previousTF�Ƿ����1���ж�
			if (UserSetTF ==1) //�û������˵�������
			{

			}
			else //�û�û�����õ�������
			{
				return DBG_CONTINUE;
			}

		}
		else if (StepOverSetTF) //stepover����
		{
			StepOverSetTF = 0;
			//����һ���Զϵ�
			UpdateStack();

			LPVOID UAddr = (LPVOID)Stack.Current_Esp;
			//��ȡ�ڴ�����
			DWORD dwRead = 0;
			char Esp[5] = { 0 };
			ReadProcessMemory(hProcess, (LPVOID)UAddr, Esp, 4, &dwRead);


			SetInt3BreakPoint(hProcess, (LPVOID)(*(DWORD*)Esp), 1);
			//UserSetTF = 0;
			return DBG_CONTINUE;
		}
		else if (HardBpTriggerTF) //Ӳ���ϵ㴥����������
		{
			HardBpTriggerTF = 0;

			//����HardBp
			SetHwBreakPoint(hThread,bpInfo.previousAddr ,bpInfo.type ,bpInfo.len);
			//����Ҳ��������previousTF�Ƿ����1���ж�
			if (UserSetTF ==1) //�û������˵�������
			{

			}
			else //�û�û�����õ�������
			{
				return DBG_CONTINUE;
			}
		}
		else if (MemBpTriggerTF)//�ڴ�ϵ㴥����������
		{
			MemBpTriggerTF = 0;
			//�ٴ����÷�ҳ����,ʹ��record�ṹ��
			SetMmBreakPoint(hProcess,RecordMemBpInfo.MemAddrToReset,RecordMemBpInfo.TypeToReset);
			if (UserSetTF == 1) //�û������˵�������
			{
			}
			else //�û�û�����õ�������
			{
				return DBG_CONTINUE;
			}
		}

		if (UserSetTF ==1)//�û����õ�TF�쳣
		{
			UserSetTF = 0;
		}
		else if(FixHwBreakPoint(hThread, ExceptionAddr)>=0)//Ӳ���ϵ�
		{
			//�޸�Ӳ���ϵ�
			//����ִ�кͶ�д,�޸�Eip
			//PR7 Dr7 = (PR7)&RegContext.Dr7;
			//BOOL IsHpExe = 
			//if (!IsHpExe)//����Ӳ���ϵ���Ҫ�޸�Eip,����ָ����һ��ָ���ַ
			//{
			//	//�޸�Eip
			//	RegContext.Eip =-1;
			//	SetThreadContext(hThread, &RegContext);
			//}
			//����TF
			//�ȱ���֮ǰ��TF
			CONTEXT context{CONTEXT_ALL};
			GetThreadContext(hThread,&context);
			PreviousTF=((context.EFlags>>=0x8)&=0x00000001);
			SetTfBreakPoint(hThread);
			HardBpTriggerTF = 1;
		}
	}
	break;
	case EXCEPTION_ACCESS_VIOLATION://���ʶϵ�
	{
		auto ExceptionType = DbgInfo.ExceptionInformation[0];//�����ڴ�ϵ�����
		auto ExceptionMemAddr = DbgInfo.ExceptionInformation[1];//�����ڴ�ϵ��ַ
		//�ָ�ҳ������
		FixMmBreakPoint(hProcess,hThread, (LPVOID)ExceptionMemAddr, ExceptionType);//ע������ָ���ַ���ڴ��ַ
		MemBpTriggerTF = 1;

		//�ж��ǲ����������õĵ�ַ������
		if ((LPVOID)ExceptionMemAddr==UserSetMemInfo.UserSetMemAddr
			&& ExceptionType== UserSetMemInfo.UserSetType
			)//�ǵĻ� ���ض���ʾ���
		{
		}
		else //���ǣ�ֱ������
		{
			return DBG_CONTINUE;
		}
	}
	break;
	default://�����쳣���������������Գ�������쳣�������
		return DBG_EXCEPTION_NOT_HANDLED;
		break;
	}

	//�������ʾ��Ĭ��20��
	Capstone::DisAsm(hProcess,  ExceptionAddr, DefaultPrintLine);
	//�û�����
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
		//�õ��û�����
		objCmdEnter.GetEnterStr();
		//�����и�
		DWORD NumParam = objCmdEnter.DivideCmdParam();
		if (!NumParam)
		{
			printf("Input is not valid\n");
		}
		else
		{
			//ִ������
			//�ض������������û�������ѭ�����ָ�Ŀ������
			if (OperateDebugInfo(objCmdEnter))
			{
				break;
			}
			//ԭ��ȡ���ϵ�
			auto ExceptionAddr= ObjDebugEcvent.u.Exception.ExceptionRecord.ExceptionAddress;
			int CheckIsOnceInt3 = GetVectorIndex(ExceptionAddr);
			if ((CheckIsOnceInt3 == -1) && Int3TriggerTF) //�Ѿ������öϵ���ɾ��������TF����������CC
			{
				Int3TriggerTF = 0;//����TF��־λ
				//�ָ�ԭ����TF
				FixTfBreakPoint(hThread);
				//�޸�ԭ�ȵ�
				printf("ȡ��������������\n");
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
//		case 't'://��������
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

//�û�����
BOOL CDebugger::OperateDebugInfo(CommandTransLate& objCmdEnter) {

	char* CmdType = objCmdEnter.vec_ParamArr[0];
	switch (CmdType[0])
	{
	case 'u'://�����
	{
		UnassemblyRead(objCmdEnter);
	}
	break;
	case 'a'://�༭���
	{
		UnassemblyWrite(objCmdEnter);
	}
	break;
	case 'd'://�ڴ�
	{
		switch (CmdType[1])
		{
		case 'd'://dd
		{
			if (objCmdEnter.vec_ParamArr.size() == 2) //Ĭ������80 ֻ֧�ֵ�ַ
			{
				LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);

				//��ȡ�ڴ�����
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
			else if (objCmdEnter.vec_ParamArr.size() == 3)//�Զ�������
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
	case 'e'://�޸��ڴ�
	{
		if (objCmdEnter.vec_ParamArr.size() == 3) //Ĭ�� e ��ַ  value 
		{

			LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
			DWORD HexNUmber=strlen(objCmdEnter.vec_ParamArr[2]);
			DWORD ByteNUmber = HexNUmber/2;

			LPVOID SetValue = objCmdEnter.SetValuerCharToHex(objCmdEnter.vec_ParamArr[2]);
			//д���ڴ�����
			DWORD dwWrite = 0;
			//BYTE MemBuffer[80*4]{ 0 };

			//memcpy(MemBuffer, (char*)SetValue, ByteNUmber);
			WriteProcessMemory(hProcess, UAddr, SetValue, ByteNUmber, &dwWrite);
			//WriteProcessMemory(hProcess, UAddr, MemBuffer, ByteNUmber, &dwWrite);
			printf("Write Mem sucess\n");
		}
	}
	break;
	case 'r'://�Ĵ���
	{
		UpdateRegister(hThread);
		if (objCmdEnter.vec_ParamArr.size() == 1) //�鿴���мĴ���
		{
			
			printf("Eax = %08x\tEax = %08x\n",RegContext.Eax, RegContext.Ebx);
			printf("Ecx = %08x\tEdx = %08x\n",RegContext.Ecx, RegContext.Edx);
			printf("Esp = %08x\tEbp = %08x\n",RegContext.Esp, RegContext.Ebp);
			printf("Esi = %08x\tEdi = %08x\n",RegContext.Esi, RegContext.Edi);
			printf("Eip = %08x\tEfg = %08x\n",RegContext.Eip, RegContext.EFlags);
		}
		else if (objCmdEnter.vec_ParamArr.size() == 2) //�鿴�ض��Ĵ���
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
		else if (objCmdEnter.vec_ParamArr.size() == 3)//�޸ļĴ���  ֻ֧���޸�һ��
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
	case 'k'://�鿴��ջ
	{
		//OEP->��ǰEsp
		UpdateStack(); 

		DWORD Startk = Stack.OEP_Esp;
		DWORD Cunrentk = Stack.Current_Esp;
		size_t length = (Startk- Cunrentk) / 4+1;

		//��ȡ�ڴ�����
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
	case 'm'://�鿴ģ����Ϣ
	{
		if (objCmdEnter.vec_ParamArr.size() == 1)
		{
			GetModuleInfo(GetProcessId(hProcess));
		}
		else if (objCmdEnter.vec_ParamArr.size() == 3)
		{
			//��ö�Ӧģ��
			LPVOID VecModuleIndex = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
			HMODULE hModule= vechModule[(DWORD)VecModuleIndex];//�ض���ģ�����������ػ�ַ
			
			//��� ���뻹�ǵ���
			LPVOID IsImport = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[2]);


			if (IsImport ==0)
			{
				//������
				//get_export_information(hProcess,(char*)hModule);
			}
			else
			{
				//�����
				//get_import_information(hProcess,(char*)hModule);
			}
			
		}
		
	}
	break;
	case 'b'://�ϵ�����
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
			else if (objCmdEnter.vec_ParamArr.size() == 1)//��ǰ�¶ϵ�
			{
				//SetInt3BreakPoint(hProcess, );
			}
			else if (objCmdEnter.vec_ParamArr.size() == 3)//�����ϵ� ֻ֧��eax
			{
				LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
				LPVOID BpValue = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[2]);//�������16����				StcConditionBp.BpAddr = UAddr; 
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
			if (objCmdEnter.vec_ParamArr.size() == 2) //bc + vector ����
			{
				LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
				//�޸�ɾ���ϵ��CC
				FixInt3BreakPoint(hProcess, hThread, vecInt3[(DWORD)UAddr].BpAddr);
				vecInt3.erase(vecInt3.begin()+ (DWORD)UAddr);
				printf("ɾ������ϵ�ɹ�\n");

			}
			else
			{
				printf("bc Error\n");
			}
		}
		break;
		case 'l'://bl ��ʾ�ϵ��б�
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
				printf("�ϵ��б�Ϊ��");
			}
			printf("\n");
		}
		break;
		case 'h'://bhӲ���ϵ�
		{
			if (objCmdEnter.vec_ParamArr.size() == 4) //bh + ��ַ + type +Len
			{
				//�õ���ַ
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
				printf("����Ӳ���ϵ�ɹ�\n");

			}
			else
			{
				printf("bh Error\n");
			}
		}
		break;
		case 'm'://bmӲ���ϵ�
		{
			if (objCmdEnter.vec_ParamArr.size() == 3) //bm + ��ַ + type 
			{
				//�õ���ַ
				LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
				int Type = (int)objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[2]);
				
				UserSetMemInfo.UserSetMemAddr=UAddr;
				UserSetMemInfo.UserSetType=Type;
				SetMmBreakPoint(hProcess, UAddr,Type);
				UserSetMemInfo.dwUserOldProtected=RecordMemBpInfo.dwOldProtected;
				printf("�����ڴ�ϵ�ɹ�\n");

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
	//ִ�����
	case 'g': //ֱ������  ��������ַ  g 0x12345678
	{
		if (objCmdEnter.vec_ParamArr.size() == 1) //
		{
		}
		else if (objCmdEnter.vec_ParamArr.size() == 2) //���е�ĳ��ͣ��
		{
			LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
			SetInt3BreakPoint(hProcess, UAddr,1);
		}
		else if (objCmdEnter.vec_ParamArr.size() == 2)//����
		{
			printf("g Error\n");
		}
		return 1;
	}
	case 'p'://��������
	{
		//��ȡ��ǰָ����׸�Opcode
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
		//����TF
		SetTfBreakPoint(hThread);
		UserSetTF = 1;
		if (Flag)//�ض���Opcode 
		{
			StepOverSetTF = 1;
		}
		else //����
		{

		}
		return 1;
	}
	case 't'://��������
	{
		//����ɿ������ò��������� t 10
		SetTfBreakPoint(hThread);
		UserSetTF = 1;
		return 1;
	}
	break;
	default:
		printf("Command Error\n");	//�Ǳ�׼��������
		break;
	}
	return 0;
}
//u+��ַ
BOOL CDebugger::UnassemblyRead(CommandTransLate& objCmdEnter) {
	//�õ���ַ
	LPVOID UAddr = 0;
	if (objCmdEnter.vec_ParamArr.size()==1)
	{
		UpdateRegister(hThread);
		UAddr=(LPVOID)RegContext.Eip;
		Capstone::DisAsm(hProcess, UAddr, DefaultPrintLine);//0��Ҫ�޸�
	}
	else if(objCmdEnter.vec_ParamArr.size() == 2)
	{
		//�õ���ַ
		 UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
		Capstone::DisAsm(hProcess, UAddr, DefaultPrintLine);
	}
	else if (objCmdEnter.vec_ParamArr.size() == 3)
	{
	}
	return 0;
}
//д��Opcode
BOOL CDebugger::UnassemblyWrite(CommandTransLate& objCmdEnter) {
	
	LPVOID UAddr = objCmdEnter.AddrCharToHex(objCmdEnter.vec_ParamArr[1]);
	// ��������opcode�ĵĳ�ʼ��ַ
	if (objCmdEnter.vec_ParamArr.size() == 2)
	{
		// ����һ���������ڲ����������.
		XEDPARSE xed = { 0 };
		//xed.cip = (ULONGLONG)UAddr;
		// ����ָ��
		// ʹ��  gets_s()  ���������������룬�����ո���ַ�
		gets_s(xed.instr, XEDPARSE_MAXBUFSIZE);
		// ʹ�� XEDParseAssemnle() ���������ָ��ת���� OPCODE
		if (XEDPARSE_OK != XEDParseAssemble(&xed))
		{
			printf("ָ�����%s\n", xed.error);
		}
		else
		{
			printf("������OpcodeΪ��\t");
			for (int i = 0; i < xed.dest_size; i++)
			{
				printf("%x ", xed.dest[i]);
			}
		}
		//д��Opcode
		DWORD dwWrite = 0;
		WriteProcessMemory(hProcess, UAddr, xed.dest, xed.dest_size, &dwWrite);
		printf("\nд��Opcode�ɹ�\n");
		return 0;
	}
	else if (objCmdEnter.vec_ParamArr.size() == 3)
	{
		PCHAR POpcode=objCmdEnter.SetValuerCharToHex(objCmdEnter.vec_ParamArr[2]);
		//д��Opcode
		DWORD dwWrite = 0;
		WriteProcessMemory(hProcess, UAddr, POpcode, strlen(POpcode), &dwWrite);
		printf("д��Opcode�ɹ�\n");
		return 0;
	}
	printf("��������\n");
	return 1;
}
//ģ����Ϣ
BOOL CDebugger::GetModuleInfo(DWORD Pid) {
	//��������������ĵ�
	setlocale(LC_ALL, "chs");
	//1. ����һЩ����
	HANDLE hProcessSnapshot = 0;
	MODULEENTRY32 me = {};
	me.dwSize = sizeof(MODULEENTRY32);
	//2. ����ģ�����
	hProcessSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE,  //��������ģ�����
		Pid            //����ID��ֻ���ڴ���ģ�飬�ѿ��յ�ʱ��ָ������
	);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	//3. ��ȡ��һ��ģ�����Ϣ�������ȡ�ɹ����Ϳ��Լ��������ȡ
	BOOL bSuccess = Module32First(
		hProcessSnapshot,//���յľ��
		&me              //��һ��ģ�����Ϣ
	);
	//4. ѭ�����������е�ģ����Ϣ

	if (bSuccess == TRUE)
	{
		do
		{
			printf("ģ����Ϣ��%S          %S\n", me.szModule, me.szExePath);

			/*WCHAR* p = new WCHAR[wcslen(me.szModule) + 2]{0};
			wcscpy_s(p, wcslen(me.szModule) + 2, me.szModule);*/
			vechModule.push_back(me.hModule);
		} while (Module32Next(hProcessSnapshot, &me));
	}
	return 1;
}

//ģ�鵼����
void CDebugger::get_export_information(HANDLE hProcess, char* ObjProcessbuff) {

	DWORD dwRead = 0;
	// �Ƚ�������ת���� dos ͷ
	PIMAGE_DOS_HEADER dos_head_buffer{0};
	ReadProcessMemory(hProcess, (LPVOID)ObjProcessbuff, &dos_head_buffer, sizeof(PIMAGE_DOS_HEADER), &dwRead);

	// ���� dos ͷ�ҵ� nt ͷ
	DWORD dwOldPage = 0;
	VirtualProtectEx(hProcess, (ObjProcessbuff + dos_head_buffer->e_lfanew), sizeof(PIMAGE_NT_HEADERS),PAGE_EXECUTE_READWRITE ,&dwOldPage);
	dwRead = 0;
	PIMAGE_NT_HEADERS nt_head_buffer{ 0 };
	ReadProcessMemory(hProcess, (LPVOID)(ObjProcessbuff + dos_head_buffer->e_lfanew), &nt_head_buffer, sizeof(PIMAGE_NT_HEADERS), &dwRead);
	VirtualProtectEx(hProcess, (ObjProcessbuff + dos_head_buffer->e_lfanew), sizeof(PIMAGE_NT_HEADERS), dwOldPage, &dwOldPage);

	
	// ��ȡ�ļ�ͷ
	dwRead = 0;
	PIMAGE_OPTIONAL_HEADER optional_head_buffer{ 0 };
	ReadProcessMemory(hProcess, (LPVOID)(&nt_head_buffer->OptionalHeader), &optional_head_buffer, sizeof(PIMAGE_OPTIONAL_HEADER), &dwRead);
	 
	//�����Ҫ���õĶ�ȡ��С
	DWORD dwSize=optional_head_buffer->SizeOfImage;
	
	//��ȡ����������
	dwRead = 0;
	char* buff=new char[dwSize]{0};
	ReadProcessMemory(hProcess, (LPVOID)ObjProcessbuff, buff, dwSize, &dwRead);

	PIMAGE_DOS_HEADER dos_head = (PIMAGE_DOS_HEADER)buff;
	PIMAGE_NT_HEADERS nt_head =PIMAGE_NT_HEADERS(buff + dos_head_buffer->e_lfanew);
	PIMAGE_OPTIONAL_HEADER optional_head = &nt_head->OptionalHeader;

	// ������������Ŀ¼��ĵ� 0 ��
	DWORD export_rva = optional_head->DataDirectory[0].VirtualAddress;
	//DWORD export_foa = rva_to_foa(buff, export_rva);

	// ��ȡ�������������
	PIMAGE_EXPORT_DIRECTORY export_table =
		(PIMAGE_EXPORT_DIRECTORY)(export_rva + (DWORD)buff);

	// ��������
	//DWORD name_foa = rva_to_foa(buff, export_table->Name);
	PCHAR name = (PCHAR)((export_table->Name)+(DWORD)buff);
	printf("����ģ������ƣ�%s\n", name);

	// ��ȡ����ŵĻ�ַ
	DWORD base = export_table->Base;
	// ��ȡ�����ű������
	DWORD address_count = export_table->NumberOfFunctions;
	DWORD name_count = export_table->NumberOfNames;
	// �������ű���ȡ���ݣ�������ű�û�������˴��������ɣ�
	// ����ַ�������Ʊ�������ű�
	// �õ�������ַ��
	DWORD func_table_rva = export_table->AddressOfFunctions;
	PDWORD func_table = PDWORD(func_table_rva + DWORD(buff));
	// �õ��������Ʊ�
	DWORD name_table_rva = export_table->AddressOfNames;
	PDWORD name_table = PDWORD(name_table_rva + DWORD(buff));
	// �õ�������ű�// ���ǿ����Լ�ʵ�� GetProcAddress �������
	DWORD ordinal_table_rva = export_table->AddressOfNameOrdinals;
	PWORD ordinal_table = PWORD(ordinal_table_rva + DWORD(buff));

	// ��ʼ����,��Ϊ��ַ���е����ݶ࣬������������
	for (int i = 0; i < address_count; i++)
	{
		if (func_table[i] == 0)
		{
			// �����ַ�������Ϊ 0 ������Ч����
			continue;
		}
		// �жϺ����Ƿ������Ʊ��У�����ھ������Ƶ��������������ŵ���
		// ��־λ�����Ϊ�٣���˵���������Ʊ���
		bool is_find = false;
		for (int j = 0; j < name_count; j++)
		{
			// i �Ǵ� 0 ��ʼ��������ű�Ҳ�Ͳ���Ҫ�� base ��
			// �����ַ���������������ű������һ�£���˵�����Ƶ���
			// printf("%d %d\n", i, ordinal_table[j]);
			if (i == ordinal_table[j])
			{
				is_find = true;
				PCHAR fun_name =
					(PCHAR)(name_table[j]+ (DWORD)buff);
				printf("������ַ: %p  ��������: %s  �������: %d \n",
					func_table[i], fun_name, ordinal_table[j] + base);
				break;
			}
		}
		if (is_find == false)
		{
			printf("������ַ: %p  ��������: NULL  ������� %d \n",
				func_table[i], i + base);
		}

	}

}

//ģ�鵼���
void CDebugger::get_import_information(HANDLE hProcess,char* buff) {

	// �Ƚ�������ת���� dos ͷ
	PIMAGE_DOS_HEADER dos_head = (PIMAGE_DOS_HEADER)buff;
	// ����dosͷ�ҵ�ntͷ
	PIMAGE_NT_HEADERS nt_head =
		PIMAGE_NT_HEADERS(buff + dos_head->e_lfanew);
	// ��ȡ�ļ�ͷ
	PIMAGE_OPTIONAL_HEADER optional_head = &nt_head->OptionalHeader;

	// ������������Ŀ¼��ĵ� 1 ��
	DWORD import_rva = optional_head->DataDirectory[1].VirtualAddress;
	if (import_rva==NULL)
	{
		printf("No import data\n"); 
		return;
	}

		// ��ȡ������������
	PIMAGE_IMPORT_DESCRIPTOR import_table =
		(PIMAGE_IMPORT_DESCRIPTOR)(import_rva + (DWORD)buff);

	// 0x8464 == 0x00008464 -> ���λ����0�� 0x80000000 -> 10000000000000...
	// ��������� ȫ0 �ṹΪ��β
	while (import_table->Name != 0)
	{
		// �Ȼ�ȡ������ģ�������
		//DWORD name_foa = rva_to_foa(buff, import_table->Name);
		PCHAR name = (PCHAR)(import_table->Name + (DWORD)buff);
		printf("%s \n", name);
		// ��ȡ�������ַ�� IMAGE_THUNK_DATA
		//DWORD iat_foa = rva_to_foa(buff, import_table->FirstThunk);
		PIMAGE_THUNK_DATA iat =
			(PIMAGE_THUNK_DATA)(import_table->FirstThunk + (DWORD)buff);
		//������Ӧ�����ڱ���ĳ��PEģ���е���ĺ�������ȫ0��β
		while (iat->u1.AddressOfData != 0)
		{
			BOOL is_only_ordinal = IMAGE_SNAP_BY_ORDINAL(iat->u1.Ordinal);
			if (!is_only_ordinal)
			{
				// ����������Ƶ���
				//DWORD name_table_foa =rva_to_foa(buff, iat->u1.AddressOfData);
				PIMAGE_IMPORT_BY_NAME name_table =
					(PIMAGE_IMPORT_BY_NAME)(iat->u1.AddressOfData + (DWORD)buff);

				//��ȡ�ڴ�����
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
				printf("��ţ�%02X, ������ : %s \n",
					name_table->Hint,
					name_table->Name);
				VirtualProtectEx(hProcess, (LPVOID)name_table->Hint, 2, dwOldPage1, &dwOldPage1);
				VirtualProtectEx(hProcess, (LPVOID)name_table->Name, 1000, dwOldPage2, &dwOldPage2);
				VirtualProtectEx(hProcess, (LPVOID)name_table, sizeof(PIMAGE_IMPORT_BY_NAME), dwOldPage3, &dwOldPage3);
			}
			// �ж����λ�Ƿ�Ϊ1�����Ϊ1������ŵ���
			else
			{
				printf("�������Ϊ %02x \n",
					iat->u1.Ordinal & 0x7FFFFFFF);
			}
			iat++;
		}
		import_table++;
	}
}