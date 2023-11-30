#include "CommandTransLate.h"
#include<stdio.h>

CommandTransLate::CommandTransLate() {
	memset(CommandEnter, CommandLength,0);
	//std::fill(vec_ParamArr.begin(), vec_ParamArr.end(), NULL);
}

CommandTransLate::~CommandTransLate(){
	for (auto& ele:vec_ParamArr)
	{
		delete[]ele;
	}
}
DWORD CommandTransLate::DivideCmdParam()
{
	//vector<char*>vec_tempArr{};

	DWORD i = 0;
	int NotSpaceflag = 0;
	DWORD NumParam = 0;
	char* temp = new char[100] {0};
	DWORD length = strlen(CommandEnter);

	while (i< length)
	{
		if (CommandEnter[i]==' ')
		{
			label:
			if (NotSpaceflag)
			{
				NumParam++;
				//���ݷ�������Ĳ�����vector
				char* Param = new char[100] {0};
				strcpy_s(Param,100, temp);
				vec_ParamArr.push_back(Param);
				NotSpaceflag = 0;

				char buffer[100] = { 0 };
				strcpy_s(temp,100,buffer);
			}
			i++;
			continue;
		}
		else //��Ϊspace
		{
			char tempChar[2] = { 0 };
			tempChar[0] = CommandEnter[i];
			strcat_s(temp, 100, (const char*)tempChar);

			NotSpaceflag = 1;
			if (i == length - 1)
			{
				goto label;
			}
			i++;
		}
	}
	//vec_tempArr.swap(vec_ParamArr);
	delete[]temp;
	return NumParam;
}

void CommandTransLate::GetEnterStr() {
	gets_s(CommandEnter, CommandLength);
}
LPVOID CommandTransLate::AddrCharToHex(char* tempAddr) {

	//�õ���ַ
	LPVOID Addr = 0;
	sscanf_s(tempAddr, "%x", &Addr);
	return Addr;

}
void CommandTransLate::SectorStringTo8Hex(char* tempSetValue,vector<char*>& vecSector8Hex) {
	DWORD HexNumber = strlen(tempSetValue);
	DWORD ByteNum = HexNumber / 2;
	//�и�
	DWORD CountSector = 0;
	if (HexNumber % 8 == 0)
	{
		CountSector = HexNumber / 8;
	}
	else
	{
		CountSector = HexNumber / 8 + 1;
	}
	for (size_t i = 0; i < CountSector; i++)
	{
		char* SectorValue = NULL;
		int index = (HexNumber - (i + 1) * 8);
		char* SectorString = new char[9] {0};
		if (index >= 0)
		{
			for (size_t i = 0; i < 8; i++)
			{
				SectorString[i] = *((tempSetValue + index)+i);
			}
				
			vecSector8Hex.push_back(SectorString);
			//ĩβ����

		}
		else //ʣ�����һ������8Hex
		{
			for (size_t i = 0; i < 8+index; i++)
			{
				SectorString[i] = *((tempSetValue) + i);
			}
			vecSector8Hex.push_back(SectorString);
		}
	}
	return;
}
PCHAR  CommandTransLate::SetValuerCharToHex(char* tempSetValue) {
	DWORD HexNumber = strlen(tempSetValue);
	if (HexNumber%2==0)
	{
		DWORD ByteNum = HexNumber / 2;
		char* PValue = new char[ByteNum];
		//��ȡ�и���vector
		vector<char*> vec_sector;
		SectorStringTo8Hex(tempSetValue,vec_sector);
		for (size_t i = 0; i < vec_sector.size(); i++)
		{
			char* SectorValue = NULL;
			SectorValue=vec_sector[i];
			sscanf_s(SectorValue, "%x", (PCHAR)((DWORD*)PValue+i));
			
		}
		for (auto& ele:vec_sector)
		{
			delete[]ele;
		}
		return PValue;

	}
	printf("SetValue error\n");
	return NULL;
}
//PBYTE CommandTransLate::SetOpcodeCharToHex(char* tempSetOpcode) {
//	DWORD HexNumber = strlen(tempSetOpcode);
//	if (HexNumber % 2 == 0)
//	{
//		DWORD ByteNum = HexNumber / 2;
//		BYTE* PValue = new BYTE[ByteNum + 1] {0};
//		
//		for (size_t i = 0; i < ByteNum; i++)
//		{
//			sscanf_s(tempSetOpcode+i, "%x", PValue + i);
//		}
//		return PValue;
//
//	}
//	printf("SetOpcode error\n");
//	return NULL;
//}




