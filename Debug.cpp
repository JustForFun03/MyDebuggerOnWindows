#include<stdio.h>
#include "CDebugger.h"
#include "CDisassembly.h"


int main() {
	
	Capstone::Init();
	CDebugger ObjDebugger;
	ObjDebugger.init();
	printf("��ѡ�����ģʽ��\n1 ��������\n2 ���ӽ���\n");

	//����ѡ��
	int Mode = _getch();

	if (Mode=='1')
	{
		//����
		ObjDebugger.Open();
	}
	else if (Mode=='2')
	{
		//����
		ObjDebugger.Load();
	}

	ObjDebugger.Run();
	return 0;
}