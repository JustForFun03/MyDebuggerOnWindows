#include<stdio.h>
#include "CDebugger.h"
#include "CDisassembly.h"


int main() {
	
	Capstone::Init();
	CDebugger ObjDebugger;
	ObjDebugger.init();
	printf("请选择调试模式：\n1 启动进程\n2 附加进程\n");

	//输入选择
	int Mode = _getch();

	if (Mode=='1')
	{
		//启动
		ObjDebugger.Open();
	}
	else if (Mode=='2')
	{
		//加载
		ObjDebugger.Load();
	}

	ObjDebugger.Run();
	return 0;
}