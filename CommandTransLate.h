#include <windows.h>
#include <sal.h>
#include <vector>
using std::vector;
#define CommandLength MAX_PATH*2

class CommandTransLate 
{
public:
	CommandTransLate();
	~CommandTransLate();
	char CommandEnter[CommandLength];
	vector<char*>vec_ParamArr;
	void GetEnterStr();
	DWORD DivideCmdParam();
	void  SectorStringTo8Hex(char* tempAddr, vector<char*>&);
	LPVOID AddrCharToHex(char* tempAddr);
	PCHAR SetValuerCharToHex(char* tempSetValue);
	//PBYTE SetOpcodeCharToHex(char* tempSetOpcode);
	//BOOL EditDebugInfo(const char*pUserCommand);
};