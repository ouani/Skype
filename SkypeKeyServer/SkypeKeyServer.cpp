/*  
*
* SkypeKeyServer : Skype RC4 Seed To Key Server (Code injected in Skype Client)
* Part of FakeSkype : Skype reverse engineering proof-of-concept client
*
* Ouanilo MEDEGAN (c) 2006
* http://www.oklabs.net
*
* Feel free to modifiy, update or redistribute (Quotation appreciated ;))
*
*/

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define	 RC4_KLEN		88

HANDLE	 hProcess = 0;
LPVOID   RemoteAddr, KeyAddr;
int	     Size;

void	__declspec(naked) InjectedCode()
{
__asm
	{
		jmp BeginOCode
//KeyAddr:
		INT 3
		INT 3
		INT 3
		INT 3
KeyAddrGet:
		_emit 0xE8
		_emit 0x00
		_emit 0x00
		_emit 0x00
		_emit 0x00
		pop eax
		sub eax, 0x09
		mov eax, dword ptr [eax]
		ret
//Seed:
		INT 3
		INT 3
		INT 3
		INT 3
SeedGet:
		_emit 0xE8
		_emit 0x00
		_emit 0x00
		_emit 0x00
		_emit 0x00
		pop eax
		sub eax, 0x09
		mov eax, dword ptr [eax]
		ret
BeginOCode:
		call KeyAddrGet
		mov ecx, eax
		call SeedGet
		mov edx, eax
		mov eax, 0x0075D470
		call eax
		//mov eax, 0x7C80C058 //ON COMMON MACHINE : ExitThread Address
		//mov eax, 0x77E54A8F //ON "NEUF" MACHINE
		mov eax, 0x401304
		call eax

		DEC ECX		//I
		DEC ESI		//N
		DEC EDX		//J
		INC EBP		//E
		INC EBX		//C
		PUSH ESP	//T
		DEC ECX		//I
		DEC EDI		//O
		DEC ESI		//N
		POP EDI		//_
		INC EBP		//E
		DEC ESI		//N
		INC ESP		//D
	}
}

int				SizeOfCode()
{
	int			Size;
	char		*Proc;
	char		Buffer[14] = {0};

	Size = 0;
	Proc = (char *)InjectedCode;
	do
	{
		memcpy(Buffer, Proc, 13);
        Size++;
        Proc++;
	}
    while (strcmp(Buffer, "INJECTION_END"));
    return (Size - 1);
}

DWORD				GetSkypeProcessHandle()
{
	HANDLE			hProcessSnap;
	PROCESSENTRY32	PE32;
	DWORD			SkypeProcess;

	SkypeProcess = -1;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("Error : CreateToolhelp32Snapshot (of processes) failed..\n");
		return (-1);
	}
	PE32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &PE32))
	{
		printf("Error : Process32First failed..\n" );
		CloseHandle(hProcessSnap);
		return (-1);
	}
	do
	{
		if (strcmp("Skype.exe", PE32.szExeFile) == 0)
		{
			SkypeProcess = PE32.th32ProcessID;
			break;
		}
	}
	while (Process32Next(hProcessSnap, &PE32));

	CloseHandle(hProcessSnap);
	return (SkypeProcess);
}

int						Seed2Key(unsigned char *Key, unsigned int seed)
{
	/* FIXME */
	/* For the moment based on Skype.exe process in memory. Pick the proc Appart !*/
	DWORD				NbWritten, ThID;
	HANDLE				hThread;
	unsigned char		*CodeBuffer;

	if (!WriteProcessMemory(hProcess, KeyAddr, (LPCVOID)Key, RC4_KLEN, (SIZE_T *)&NbWritten))
	{
		printf("Skype Process WriteProcessMemory (Key) failed.. Aborting..\n");
		return (0);
	}	
	
	CodeBuffer = (unsigned char *)malloc(Size);
	memcpy(CodeBuffer, (void *)InjectedCode, Size);
	memcpy(CodeBuffer + 2, (void *)&KeyAddr, 4);
	memcpy(CodeBuffer + 18, (void *)&seed, 4);
	
	if (!WriteProcessMemory(hProcess, RemoteAddr, (LPCVOID)CodeBuffer, Size, (SIZE_T *)&NbWritten))
	{
		printf("Skype Process WriteProcessMemory (Code) failed.. Aborting..\n");
		return (0);
	}
	
	free(CodeBuffer);

	hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)RemoteAddr, NULL, NULL, (LPDWORD)&ThID);
	if (!hThread)
	{
		printf("Skype Process CreateRemoteThread failed.. Aborting..\n");
		return (0);
	}

	WaitForSingleObject(hThread, INFINITE);

	if (!ReadProcessMemory(hProcess, KeyAddr, (LPVOID)Key, RC4_KLEN, (SIZE_T *)&NbWritten))
	{
		printf("Skype Process ReadProcessMemory (Key) failed.. Aborting..\n");
		return (0);
	}
	
	return (1);
}

int		InitProc()
{
	STARTUPINFO Si;
	PROCESS_INFORMATION Pi; 

	ZeroMemory(&Si, sizeof(Si));
	ZeroMemory(&Pi, sizeof(Pi));
	Si.cb = sizeof(Si);
	//CREATE_SUSPENDED
	
	/*if(!CreateProcessA("SkypeKeyServer.exe", "SkypeKeyServer.exe", NULL, NULL, FALSE, NULL, NULL, NULL, (LPSTARTUPINFOA)&Si, &Pi))
	{
		printf("Error creating process..\n");
		return (0);
	}

	hProcess = Pi.hProcess;*/

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetSkypeProcessHandle());

	if (!hProcess)
	{
		printf("Failed Opening process..\n");
		return (0);
	}

	KeyAddr = VirtualAllocEx(hProcess, NULL, RC4_KLEN, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!KeyAddr)
	{
		printf("Skype Process VirtualAllocEx (Key) failed.. Aborting..\n");
		return (0);
	}
	
	Size = SizeOfCode();
	RemoteAddr = VirtualAllocEx(hProcess, NULL, Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!RemoteAddr)
	{
		printf("Skype Process VirtualAllocEx (Code) failed.. Aborting..\n");
		return (0);
	}

	return (1);
}

void	EndProc()
{
	VirtualFreeEx(hProcess, KeyAddr, 0, MEM_RELEASE);
	VirtualFreeEx(hProcess, RemoteAddr, 0, MEM_RELEASE);

	CloseHandle(hProcess);
}

int main(int argc, char* argv[])
{
	WORD	wVersionRequested;
	WSADATA wsaData;
	int		err, SelRes, Res, CbSz, i;
	SOCKET	Sock;
	sockaddr_in	LocalBind, ClientBind;
	fd_set	Sockets;
	unsigned char	Key[RC4_KLEN] = {0};
	unsigned int	Seed;

	wVersionRequested = MAKEWORD(2, 2);
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0)
	{
		printf("Unable to start WSA Lib\n");
		return (0xBADF00D);
	}

	if (!InitProc())
		return 0;

	printf("SkypeKeyServer Started..\n");

	Sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (Sock == INVALID_SOCKET)
	{
		printf("Could not create socket..\n");
		WSACleanup();
		exit(0);
	}

	ZeroMemory((char *)&LocalBind, sizeof(LocalBind));
	LocalBind.sin_family = AF_INET;
	LocalBind.sin_addr.s_addr = htonl(INADDR_ANY);
	LocalBind.sin_port = htons(33033);
	bind(Sock, (struct sockaddr *)&LocalBind, sizeof(LocalBind));

	while(1)
	{
		FD_ZERO(&Sockets);
		FD_SET(Sock, &Sockets);

		CbSz = sizeof(struct sockaddr_in);
		
		SelRes = select(FD_SETSIZE, &Sockets, NULL, NULL, NULL);
		if (SelRes)
		{
			Res = recvfrom(Sock, (char *)&Seed, 0x04, 0, (SOCKADDR *)&ClientBind, &CbSz);
			if (Res != 0x04)
				ZeroMemory((char *)&Key[0], RC4_KLEN);
			else
			{
				for (i = 0; i < 0x14; i++)
					*(unsigned int *)(Key + 4 * i) = Seed;
				Seed2Key(Key, Seed);
			}
			Res = sendto(Sock, (char *)&Key[0], RC4_KLEN, 0, (SOCKADDR *)&ClientBind, CbSz);
		}
	}

	EndProc();
	closesocket(Sock);
	WSACleanup();
	return 0;
}
