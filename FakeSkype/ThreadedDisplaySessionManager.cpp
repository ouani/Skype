#include "SessionManager.h"

static int			Connected = 0;
static SOCKET		TCPSock;
static sockaddr_in	LocalBind;
static TCPKeyPair	RelayKeys;

CConsoleLogger		ThreadConsole;
SessProp			*SessionProposal;

#define			TPRINTF	ThreadConsole.printf

//FIXME : PUT SYNCHRONISATION ON RECVBUFFER & ALL OVER THE CODE

int	DeclareSession(Host Relay)
{
	uchar		Request[0xFF];
	ushort		TransID;
	uchar		*PRequest, *Mark;
	uint		Size, SizeSz;
	ObjectDesc	ObjNbr;

	PRequest = Request;

	ZeroMemory(Request, 0xFF);
	TransID = BytesRandomWord();
	if (0xFFFF - TransID < 0x1000)
		TransID -= 0x1000;
	
	*(unsigned short *)PRequest = htons(TransID);
	PRequest += 2;

	Mark = PRequest;
	WriteValue(&PRequest, 0x0A);
	WriteValue(&PRequest, 0x293);
	*(unsigned short *)PRequest = htons(Reply2ID);
	PRequest += 2;
	
	*PRequest++ = RAW_PARAMS;
	WriteValue(&PRequest, 0x02);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x01;
	ObjNbr.Value.Nbr = 0x02;
	WriteObject(&PRequest, ObjNbr);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x08;
	ObjNbr.Value.Nbr = 0x0A;
	WriteObject(&PRequest, ObjNbr);

	Size = (uint)(PRequest - Request);
	SizeSz = GetWrittenSz(Size << 1);

	PRequest = Request;
	memmove_s(Request + SizeSz, 0xFF, Request, 0xFF - SizeSz);
	WriteValue(&PRequest , Size << 1);

	Size += SizeSz;
	
	CipherTCP(&(RelayKeys.SendStream), Request, 3);
	CipherTCP(&(RelayKeys.SendStream), Request + 3, Size - 3);

	printf("Declaring session..\n");

	if (TSENDPACKETTCP(ThreadConsole, TCPSock, Relay, Request, Size, HTTPS_PORT, &Connected))
}

int	RelayExchangeKeys(Host Relay, int IsKeyAlreadySent, ushort HandShakeResponseLen)
{
	uint	BadSeed = 1;
	uint	Seed, UpSeed, Idx, SentKeySz;
	ushort	ZWord;
	TCPCtrlPacketHeader	Header;
	TCPCtrlPacketHeader *RHeader;
	uchar	Packet[sizeof(TCPCtrlPacketHeader) + 35] = {0};
	uchar	*AlreadySentKey;

	if (IsKeyAlreadySent)
	{
		SentKeySz = RecvBufferSz - HandShakeResponseLen - sizeof(HttpsPacketHeader);
		AlreadySentKey = (uchar *)malloc(SentKeySz);
		memcpy_s(AlreadySentKey, SentKeySz, RecvBuffer + HandShakeResponseLen + sizeof(HttpsPacketHeader), SentKeySz);
	}

	Seed = BytesRandom();
	while (BadSeed)
	{
		Seed = Update(Seed);
		__asm
		{
			push eax
			mov  eax, Seed
			test eax, 0x80808080
			je	 EndTest
			and  eax, 0xFF000000
			cmp  eax, 0x80000000
			je	 EndTest
			mov	 BadSeed, 0
EndTest:
			pop eax
		}
	}
	UpSeed = Update(Seed);
	ZWord = Update(Seed) & 0x81FF;
	if (ZWord == 1)
		ZWord = 2;
	Header.Seed = htonl(Seed);
	Header.ZWord = htons(ZWord);
	Header.Cookie_1 = htonl(0x01);
	Header.Cookie_2 = htonl(0x03);
	Header.Length = 36 + 36 + 1;
	Header.Type = PKT_TYPE_CTRL;
	InitKey(&(RelayKeys.SendStream), Seed);
	CipherTCP(&(RelayKeys.SendStream), (uchar *)&(Header.ZWord), sizeof(TCPCtrlPacketHeader) - sizeof(Header.Seed) - 2);	
	memcpy_s(Packet, sizeof(TCPCtrlPacketHeader) + 35, (uchar *)&Header, sizeof(TCPCtrlPacketHeader));
	InitKey(&(RelayKeys.SendStream), Seed);
	Seed = UpSeed;
	for (Idx = sizeof(TCPCtrlPacketHeader); Idx < sizeof(TCPCtrlPacketHeader) + 35; Idx++)
	{
		Seed = Update(Seed);
		Packet[Idx] = ((uchar *)&Seed)[3];
	}

	CipherTCP(&(RelayKeys.SendStream), Packet + sizeof(TCPCtrlPacketHeader) - 2, 35 + 2);
	
	TPRINTF("Sending Our Seed..\n");
	TSHOWMEM(ThreadConsole, Packet, sizeof(TCPCtrlPacketHeader) + 35);
	TPRINTF("\n\n");

	if (TSENDPACKETTCP(ThreadConsole, TCPSock, Relay, Packet, sizeof(TCPCtrlPacketHeader) + 35, HTTPS_PORT, &Connected))
	{
		TPRINTF("Send Seed Response..\n");
		TSHOWMEM(ThreadConsole, RecvBuffer, RecvBufferSz);
		TPRINTF("\n\n");
	}
	else if (IsKeyAlreadySent)
	{
		RecvBufferSz = 0xFFFF;
		ZeroMemory(RecvBuffer, 0xFFFF);
		TPRINTF("Key Already Sent with handshake response..\n");
		memcpy_s(RecvBuffer, RecvBufferSz, AlreadySentKey, SentKeySz);
		RecvBufferSz = SentKeySz;
	}
	else
	{
		TPRINTF("Skipping Host %s..\n", Relay.ip);
		return 0;
	}

	UncipherObfuscatedTCPCtrlPH(RecvBuffer);

	RHeader = (TCPCtrlPacketHeader *)RecvBuffer;
	if ((htonl(RHeader->Cookie_1) == 0x01) && (htonl(RHeader->Cookie_2) == 0x03))
	{
		TPRINTF("Remote Seed : 0x%x\n", htonl(RHeader->Seed));
		
		InitKey(&(RelayKeys.RecvStream), htonl(RHeader->Seed));
		CipherTCP(&(RelayKeys.RecvStream), RecvBuffer + sizeof(TCPCtrlPacketHeader) - 2, RecvBufferSz - sizeof(TCPCtrlPacketHeader) + 2);

		TPRINTF("Key Exchange Response [Decrypted]..\n");
		TSHOWMEM(ThreadConsole, RecvBuffer, RecvBufferSz);
		TPRINTF("\n\n");

		TPRINTF("Keys Pair Initialized..\n");
	}
	else
	{
		TPRINTF("Bad Key Exchange Response.. Leaving Relay..\n");
		return 0;
	}
	return (DeclareSession(Relay));
}

int	RelayHandShake(Host Relay)
{
	uchar	HttpsHSPacket[HHSP_SIZE] = {0};
	uint	Initial;
	int		Idx;
	HttpsPacketHeader	*RHeader;

	memcpy_s(HttpsHSPacket, HHSP_SIZE, HttpsHandShakeTemplate, HHSP_SIZE);
	Initial = BytesRandom();
	for (Idx = HHSP_SIZE - 16; Idx < HHSP_SIZE; Idx++)
	{
		Initial = Update(Initial);
		HttpsHSPacket[Idx] = ((uchar *)&Initial)[3];
	}

	TPRINTF("Sending https HandShake to Relay %s:%d\n", Relay.ip, Relay.port);
	TSHOWMEM(ThreadConsole, HttpsHSPacket, HHSP_SIZE);
	TPRINTF("\n\n");

	if (TSENDPACKETTCP(ThreadConsole, TCPSock, Relay, HttpsHSPacket, HHSP_SIZE, HTTPS_PORT, &Connected))
	{
		TPRINTF("HandShake Response..\n");
		TSHOWMEM(ThreadConsole, RecvBuffer, RecvBufferSz);
		TPRINTF("\n\n");
	}
	else
	{
		TPRINTF("Relay %s:%d not responding..\n", Relay.ip, Relay.port);
		return 0;
	}
	RHeader = (HttpsPacketHeader *)RecvBuffer;
	if (strncmp((const char *)RHeader->MAGIC, HTTPS_HSR_MAGIC, strlen(HTTPS_HSR_MAGIC)))
	{
		TPRINTF("Bad Handshake Response.. Leaving Relay %s:%d\n", Relay.ip, Relay.port);
		return 0;
	}
	TPRINTF("Relay OK.. Handing Over.. %s:%d\n", Relay.ip, Relay.port);
	return (RelayExchangeKeys(Relay, (htons(RHeader->ResponseLen) + sizeof(HttpsPacketHeader) != RecvBufferSz), htons(RHeader->ResponseLen)));
}

DWORD WINAPI	InitSessionThreadProc(LPVOID Param)
{
	uint			ReUse = 1;

	SessionProposal = (SessProp *)Param;

	ThreadConsole.Create("FakeSkype Thread - Initializing Session with peer..", -1, -1, NULL, CONSOLEHELPER_EXE);
	TPRINTF("Initializing Session [%x]..\n\n", SessionProposal->SessID);

	TCPSock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(TCPSock, SOL_SOCKET, SO_REUSEADDR, (const char *)&ReUse, sizeof(ReUse));

	if (RelayHandShake(SessionProposal->Relays->front()) == 0)
		goto End;
End:
	ExitThread(0);
}

void	InitSession(SessProp *SessionProposal)
{
	HANDLE	hThread;
	DWORD	ThreadID;

	hThread = CreateThread(NULL, 0, InitSessionThreadProc, (LPVOID)SessionProposal, 0, &ThreadID); 
	WaitForSingleObject(hThread, INFINITE);
}