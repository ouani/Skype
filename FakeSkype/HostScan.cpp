#include "HostScan.h"

/*FIXME* IMPLEMENT SKYPE_CMD FUNC TO WRITE CMDZ*/

Host	Hosts[] = {
				   {"193.88.6.19", 33033},
				   {"194.165.188.82", 33033},
				   {"66.235.180.9", 33033},
				   {"66.235.181.9", 33033},
				   {"212.72.49.143", 33033},
				   {"195.215.8.145", 33033},
				   {"64.246.48.23", 33033},
				   {"64.246.49.60", 33033},
				   {"64.246.49.61", 33033},
				   {0, 0}
				  };

queue<Host>		HostsQueue;

static SOCKET	UDPSock;
static SOCKET	TCPSock;

static sockaddr_in	LocalBind;
unsigned int		my_public_ip = 0;
int					Scan = 1;
static int			Connected = 0;

uint				NbUserConnected = 0;

TCPKeyPair			Keys;

void	InitQueue()
{
	//SHOULD ADD CACHED HOSTS IN A XML FILE
	int	Idx;
	
	for (Idx = 0; (Hosts[Idx].port != 0); Idx++)
		HostsQueue.push(Hosts[Idx]);
}

void	ResetTCPSock()
{
	uint	ReUse;

	ReUse = 1;
	Connected = 0;
	closesocket(TCPSock);
	TCPSock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(TCPSock, SOL_SOCKET, SO_REUSEADDR, (const char *)&ReUse, sizeof(ReUse));
}

uchar	GetPacketType()
{
	ushort	TransID;
	uchar	PacketType;

	if (RecvBufferSz < 3)
	{
		printf("Invalid packet..\n");
		return (0);
	}

	TransID = *(ushort *)&RecvBuffer[0];
	PacketType = *(uchar *)&RecvBuffer[2];

	return (PacketType & 0x8F);
}

//PBody->ProbeCmd = htons(0xD201); => Start Supernode

int		ForgeProbe(uchar *Probe, Host CurHost)
{
	unsigned short	TransID;
	ProbeHeader		*PHeader;
	ReqBody			*PBody;

	TransID = BytesRandomWord();
	PHeader = (ProbeHeader *)Probe;
	PHeader->TransID = htons(TransID);
	PHeader->PacketType = PKT_TYPE_OBFSUK;
	PHeader->IV = htonl(GenIV());
	
	PBody = (ReqBody *)(Probe + sizeof(ProbeHeader));
	PBody->PayLoadLen = 0x04;
	PBody->ProbeCmd = htons(0xDA01);
	PBody->RequestID = PHeader->TransID - 1;
	PBody->ParamListType = RAW_PARAMS;
	PBody->NbObj = 0x00;
	
	PHeader->Crc32 = htonl(crc32((uchar *)PBody, sizeof(ReqBody) + PROBE_PAYL_LEN, -1));

	Cipher(Probe + sizeof(ProbeHeader), sizeof(ReqBody) + PROBE_PAYL_LEN, htonl(my_public_ip), htonl(inet_addr(CurHost.ip)), htons(PHeader->TransID), htonl(PHeader->IV), 0);

	return (sizeof(ProbeHeader) + sizeof(ReqBody) + PROBE_PAYL_LEN);
}

int		ResendProbe(Host CurHost, uchar *Probe)
{
	uchar					ReProbe[65536] = {0};
	NackPacket				*NPacket;
	ResendProbeHeader		*RPHeader;
	ProbeHeader				*PHeader;
	ReqBody					*PBody;

	NPacket = (NackPacket *)RecvBuffer;
	RPHeader = (ResendProbeHeader *)ReProbe;
	PHeader = (ProbeHeader *)Probe;

	RPHeader->TransID = NPacket->TransID;
	RPHeader->PacketType = PKT_TYPE_RESEND;
	RPHeader->Unknown_COOKIE = 0x1;
	RPHeader->Challenge = NPacket->Challenge;
	RPHeader->Dest = inet_addr(CurHost.ip);
	RPHeader->Crc32 = PHeader->Crc32;

	my_public_ip = NPacket->PublicIP;
	
	PBody = (ReqBody *)(ReProbe + sizeof(ResendProbeHeader));
	PBody->PayLoadLen = 0x04;
	PBody->ProbeCmd = htons(0xDA01);
	PBody->RequestID = PHeader->TransID - 1;
	PBody->ParamListType = RAW_PARAMS;
	PBody->NbObj = 0x00;

	Cipher(ReProbe + sizeof(ResendProbeHeader), sizeof(ReqBody) + PROBE_PAYL_LEN, htonl(my_public_ip), htonl(inet_addr(CurHost.ip)), htons(PHeader->TransID), htonl(NPacket->Challenge), 1);

	//showmem(ReProbe, sizeof(ResendProbeHeader) + sizeof(ReqBody) + PROBE_PAYL_LEN);
	//printf("\n\n");

	printf("Re-Sending probe to host : %s:%d..\n", CurHost.ip, CurHost.port);
	return (SendPacket(UDPSock, CurHost, ReProbe, sizeof(ResendProbeHeader) + sizeof(ReqBody) + PROBE_PAYL_LEN));
}

void	RequestBCM(Host CurHost, uint BCM_id)
{
	uchar		Request[0xFF] = {0};
	ushort		TransID;
	uchar		*PRequest, *Mark, *Mark2;
	ObjectDesc	ObjNbr;
	
	PRequest = Request;
	
	TransID = BytesRandomWord();
	*PRequest++ = 0x00;
	*(unsigned short *)PRequest = htons(TransID);
	PRequest += 2;
	Mark = PRequest;
	WriteValue(&PRequest, 0x06 + GetWrittenSz(BCM_id));
	WriteValue(&PRequest, 0x182);
	*(unsigned short *)PRequest = htons(TransID - 1);
	PRequest += 2;
	
	*PRequest++ = RAW_PARAMS;
	WriteValue(&PRequest, 0x01);
	
	Mark2 = PRequest;
	ObjNbr.Family = OBJ_FAMILY_NBR; //BCM ID
	ObjNbr.Id = 0x00;
	ObjNbr.Value.Nbr = BCM_id;
	WriteObject(&PRequest, ObjNbr);
	
	*Request = (uchar)(PRequest - Request) - 1;
	*Request <<= 1;

	printf("Sending BCM #%d request..\n", BCM_id);
	//showmem(Request, (uint)(PRequest - Request));

	CipherTCP(&(Keys.SendStream), Request, 3);
	CipherTCP(&(Keys.SendStream), Request + 3, (uint)(PRequest - Request) - 3);

	if (SendPacketTCP(TCPSock, CurHost, Request, (uint)(PRequest - Request), HTTPS_PORT, &Connected))
	{
		CipherTCP(&(Keys.RecvStream), RecvBuffer, RecvBufferSz);
		
		printf("Channel successfully subscribed on..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		//printf("\n\n");
	}
	else
	{
		printf("No response to request..\n");
		return ;
	}
}

void	SubmitPropsNStats(Host CurHost)
{
	/*unsigned char data[] = {
	0x1C, 0xF0, 0x8F, 0x0A, 0x32, 0xF0, 0x8E, 0x41, 0x02, 0x00, 0x04, 0x10, 0x00, 0x05, 0x06, 0xC0, 
	0x01, 0xF0, 0x90, 0x53, 0xA9, 0x02, 0x41, 0x13, 0x00, 0x06, 0x00, 0x00, 0x07, 0x00, 0x00, 0x08, 
	0x01, 0x03, 0x0E, 0x30, 0x2F, 0x31, 0x2E, 0x30, 0x2E, 0x30, 0x2E, 0x30, 0x30, 0x30, 0x00, 0x00, 
	0x0F, 0xBF, 0xAE, 0xCC, 0xB2, 0x04, 0x00, 0x00, 0x22, 0x00, 0x01, 0xBE, 0x07, 0x00, 0x0D, 0x02, 
	0x00, 0x15, 0xC4, 0xAD, 0xD5, 0xB2, 0x04, 0x00, 0x98, 0x01, 0x00, 0x00, 0x7D, 0x05, 0x00, 0x96, 
	0x01, 0x01, 0x00, 0x97, 0x01, 0x01, 0x00, 0x7E, 0x01, 0x00, 0x0B, 0x00, 0x00, 0x05, 0xE8, 0x07, 
	0x00, 0x02, 0x00, 0x00, 0x03, 0x00, 0x00, 0x04, 0x00, 0x05, 0xB1, 0x02, 0x41, 0x01, 0x00, 0x62, 
	0x01
	};

	unsigned char data[] = {
	0x1C, 0xBB, 0x78, 0x0A, 0x32, 0xBB, 0x77, 0x41, 0x02, 0x00, 0x04, 0x10, 0x00, 0x05, 0x06, 0xC0, 
	0x01, 0xBB, 0x79, 0x53, 0xA9, 0x02, 0x41, 0x13, 0x00, 0x06, 0x00, 0x00, 0x07, 0x00, 0x00, 0x08, 
	0x01, 0x03, 0x0E, 0x30, 0x2F, 0x32, 0x2E, 0x35, 0x2E, 0x30, 0x2E, 0x31, 0x35, 0x31, 0x00, 0x00, 
	0x0F, 0xBF, 0xB7, 0xFF, 0xB3, 0x04, 0x00, 0x00, 0x22, 0x00, 0x01, 0xBE, 0x07, 0x00, 0x0D, 0x02, 
	0x00, 0x15, 0x87, 0x8A, 0xFE, 0xB3, 0x04, 0x00, 0x98, 0x01, 0x00, 0x00, 0x7D, 0x05, 0x00, 0x96, 
	0x01, 0x01, 0x00, 0x97, 0x01, 0x01, 0x00, 0x7E, 0x01, 0x00, 0x0B, 0x00, 0x00, 0x05, 0xE8, 0x07, 
	0x00, 0x02, 0x00, 0x00, 0x03, 0x00, 0x00, 0x04, 0x00, 0x05, 0xB1, 0x02, 0x41, 0x01, 0x00, 0x62, 
	0x01
	};*/

	unsigned char data[28] = {
	0x1C, 0x97, 0xBF, 0x0A, 0x32, 0x97, 0xBE, 0x41, 0x02, 0x00, 0x04, 0x10, 0x00, 0x05, 0x06, 0x18, 
	0x97, 0xC0, 0x02, 0xA9, 0x02, 0x41, 0x00, 0x02, 0xB1, 0x02, 0x41, 0x00
	};

	printf("Sending props & stats to parentnode (with slotinfos request)..\n");
	//showmem(data, sizeof(data));

	CipherTCP(&(Keys.SendStream), data, 3);
	CipherTCP(&(Keys.SendStream), data + 3, sizeof(data) - 3);

	if (SendPacketTCP(TCPSock, CurHost, data, sizeof(data), HTTPS_PORT, &Connected))
	{
		CipherTCP(&(Keys.RecvStream), RecvBuffer, RecvBufferSz);

		//showmem(RecvBuffer, RecvBufferSz);
		////printf("\n\n");
	}
	printf("Props & Stats Submitted..\n");
}

void	OnClientAccept(Host CurHost)
{
	uchar		*Browser;
	SResponse	Response;
	
	Browser = RecvBuffer;

	CipherTCP(&(Keys.RecvStream), RecvBuffer, RecvBufferSz);
	
	//printf("UnCiphered Response..\n");
	//showmem(RecvBuffer, RecvBufferSz);
	//printf("\n\n");

	Response.Objs = NULL;
	Response.NbObj = 0;
	TCPResponseManager(&Browser, (uint *)&RecvBufferSz, &Response);

	/*ReadValue(&Browser, &Size);
	printf("Packet ID : 0x%x%x\n", Browser[0], Browser[1]);
	Browser += 2;

	PayLoadLen = Browser[0];
	Browser += 1;

	ReadValue(&Browser, &Cmd);

	printf("Reply to packet : 0x%x%x\n", Browser[0], Browser[1]);
	Browser += 2;*/

	switch (Response.Cmd / 8)
	{
	case CMD_CLIENT_OK:
		printf("Client Accepted.. HostScanning Stop.. Connected to %s:%d !\n", CurHost.ip, CurHost.port);
		printf("INFOS RECEIVED..\n");
		for (uint Idx = 0; Idx < Response.NbObj; Idx++)
		{
			switch (Response.Objs[Idx].Id)
			{
			case OBJ_ID_STACKVER:
				printf("StackVersion : %d\n", Response.Objs[Idx].Value.Nbr);
				break;
			case OBJ_ID_STACKTS:
				printf("StackTimeStamp : %d\n", Response.Objs[Idx].Value.Nbr);
				break;
			case OBJ_ID_PEERLPORT:
				printf("Peer Listenning Port : %d\n", Response.Objs[Idx].Value.Nbr);
				break;
			case OBJ_ID_PUBNETADDR:
				printf("My Public Interface : %s:%d\n", Response.Objs[Idx].Value.Addr.ip, Response.Objs[Idx].Value.Addr.port);
				break;
			default :
				printf("Unexpected Object %d:%d\n", Response.Objs[Idx].Family, Response.Objs[Idx].Id);
				break;
			}
		}
		printf("\n");
		Scan = 0;
		break;
	case CMD_CLIENT_REFUSED:
		printf("Client refused.. Asking to someone else..\n");
		break;
	default:
		break;
	}

	while (RecvBufferSz > 0)
	{
		Response.Objs = NULL;
		Response.NbObj = 0;
		TCPResponseManager(&Browser, (uint *)&RecvBufferSz, &Response);
		switch (Response.Cmd / 8)
		{
		case CMD_NETSTATS:
			printf("NetStats Received..\n");
			for (uint Idx = 0; Idx < Response.NbObj; Idx++)
			{
				DumpObj(Response.Objs[Idx]);
				switch (Response.Objs[Idx].Id)
				{
				case OBJ_ID_NBCONNECTED:
					NbUserConnected = Response.Objs[Idx].Value.Nbr;
					cprintf(FOREGROUND_BLUE, "%d clients connected..\n\n", Response.Objs[Idx].Value.Nbr);
					break;
				default :
					printf("Unexpected Object %d:%d\n", Response.Objs[Idx].Family, Response.Objs[Idx].Id);
					break;
				}
			}
			break;
		case CMD_BCM:
			{
				uchar	RecvCopy[0xFFFF];
				int		RecvSzCopy;
				
				int		SkipBCM;

				SkipBCM = 1;

				printf("Received Channels to Suscribe On.. Suscribe ?\n");

				if (SkipBCM)
				{
					printf("SkipBCM Request Set To TRUE.. Sending ACK\n\n");
					ZeroMemory(RecvCopy, 0xFFFF);
					memcpy_s(RecvCopy, 0xFFFF, RecvBuffer, RecvBufferSz);
					RecvSzCopy = RecvBufferSz;

					SendACK(Response.PacketID, TCPSock, CurHost, HTTPS_PORT, &Connected, &Keys);

					ZeroMemory(RecvBuffer, 0xFFFF);
					memcpy_s(RecvBuffer, 0xFFFF, RecvCopy, RecvSzCopy);
					RecvBufferSz = RecvSzCopy;					
				}
				else
				{
					printf("SkipBCM Request Set To FALSE.. Will Request..\n\n");

					uint Idx = 0;

					while (Idx < Response.NbObj)
					{
						uint BCM_ver = 0;
						uint BCM_id = 0;

						switch (Response.Objs[Idx].Id)
						{
						case OBJ_ID_BCMID:
							BCM_id = Response.Objs[Idx].Value.Nbr;
							break;
						case OBJ_ID_BCMVER:
							BCM_ver = Response.Objs[Idx].Value.Nbr;
							break;
						default:
							printf("Unexpected Object %d:%d\n", Response.Objs[Idx].Family, Response.Objs[Idx].Id);
							break;
						}
						Idx++;
						switch (Response.Objs[Idx].Id)
						{
						case OBJ_ID_BCMID:
							BCM_id = Response.Objs[Idx].Value.Nbr;
							break;
						case OBJ_ID_BCMVER:
							BCM_ver = Response.Objs[Idx].Value.Nbr;
							break;
						default:
							printf("Unexpected Object %d:%d\n", Response.Objs[Idx].Family, Response.Objs[Idx].Id);
							break;
						}
						Idx++;
						
						if ((BCM_ver) && (BCM_id))
						{
							printf("BCM: #%d, version %d\n", BCM_id, BCM_ver);
							ZeroMemory(RecvCopy, 0xFFFF);
							memcpy_s(RecvCopy, 0xFFFF, RecvBuffer, RecvBufferSz);
							RecvSzCopy = RecvBufferSz;
							RequestBCM(CurHost, BCM_id);
							ZeroMemory(RecvBuffer, 0xFFFF);
							memcpy_s(RecvBuffer, 0xFFFF, RecvCopy, RecvSzCopy);
							RecvBufferSz = RecvSzCopy;	
							printf("\n");
						}
					}
				}
				break;
			}
		default:
			printf("Unmanaged Cmd %d\n", Response.Cmd / 8);
			break;
		}
	}
	//SubmitPropsNStats(CurHost);
}

void	ClientAccept(Host CurHost)
{
	uchar		Request[0xFF] = {0};
	ReqBody		*PBody;
	ushort		TransID;
	uchar		*PRequest;
	uchar		NodeID[NODEID_SZ] = {0};
	uchar		*PNodeID;
	int			IdxUp, IdxDown;
	ObjectDesc	ObjNodeID, ObjListeningPort, ObjUpTime, ObjStackVersionLike;
	
	PRequest = Request;
	
	TransID = BytesRandomWord();
	Request[0] = 0x1C + 0x1C + 0x04;
	*(unsigned short *)&Request[1] = htons(TransID);

	PBody = (ReqBody *)(Request + 3);
	PBody->PayLoadLen = 0x19;
	PBody->ProbeCmd = htons(0xF201);
	PBody->RequestID = htons(TransID - 1);
	PBody->ParamListType = RAW_PARAMS;
	PBody->NbObj = 0x04;

	PRequest += sizeof(ReqBody) + 3;
	
	PNodeID = GetNodeId();
	IdxUp = 0;
	IdxDown = NODEID_SZ - 1;
	while (IdxDown >= 0)
		NodeID[IdxDown--] = PNodeID[IdxUp++];

	ObjNodeID.Family = OBJ_FAMILY_TABLE;
	ObjNodeID.Id = OBJ_ID_NODEID;
	memcpy_s(ObjNodeID.Value.Table, sizeof(ObjNodeID.Value.Table), NodeID, NODEID_SZ);
	WriteObject(&PRequest, ObjNodeID);

	ObjListeningPort.Family = OBJ_FAMILY_NBR;
	ObjListeningPort.Id = OBJ_ID_LPORT;
	ObjListeningPort.Value.Nbr = GetListeningPort();
	WriteObject(&PRequest, ObjListeningPort);

	ObjUpTime.Family = OBJ_FAMILY_NBR;
	ObjUpTime.Id = OBJ_ID_UPTIME;
	ObjUpTime.Value.Nbr = GetUpTime();
	WriteObject(&PRequest, ObjUpTime);

	ObjStackVersionLike.Family = OBJ_FAMILY_NBR;
	ObjStackVersionLike.Id = OBJ_ID_STVL;
	ObjStackVersionLike.Value.Nbr = 0x00;
	WriteObject(&PRequest, ObjStackVersionLike);

	printf("Asking for client accept..\n");
	//showmem(Request, (uint)(PRequest - Request));
	//printf("\n\nRequest Ciphered :\n");

	CipherTCP(&(Keys.SendStream), Request, 3);
	CipherTCP(&(Keys.SendStream), Request + 3, (uint)(PRequest - Request) - 3);

	//showmem(Request, (uint)(PRequest - Request));
	//printf("\n\n");

	if (SendPacketTCP(TCPSock, CurHost, Request, (uint)(PRequest - Request), HTTPS_PORT, &Connected))
	{
		printf("Client Accept Response..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		//printf("\n\n");
		OnClientAccept(CurHost);
	}
	else
	{
		printf("No response to client accept request.. Skipping Host %s..\n", CurHost.ip);
		return ;
	}
}

void	ExchangeKeys(Host CurHost, int IsKeyAlreadySent, ushort HandShakeResponseLen)
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
	InitKey(&(Keys.SendStream), Seed);
	CipherTCP(&(Keys.SendStream), (uchar *)&(Header.ZWord), sizeof(TCPCtrlPacketHeader) - sizeof(Header.Seed) - 2);	
	memcpy_s(Packet, sizeof(TCPCtrlPacketHeader) + 35, (uchar *)&Header, sizeof(TCPCtrlPacketHeader));
	InitKey(&(Keys.SendStream), Seed);
	Seed = UpSeed;
	for (Idx = sizeof(TCPCtrlPacketHeader); Idx < sizeof(TCPCtrlPacketHeader) + 35; Idx++)
	{
		Seed = Update(Seed);
		Packet[Idx] = ((uchar *)&Seed)[3];
	}

	CipherTCP(&(Keys.SendStream), Packet + sizeof(TCPCtrlPacketHeader) - 2, 35 + 2);
	
	printf("Sending Our Seed..\n");
	//showmem(Packet, sizeof(TCPCtrlPacketHeader) + 35);
	//printf("\n\n");

	if (SendPacketTCP(TCPSock, CurHost, Packet, sizeof(TCPCtrlPacketHeader) + 35, HTTPS_PORT, &Connected))
	{
		printf("Send Seed Response..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		//printf("\n\n");
	}
	else if (IsKeyAlreadySent)
	{
		RecvBufferSz = 0xFFFF;
		ZeroMemory(RecvBuffer, 0xFFFF);
		printf("Key Already Sent with handshake response..\n");
		memcpy_s(RecvBuffer, RecvBufferSz, AlreadySentKey, SentKeySz);
		RecvBufferSz = SentKeySz;
	}
	else
	{
		printf("Skipping Host %s..\n", CurHost.ip);
		return ;
	}

	UncipherObfuscatedTCPCtrlPH(RecvBuffer);

	RHeader = (TCPCtrlPacketHeader *)RecvBuffer;
	if ((htonl(RHeader->Cookie_1) == 0x01) && (htonl(RHeader->Cookie_2) == 0x03))
	{
		printf("Remote Seed : 0x%x\n", htonl(RHeader->Seed));
		InitKey(&(Keys.RecvStream), htonl(RHeader->Seed));
		CipherTCP(&(Keys.RecvStream), RecvBuffer + sizeof(TCPCtrlPacketHeader) - 2, RecvBufferSz - sizeof(TCPCtrlPacketHeader) + 2);

		printf("Key Exchange Response [Decrypted]..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		//printf("\n\n");

		printf("Keys Pair Initialized..\n");
	}
	else
	{
		printf("Bad Key Exchange Response.. Skipping Host..\n");
		return ;
	}
	ClientAccept(CurHost);
}

void	HandShake(Host CurHost)
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

	printf("Sending https HandShake to %s\n", CurHost.ip);
	//showmem(HttpsHSPacket, HHSP_SIZE);
	//printf("\n\n");

	if (SendPacketTCP(TCPSock, CurHost, HttpsHSPacket, HHSP_SIZE, HTTPS_PORT, &Connected))
	{
		printf("HandShake Response..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		//printf("\n\n");
	}
	else
	{
		printf("Skipping Host %s..\n", CurHost.ip);
		return ;
	}
	RHeader = (HttpsPacketHeader *)RecvBuffer;
	if (strncmp((const char *)RHeader->MAGIC, HTTPS_HSR_MAGIC, strlen(HTTPS_HSR_MAGIC)))
	{
		printf("Bad Handshake Response.. Skipping Host %s..\n", CurHost.ip);
		return ;
	}
	printf("SuperNode Found.. Handing Over.. %s\n", CurHost.ip);
	ExchangeKeys(CurHost, (htons(RHeader->ResponseLen) + sizeof(HttpsPacketHeader) != RecvBufferSz), htons(RHeader->ResponseLen));
}

void	ManageObfuscatedPacket(Host CurHost)
{
	struct in_addr	PublicIP;
	PacketBody		*Packet;
	int				i;
	uchar			*SNList;
	Host			NewHost;

	PublicIP.S_un.S_addr = my_public_ip;
	if (UnCipherObfuscated(RecvBuffer, RecvBufferSz, inet_ntoa(PublicIP), CurHost.ip) == 0)
	{
		printf("Unable to uncipher Packet..\n");
		return ;
	}

	//showmem(RecvBuffer, RecvBufferSz);
	//printf("\n\n");

	Packet = (PacketBody *)(RecvBuffer + sizeof(CipheredPacketHeader));
	
	/*FIXME MUST USE SORT OF GETCMD*/

	switch (*(uchar *)&Packet->Cmd / 8)
	{
	case CMD_PROBE_REFUSED:
		SNList = RecvBuffer + sizeof(CipheredPacketHeader) + sizeof(PacketBody);
		i = RecvBufferSz - sizeof(CipheredPacketHeader) - sizeof(PacketBody);
		if ((Packet->Unknown_COOKIE == 0x42) && ((SNList[3] == 0x27) || SNList[3] == 0x77))
		{
			printf("Probe Refused by %s:%d, but New SuperNodes Discovered\n", CurHost.ip, CurHost.port);
			SNList = SNList + ((SNList[3] == 0x27) ? 4 : 6);
			i -= (SNList[3] == 0x27) ? 4 : 6;
			while (i > 0)
			{
				PublicIP.S_un.S_addr = htonl(*(unsigned long *)SNList);
				ZeroMemory(NewHost.ip, MAX_IP_LEN + 1);
				strcpy_s(NewHost.ip, MAX_IP_LEN + 1, inet_ntoa(PublicIP));
				NewHost.port = *(unsigned short *)(SNList + 4);
				printf("-> %s:%d\n", NewHost.ip, NewHost.port);
				HostsQueue.push(NewHost);
				SNList += 6;
				i -= 6;
			}
		}
		else
			printf("Unable to analyze Object List..\n");
		break;
	case CMD_PROBE_OK:
		printf("Probe Accepted by %s:%d\n", CurHost.ip, CurHost.port);
		HandShake(CurHost);
		break;
	default:
		printf("Unmanaged Cmd 0x%x..\n", *(uchar *)&Packet->Cmd / 8);
		break;
	}
}

void		HostScan(Host *Session_SN)
{
	Host	CurHost;
	uchar	Probe[65536] = {0};
	uint	Size, DoResend, ReUse;

	DoResend = 0;
	ReUse = 1;
	Scan = 1;
	InitQueue();

	SetConsoleTitle("FakeSkype - Scanning for SuperNodes..");
	
	UDPSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	TCPSock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(TCPSock, SOL_SOCKET, SO_REUSEADDR, (const char *)&ReUse, sizeof(ReUse));

	ZeroMemory((char *)&LocalBind, sizeof(LocalBind));
	LocalBind.sin_family = AF_INET;
	LocalBind.sin_addr.s_addr = htonl(INADDR_ANY);
	LocalBind.sin_port = htons(DEF_LPORT);
	bind(UDPSock, (struct sockaddr *)&LocalBind, sizeof(LocalBind));

	while (!HostsQueue.empty())
	{
		CurHost = HostsQueue.front();
		
		if (DoResend)
		{
			if (ResendProbe(CurHost, Probe))
			{				
				//showmem(RecvBuffer, RecvBufferSz);
				//printf("\n\n");
			}
			DoResend = 0;
		}
		else
		{
			Size = ForgeProbe(Probe, CurHost);

			printf("Sending probe to host : %s:%d..\n", CurHost.ip, CurHost.port);
			//showmem(Probe, Size);
			//printf("\n\n");

			if (SendPacket(UDPSock, CurHost, Probe, Size))
			{
				//showmem(RecvBuffer, RecvBufferSz);
				//printf("\n\n");
			}
			else
				goto PassEnd;
		}

		switch(GetPacketType())
		{
		case PKT_TYPE_NACK:
			printf("NACK Receveid.. Will ReSend..\n");
			DoResend = 1;
			break;
		case PKT_TYPE_OBFSUK:
			printf("Obfuscated Packet received..\n");
			ManageObfuscatedPacket(CurHost);
			break;
		default:
			printf("UnManaged Packet type..\n");
			break;
		}
PassEnd:
		if (!Scan)
		{
			ZeroMemory(Session_SN->ip, MAX_IP_LEN + 1);
			memcpy_s(Session_SN->ip, MAX_IP_LEN + 1, CurHost.ip, MAX_IP_LEN);
			Session_SN->port = CurHost.port;
			Session_SN->Connected = Connected;
			Session_SN->socket = TCPSock;
			closesocket(UDPSock);

			return ;
		}			
		if (!DoResend)
		{
			if (Connected)
				ResetTCPSock();
			HostsQueue.pop();
		}
	}
	
	closesocket(UDPSock);
	closesocket(TCPSock);
	printf("HostScan Failed.. Exiting..\n");
	ExitProcess(0);
}