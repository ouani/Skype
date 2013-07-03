#include "Presence.h"

uchar	DirBlob[0x148 + 0x40] = {0};

void	BuildLocationBlob(Host Session_SN, uchar *Buffer)
{
	uchar	NodeID[NODEID_SZ] = {0};
	uchar	*PNodeID;
	int		IdxUp, IdxDown;

	IdxUp = 0;
	IdxDown = NODEID_SZ - 1;

	PNodeID = GetNodeId();
	while (IdxUp < NODEID_SZ)
	{
		NodeID[IdxUp] = PNodeID[IdxUp];
		IdxUp++;
	}
	*(unsigned int *)Buffer = *(unsigned int *)NodeID;
	*(unsigned int *)(Buffer + 4) = *(unsigned int *)(NodeID + 4);
	Buffer += NODEID_SZ;

	*Buffer++ = 0x01;

	*(unsigned int *)Buffer = inet_addr("127.0.0.1");
	Buffer += 4;
	*(unsigned short *)Buffer = htons(GetListeningPort());
	Buffer += 2;

	*(unsigned int *)Buffer = inet_addr(Session_SN.ip);
	Buffer += 4;
	*(unsigned short *)Buffer = htons(Session_SN.port);
	Buffer += 2;
}

void	BuildSignedMetaData(uchar *Location, uchar *SignedMD)
{
	uchar			MetaData[0xFF] = {0};
	uchar			MD2Sign[0x80] = {0};
	uchar			*Browser, *Mark;
	uint			Idx, Size;
	ObjectDesc		ObjLocation;
	SHA_CTX			CredCtx, MDCtx;
	int				RSARes;

	RSARes = 0;
	Browser = MetaData;
	ZeroMemory(Browser, 0xFF);

	Mark = Browser;

	*Browser++ = RAW_PARAMS;
	WriteValue(&Browser, 0x01);

	ObjLocation.Family = OBJ_FAMILY_BLOB;
	ObjLocation.Id = OBJ_ID_CILOCATION;
	ObjLocation.Value.Memory.Memory = Location;
	ObjLocation.Value.Memory.MsZ = LOCATION_SZ;
	WriteObject(&Browser, ObjLocation);

	Size = (uint)(Browser - Mark);

	MD2Sign[0x00] = 0x4B;
	
	for (Idx = 1; Idx < (0x80 - (Size + (2 * SHA_DIGEST_LENGTH)) - 2); Idx++)
		MD2Sign[Idx] = 0xBB;
	MD2Sign[Idx++] = 0xBA;

	Mark = MD2Sign + Idx;
	SHA1_Init(&CredCtx);
	SHA1_Update(&CredCtx, GLoginD.SignedCredentials.Memory, GLoginD.SignedCredentials.MsZ);
	SHA1_Final(MD2Sign + Idx, &CredCtx);
	Idx += SHA_DIGEST_LENGTH;

	memcpy_s(MD2Sign + Idx, Size + SHA_DIGEST_LENGTH, MetaData, Size);
	Idx += Size;

	SHA1_Init(&MDCtx);
	SHA1_Update(&MDCtx, Mark, SHA_DIGEST_LENGTH + Size);
	SHA1_Final(MD2Sign + Idx, &MDCtx);
	Idx += SHA_DIGEST_LENGTH;
	
	MD2Sign[Idx] = 0xBC;

	RSARes = RSA_private_encrypt(sizeof(MD2Sign), MD2Sign, SignedMD, GLoginD.RSAKeys, RSA_NO_PADDING);
}

void	SendPresence(Host Session_SN, char *User)
{
	uchar			Request[0xFFF];
	ProbeHeader		*PHeader;
	ushort			TransID;
	uchar			*PRequest, *Mark;
	int				BaseSz;
	uint			PSize;
	ObjectDesc		ObjDirBlob;
	Host			CurSN;
	sockaddr_in		LocalBind;
	SOCKET			SNUDPSock;
	queue<SlotInfo>	Slot;
	queue<Host>		Hosts;
	uchar			Buffer[LOCATION_SZ] = {0};
	static int		Init = 0;

	SetConsoleTitle("FakeSkype - Broadcasting Presence..");

	if (Init == 0)
	{
		BuildLocationBlob(Session_SN, &Buffer[0]);
		
		*(unsigned int *)DirBlob = htonl(0x000000C4 + 0x40);
		memcpy_s(DirBlob + 0x04, 0xC4 + 0x40, GLoginD.SignedCredentials.Memory, GLoginD.SignedCredentials.MsZ);
		BuildSignedMetaData(Buffer, &DirBlob[0xC8 + 0x40]);
		Init = 1;
	}

	SNUDPSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	ZeroMemory((char *)&LocalBind, sizeof(LocalBind));
	LocalBind.sin_family = AF_INET;
	LocalBind.sin_addr.s_addr = htonl(INADDR_ANY);
	LocalBind.sin_port = htons(DEF_LPORT);
	bind(SNUDPSock, (struct sockaddr *)&LocalBind, sizeof(LocalBind));

	RequestSlotInfos(Session_SN, &Slot, 0x12, GetAssociatedSlotID(User));
	if (Slot.size() == 0)
	{
		RequestSlotInfos(Session_SN, &Slot, 0x12, GetAssociatedSlotID(User));
		if (Slot.size() == 0)
		{
			printf("Unable to get Slot Info.. Aborting..\n");
			ExitProcess(0);
		}
	}

	Hosts = *(Slot.front().SNodes);
	
	while (!(Hosts.empty()))
	{
		CurSN = Hosts.front();
		BaseSz = 0x14E;

		ZeroMemory(Request, 0xFFF);

		TransID = BytesRandomWord();
		PHeader = (ProbeHeader *)Request;
		PHeader->TransID = htons(TransID);
		PHeader->PacketType = PKT_TYPE_OBFSUK;
		PHeader->IV = htonl(GenIV());

		PRequest = Request + sizeof(*PHeader);
		Mark = PRequest;

		WriteValue(&PRequest, BaseSz);
		WriteValue(&PRequest, 0x61);

		*PRequest++ = RAW_PARAMS;
		WriteValue(&PRequest, 0x01);

		ObjDirBlob.Family = OBJ_FAMILY_BLOB;
		ObjDirBlob.Id = OBJ_ID_DIRBLOB;
		ObjDirBlob.Value.Memory.Memory = DirBlob;
		ObjDirBlob.Value.Memory.MsZ = 0x148;
		WriteObject(&PRequest, ObjDirBlob);

		PSize = (uint)(PRequest - Mark);

		PHeader->Crc32 = htonl(crc32(Mark, PSize, -1));

		//showmem(Request, sizeof(ProbeHeader) + PSize);

		Cipher(Mark, PSize, htonl(my_public_ip), htonl(inet_addr(CurSN.ip)), htons(PHeader->TransID), htonl(PHeader->IV), 0);

		if (SendPacket(SNUDPSock, CurSN, Request, sizeof(ProbeHeader) + PSize))
		{
			struct in_addr	PublicIP;

			PublicIP.S_un.S_addr = my_public_ip;
			if (UnCipherObfuscated(RecvBuffer, RecvBufferSz, inet_ntoa(PublicIP), CurSN.ip) == 0)
			{
				printf("Unable to uncipher Packet..\n");
				goto Skip;
			}
			printf("Ack Received..\n");
			//showmem(RecvBuffer, RecvBufferSz);
			//printf("\n\n");
		}
		else
		{
			printf("No Response to DirBlob BroadCast..\n");
			goto Skip;
		}
Skip:
		Hosts.pop();
	}
	printf("\n");
}