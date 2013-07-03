#include "ParentNode.h"

SOCKET			SNUDPSock;

uint			GetAssociatedSlotID(char *User)
{
	uint		*IUser;
	size_t		Len = strlen(User);
	uint		Idx, X, Salt;

	IUser = (uint *)malloc((Len + 1) * sizeof(uint));
	ZeroMemory(IUser, (Len + 1) * sizeof(uint));
	for (Idx = 0; Idx < Len; Idx++)
		IUser[Idx] = (uint)User[Idx];
	Idx = 0;
	X = 1;
	Salt = -1;
	while (IUser[Idx] > 0x20)
	{
		X = X + X * 4;
		minicrc32(IUser[Idx], &Salt);
		if (!(X < 0x800))
			break;
		Idx++;
	}
	Salt &= 0xFFFF;
	Salt &= 0x7FF;

	return (Salt);
}

void			CacheOnlineStatus(Host CurHost, char *User)
{
	/*uchar		Request[0xFFF] = {0};
	ushort		TransID;
	uchar		*PRequest, *Mark;
	uint		UserCrc, UnkCrc;
	ObjectDesc	ObjNbr;
	
	UserCrc = crc32((const uchar *)User, strlen(User), -1);
	UnkCrc = 0x69A1A400;
	PRequest = Request;
	
	TransID = BytesRandomWord();
	*PRequest++ = 0x00;
	*(unsigned short *)PRequest = htons(TransID);
	PRequest += 2;
	Mark = PRequest;
	WriteValue(&PRequest, 0x14 + GetWrittenSz(UserCrc) + GetWrittenSz(UnkCrc));
	WriteValue(&PRequest, 0x3A9);

	*PRequest++ = RAW_PARAMS;
	WriteValue(&PRequest, 0x06);
	
	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x02;
	ObjNbr.Value.Nbr = UserCrc;
	WriteObject(&PRequest, ObjNbr);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x0A;
	ObjNbr.Value.Nbr = 0x00;
	WriteObject(&PRequest, ObjNbr);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x0B;
	ObjNbr.Value.Nbr = UnkCrc;
	WriteObject(&PRequest, ObjNbr);*/

	//Skipped..
}

void			RequestSlotInfos(Host Session_SN, queue<SlotInfo> *Slots, int NbAddrs, uint SlotID)
{
	uchar		Request[0xFFF] = {0};
	ushort		TransID;
	uchar		*PRequest, *Mark;
	ObjectDesc	ObjNbr;

	PRequest = Request;
	
	TransID = BytesRandomWord();
	*PRequest++ = 0x00;
	*(unsigned short *)PRequest = htons(TransID);
	PRequest += 2;
	Mark = PRequest;
	WriteValue(&PRequest, 0x08 + GetWrittenSz(SlotID) + GetWrittenSz(NbAddrs));
	WriteValue(&PRequest, 0x32);
	*(unsigned short *)PRequest = htons(TransID - 1);
	PRequest += 2;
	
	*PRequest++ = RAW_PARAMS;
	WriteValue(&PRequest, 0x02);
	
	ObjNbr.Family = OBJ_FAMILY_NBR; //SLOT ID
	ObjNbr.Id = 0x00;
	ObjNbr.Value.Nbr = SlotID;
	WriteObject(&PRequest, ObjNbr);

	ObjNbr.Family = OBJ_FAMILY_NBR; //NUMBER OF ADDRESS
	ObjNbr.Id = 0x05;
	ObjNbr.Value.Nbr = NbAddrs;
	WriteObject(&PRequest, ObjNbr);

	*Request = (uchar)(PRequest - Request) - 1;
	*Request <<= 1;

	printf("Sending slot #%d info request..\n", SlotID);
	//showmem(Request, (uint)(PRequest - Request));

	CipherTCP(&(Keys.SendStream), Request, 3);
	CipherTCP(&(Keys.SendStream), Request + 3, (uint)(PRequest - Request) - 3);

	if (SendPacketTCP(Session_SN.socket, Session_SN, Request, (uint)(PRequest - Request), HTTPS_PORT, &(Session_SN.Connected)))
	{
		CipherTCP(&(Keys.RecvStream), RecvBuffer, RecvBufferSz);
		
		printf("Got slotsinfo..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		//printf("\n\n");
	}
	else
	{
		printf("No response to request..\n");
		return ;
	}

	uchar		*Browser;
	SResponse	Response;
	int			DecState = 0;
	int			NbGot = 0;

	Browser = RecvBuffer;

	while (RecvBufferSz > 0)
	{
		Response.Objs = NULL;
		Response.NbObj = 0;
		TCPResponseManager(&Browser, (uint *)&RecvBufferSz, &Response);
		switch (Response.Cmd / 8)
		{
		case CMD_SLOTINFOS:
			SlotInfo	Slot;
	
			Slot.SNodes = new queue<Host>;

			for (uint Idx = 0; Idx < Response.NbObj; Idx++)
			{
				switch (Response.Objs[Idx].Id)
				{
				case OBJ_ID_SLOTID:
					Slot.SlotID = Response.Objs[Idx].Value.Nbr;
					DecState += 1;
					break;
				case OBJ_ID_SLOTNBSN:
					Slot.NbSN = Response.Objs[Idx].Value.Nbr;
					DecState += 1;
					break;
				case OBJ_ID_SLOTSNADDR:
					Slot.SNodes->push(Response.Objs[Idx].Value.Addr);
					NbGot++;
					DecState += 1;
					break;
				default :
					printf("Unexpected Object %d:%d\n", Response.Objs[Idx].Family, Response.Objs[Idx].Id);
					break;
				}
			}
			if (DecState >= 3)
			{
				Slots->push(Slot);
				DecState = 0;
			}
			printf("%d Addrs Received..\n", NbGot);
			break;
		default:
			printf("Unmanaged Cmd %d\n", Response.Cmd / 8);
			break;
		}
	}

	printf("\n\n");
	return ;
}

void			RequestSlotBlocInfos(Host Session_SN, queue<SlotInfo> *Slots, int NbSlots, int NbAddrs)
{
	uchar		Request[0xFFF] = {0};
	ushort		TransID;
	uchar		*PRequest, *Mark;
	ObjectDesc	ObjNbr;
	
	PRequest = Request;
	
	TransID = BytesRandomWord();
	*PRequest++ = 0x00;
	*(unsigned short *)PRequest = htons(TransID);
	PRequest += 2;
	Mark = PRequest;
	WriteValue(&PRequest, 0x08 + GetWrittenSz(NbSlots) + GetWrittenSz(NbAddrs));
	WriteValue(&PRequest, 0x32);
	*(unsigned short *)PRequest = htons(TransID - 1);
	PRequest += 2;
	
	*PRequest++ = RAW_PARAMS;
	WriteValue(&PRequest, 0x02);
	
	ObjNbr.Family = OBJ_FAMILY_NBR; //NUMBER OF SLOTS
	ObjNbr.Id = 0x04;
	ObjNbr.Value.Nbr = NbSlots;
	WriteObject(&PRequest, ObjNbr);

	ObjNbr.Family = OBJ_FAMILY_NBR; //NUMBER OF ADDRESS
	ObjNbr.Id = 0x05;
	ObjNbr.Value.Nbr = NbAddrs;
	WriteObject(&PRequest, ObjNbr);

	*Request = (uchar)(PRequest - Request) - 1;
	*Request <<= 1;

	printf("Sending slotsinfo request..\n");
	//showmem(Request, (uint)(PRequest - Request));

	CipherTCP(&(Keys.SendStream), Request, 3);
	CipherTCP(&(Keys.SendStream), Request + 3, (uint)(PRequest - Request) - 3);

	if (SendPacketTCP(Session_SN.socket, Session_SN, Request, (uint)(PRequest - Request), HTTPS_PORT, &(Session_SN.Connected)))
	{
		CipherTCP(&(Keys.RecvStream), RecvBuffer, RecvBufferSz);
		
		printf("Got slotsinfo..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		//printf("\n\n");
	}
	else
	{
		printf("No response to request..\n");
		return ;
	}

	uchar		*Browser;
	SResponse	Response;
	int			DecState = 0;
	int			NbGot = 0;
		
	Browser = RecvBuffer;

	while (RecvBufferSz > 0)
	{
		Response.Objs = NULL;
		Response.NbObj = 0;
		TCPResponseManager(&Browser, (uint *)&RecvBufferSz, &Response);
		switch (Response.Cmd / 8)
		{
		case CMD_SLOTINFOS:
			SlotInfo	Slot;

			Slot.SNodes = new queue<Host>;

			for (uint Idx = 0; Idx < Response.NbObj; Idx++)
			{
				switch (Response.Objs[Idx].Id)
				{
				case OBJ_ID_SLOTID:
					Slot.SlotID = Response.Objs[Idx].Value.Nbr;
					DecState += 1;
					break;
				case OBJ_ID_SLOTNBSN:
					Slot.NbSN = Response.Objs[Idx].Value.Nbr;
					DecState += 1;
					break;
				case OBJ_ID_SLOTSNADDR:
					Slot.SNodes->push(Response.Objs[Idx].Value.Addr);
					DecState += 1;
					break;
				default :
					printf("Unexpected Object %d:%d\n", Response.Objs[Idx].Family, Response.Objs[Idx].Id);
					break;
				}
			}
			if (DecState >= 3)
			{
				Slots->push(Slot);
				DecState = 0;
				NbGot++;
			}
			printf("%d Slots Received..\n", NbGot);
			break;
		default:
			printf("Unmanaged Cmd %d\n", Response.Cmd / 8);
			break;
		}
	}

	printf("\n\n");
	return ;
}

void				FillSlotsListSN(Host Session_SN, SlotInfo *SlotsList, size_t NbSlots)
{
	uchar		Request[0xFFFF];
	ushort		TransID;
	uchar		*PRequest, *Mark;
	uint		LGIdx, Idx, Size, SizeSz, NbGot, NbAddrs;
	size_t		NbSlotsSave;
	ObjectDesc	ObjNbr;
	
	NbGot = NbAddrs = LGIdx = 0;
	NbSlotsSave = NbSlots;

	while (NbSlots)
	{
		PRequest = Request;
		ZeroMemory(Request, 0xFFFF);
		TransID = BytesRandomWord();
		if (0xFFFF - TransID < 0x1000)
			TransID -= 0x1000;
		
		for (Idx = 0; (Idx < NbSlots) && (Idx < 30); Idx++)
		{
			if (Idx == 0)
			{
				*(unsigned short *)PRequest = htons(TransID);
				PRequest += 2;
			}
			Mark = PRequest;
			WriteValue(&PRequest, 0x08 + GetWrittenSz(SlotsList[LGIdx].SlotID) + GetWrittenSz(0x06));
			WriteValue(&PRequest, 0x32);
			*(unsigned short *)PRequest = (Idx == 0) ? htons(TransID - 1) : htons(TransID);
			PRequest += 2;
			
			*PRequest++ = RAW_PARAMS;
			WriteValue(&PRequest, 0x02);
			
			ObjNbr.Family = OBJ_FAMILY_NBR; //SLOT ID
			ObjNbr.Id = 0x00;
			ObjNbr.Value.Nbr = SlotsList[LGIdx].SlotID;
			WriteObject(&PRequest, ObjNbr);

			ObjNbr.Family = OBJ_FAMILY_NBR; //NUMBER OF ADDRESS
			ObjNbr.Id = 0x05;
			ObjNbr.Value.Nbr = 0x06;
			WriteObject(&PRequest, ObjNbr);

			LGIdx++;
			TransID++;
		}

		Size = (uint)(PRequest - Request);
		SizeSz = GetWrittenSz(Size << 1);

		PRequest = Request;
		memmove_s(Request + SizeSz, 0xFFFF, Request, 0xFFFF - SizeSz);
		WriteValue(&PRequest , Size << 1);

		Size += SizeSz;
		
		//showmem(Request, Size);
		CipherTCP(&(Keys.SendStream), Request, 3);
		CipherTCP(&(Keys.SendStream), Request + 3, Size - 3);

		printf("Sending SlotsList Infos request..\n");

		if (SendPacketTCP(Session_SN.socket, Session_SN, Request, Size, HTTPS_PORT, &(Session_SN.Connected)))
		{
			CipherTCP(&(Keys.RecvStream), RecvBuffer, RecvBufferSz);
			
			printf("Got SlotsList Infos Response..\n");
			//showmem(RecvBuffer, RecvBufferSz);
			//printf("\n\n");
		}
		else
		{
			printf("No response to request..\n");
			return ;
		}

		uchar		*Browser;
		SResponse	Response;
		int			DecState, Suite;
		
		Browser = RecvBuffer;
		DecState = Suite = 0;

		while (RecvBufferSz > 0)
		{
			Response.Objs = NULL;
			Response.NbObj = 0;
			TCPResponseManager(&Browser, (uint *)&RecvBufferSz, &Response);
			switch (Response.Cmd / 8)
			{
			case CMD_SLOTINFOS:
				uint	SlotID, SlotIdx, Idx;
				
				Idx = 0;
				SlotID = SlotIdx = 0xFFFFFFFF;
				for (Idx = 0; Idx < Response.NbObj; Idx++)
				{
					switch (Response.Objs[Idx].Id)
					{
					case OBJ_ID_SLOTID:
						SlotID = Response.Objs[Idx].Value.Nbr;
						Idx = Response.NbObj;
						break;
					default:
						break;
					}
				}

				for (Idx = 0; Idx < NbSlotsSave; Idx++)
				{
					if ((SlotsList[Idx].SlotID == SlotID) && (SlotsList[Idx].NbSN == 0))
					{
						SlotIdx = Idx;
						break;
					}
				}

				if ((SlotID != 0xFFFFFFFF) && (SlotIdx != 0xFFFFFFFF))
				{
					for (Idx = 0; Idx < Response.NbObj; Idx++)
					{	
						switch (Response.Objs[Idx].Id)
						{
						case OBJ_ID_SLOTSNADDR:
							SlotsList[SlotIdx].SNodes->push(Response.Objs[Idx].Value.Addr);
							SlotsList[SlotIdx].NbSN += 1;
							NbAddrs += 1;
							break;
						default:
							break;
						}
					}
					NbGot += 1;
				}
				break;
			default:
				printf("Unmanaged Cmd %d\n", Response.Cmd / 8);
				break;
			}
		}
		NbSlots -= Idx;
	}
	
	printf("%d Slots Received for %d asked (%d Addresses)..\n\n", NbGot, NbSlotsSave, NbAddrs);
}

void				GetSNode(Host Session_SN, char *User, queue<Host> *Hosts, int NbAddrs, uint SlotID)
{
	uchar			Request[0xFFF];
	ProbeHeader		*PHeader;
	ushort			TransID;
	uchar			*PRequest, *Mark;
	int				BaseSz;
	uint			PSize;
	ObjectDesc		ObjNbr, ObjUser, ObjMiscDatas;
	sockaddr_in		LocalBind;
	int				UncRes;

	SNUDPSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	ZeroMemory((char *)&LocalBind, sizeof(LocalBind));
	LocalBind.sin_family = AF_INET;
	LocalBind.sin_addr.s_addr = htonl(INADDR_ANY);
	LocalBind.sin_port = htons(DEF_LPORT);
	bind(SNUDPSock, (struct sockaddr *)&LocalBind, sizeof(LocalBind));
	
	BaseSz = 0x16 + (int)strlen(User);

	queue<SlotInfo>	Slot;

	RequestSlotInfos(Session_SN, &Slot, 0x5, SlotID);
	if (Slot.size() == 0)
	{
		printf("Unable to get Slot Info.. Aborting..\n");
		ExitProcess(0);
	}

	while (!(Slot.empty()))
	{
		while (!(Slot.front().SNodes->empty()))
		{
			Host	CurSN;

			CurSN = Slot.front().SNodes->front();
			printf("Confirming Supernode %s:%d\n", CurSN.ip, CurSN.port);
		
			ZeroMemory(Request, 0xFFF);

			TransID = BytesRandomWord();
			PHeader = (ProbeHeader *)Request;
			PHeader->TransID = htons(TransID);
			PHeader->PacketType = PKT_TYPE_OBFSUK;
			PHeader->IV = htonl(GenIV());

			PRequest = Request + sizeof(*PHeader);
			Mark = PRequest;

			WriteValue(&PRequest, BaseSz);
			WriteValue(&PRequest, 0x72);
			*(unsigned short *)PRequest = htons(TransID - 1);
			PRequest += 2;
		
			*PRequest++ = RAW_PARAMS;
			WriteValue(&PRequest, 0x02);

			*PRequest++ = 0x05;
			WriteValue(&PRequest, 0x00);

			*PRequest++ = RAW_PARAMS;
			WriteValue(&PRequest, 0x03);

			ObjNbr.Family = OBJ_FAMILY_NBR;
			ObjNbr.Id = 0x02;
			ObjNbr.Value.Nbr = 0x10;
			WriteObject(&PRequest, ObjNbr);

			ObjNbr.Family = OBJ_FAMILY_NBR;
			ObjNbr.Id = 0x01;
			ObjNbr.Value.Nbr = 0x00;
			WriteObject(&PRequest, ObjNbr);

			ObjUser.Family = OBJ_FAMILY_STRING;
			ObjUser.Id = OBJ_ID_USER2SEARCH; //NOT SEARCH
			ObjUser.Value.Memory.Memory = (uchar *)User;
			ObjUser.Value.Memory.MsZ = (int)strlen(User);
			WriteObject(&PRequest, ObjUser);

			uint	MiscDatas[] = {0x10, 0x0B};
			ObjMiscDatas.Family = OBJ_FAMILY_INTLIST;
			ObjMiscDatas.Id = 0x01;
			ObjMiscDatas.Value.Memory.Memory = (uchar *)(&MiscDatas[0]);
			ObjMiscDatas.Value.Memory.MsZ = 0x02;
			WriteObject(&PRequest, ObjMiscDatas);

			PSize = (uint)(PRequest - Mark);

			PHeader->Crc32 = htonl(crc32(Mark, PSize, -1));

			Cipher(Mark, PSize, htonl(my_public_ip), htonl(inet_addr(CurSN.ip)), htons(PHeader->TransID), htonl(PHeader->IV), 0);

			if (SendPacket(SNUDPSock, CurSN, Request, sizeof(ProbeHeader) + PSize))
			{
				struct in_addr	PublicIP;
		
				PublicIP.S_un.S_addr = my_public_ip;
				UncRes = UnCipherObfuscated(RecvBuffer, RecvBufferSz, inet_ntoa(PublicIP), CurSN.ip);
				if (UncRes == 0)
				{
					printf("Unable to uncipher Packet..\n");
					
					showmem(RecvBuffer, RecvBufferSz);
					printf("\n\n");

					goto Skip;
				}
				if (UncRes == -1)
				{
					printf("Supernode Confirmed..\n");
					CurSN.socket = SNUDPSock;
					Hosts->push(CurSN);
				}
			}
			else
			{
				printf("No Response to SN_Confirm.. Skipping\n");
				goto Skip;
			}

			if (UncRes != -1)
			{
				uchar		*Browser;
				SResponse	Response;
			
				Browser = RecvBuffer;

				Response.Objs = NULL;
				Response.NbObj = 0;
				UDPResponseManager(&Browser, (uint *)&RecvBufferSz, &Response);
				switch (Response.Cmd / 8)
				{
				case CMD_SNREGOK:
					printf("Supernode Confirmed..\n");
					CurSN.socket = SNUDPSock;
					Hosts->push(CurSN);
					break;
				default :
					printf("Unmanaged Cmd %d\n", Response.Cmd / 8);
					break;
				}
			}
Skip:
			Slot.front().SNodes->pop();
		}
		Slot.pop();
	}
	
	printf("\n\n");
	return ;
}

void	PerformFireWallTest(Host ParentNode)
{
	uchar		Request[0xFF];
	ushort		TransID;
	uchar		*PRequest, *Mark;
	uint		Size, SizeSz;

	PRequest = Request;

	ZeroMemory(Request, 0xFF);
	TransID = BytesRandomWord();
	if (0xFFFF - TransID < 0x1000)
		TransID -= 0x1000;
	
	*(unsigned short *)PRequest = htons(TransID);
	PRequest += 2;

	Mark = PRequest;
	WriteValue(&PRequest, 0x04);
	WriteValue(&PRequest, 0x142);
	*(unsigned short *)PRequest = htons(TransID - 1);
	PRequest += 2;
	
	*PRequest++ = RAW_PARAMS;
	WriteValue(&PRequest, 0x00);

	Size = (uint)(PRequest - Request);
	SizeSz = GetWrittenSz(Size << 1);

	PRequest = Request;
	memmove_s(Request + SizeSz, 0xFF, Request, 0xFF - SizeSz);
	WriteValue(&PRequest , Size << 1);

	Size += SizeSz;
	
	//showmem(Request, Size);
	CipherTCP(&(Keys.SendStream), Request, 3);
	CipherTCP(&(Keys.SendStream), Request + 3, Size - 3);

	printf("Sending Firewall Test Request..\n");

	Blocking = 1;
	if (SendPacketTCP(ParentNode.socket, ParentNode, Request, Size, HTTPS_PORT, &(ParentNode.Connected)))
	{
		CipherTCP(&(Keys.RecvStream), RecvBuffer, RecvBufferSz);
		
		printf("Got Firewall Test Response..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		//printf("\n\n");
	}
	else
	{
		printf("No response to request..\n");
		return ;
	}

	uchar		*Browser;
	SResponse	Response;
	
	Browser = RecvBuffer;

	while (RecvBufferSz > 0)
	{
		Response.Objs = NULL;
		Response.NbObj = 0;
		TCPResponseManager(&Browser, (uint *)&RecvBufferSz, &Response);
		switch (Response.Cmd / 8)
		{
		case CMD_FIREWALL_RES:
			uint	TestID, State;
			Host	Tester;

			State = 0;
			for (uint Idx = 0; Idx < Response.NbObj; Idx++)
			{
				switch (Response.Objs[Idx].Id)
				{
				case OBJ_ID_FWTESTID:
					TestID = Response.Objs[Idx].Value.Nbr;
					State++;
					break;
				case OBJ_ID_FWTESTER:
					Tester = Response.Objs[Idx].Value.Addr;
					State++;
					break;
				default:
					printf("Non Critical Object %d:%d\n", Response.Objs[Idx].Family, Response.Objs[Idx].Id);
					break;
				}
			}
			if (State == 2)
				printf("FW Test (ID #%d) : Confirmed (by %s:%d)\n", TestID, Tester.ip, Tester.port);
			break;
		default:
			printf("Unamanged Cmd $%d..\n", Response.Cmd / 8);
			break;
		}
	}
	printf("\n");
}

void	SubmitUpdatedProps(Host ParentNode)
{
	uchar		Request[0xFFF];
	ushort		TransID;
	uchar		*PRequest, *Mark;
	uint		Size, SizeSz;
	
	unsigned char PropsNStats[] = {
	0x00, 0x06, 0x00, 0x00, 0x07, 0x00, 0x00, 0x08, 0x01, 0x03, 0x0E, 0x30, 0x2F, 0x32, 0x2E, 0x35, 
	0x2E, 0x30, 0x2E, 0x31, 0x35, 0x31, 0x00, 0x00, 0x0F, 0xBF, 0xB7, 0xFF, 0xB3, 0x04, 0x00, 0x00, 
	0x22, 0x00, 0x01, 0xBE, 0x07, 0x00, 0x0D, 0x02, 0x00, 0x15, 0x87, 0x8A, 0xFE, 0xB3, 0x04, 0x00, 
	0x98, 0x01, 0x00, 0x00, 0x7D, 0x05, 0x00, 0x96, 0x01, 0x01, 0x00, 0x97, 0x01, 0x01, 0x00, 0x7E, 
	0x01, 0x00, 0x0B, 0x00, 0x00, 0x05, 0xE8, 0x07, 0x00, 0x02, 0x00, 0x00, 0x03, 0x00, 0x00, 0x09, 
	0x00, 0x00, 0x0C, 0x07, 0x00, 0x0A, 0x5C, 0x00, 0x91, 0x01, 0x0A, 0x00, 0x92, 0x01, 0x00, 0x00, 
	0x93, 0x01, 0x00, 0x00, 0x94, 0x01, 0x00, 0x00, 0x95, 0x01, 0x00, 0x00, 0x81, 0x01, 0x00, 0x00, 
	0x76, 0x00, 0x00, 0x77, 0x00, 0x00, 0x8D, 0x01, 0xCC, 0x08, 0x00, 0x85, 0x01, 0x03, 0x00, 0x8F, 
	0x01, 0x02, 0x00, 0x87, 0x01, 0x02, 0x00, 0x9A, 0x01, 0x00, 0x00, 0x9B, 0x01, 0x00, 0x00, 0x9C, 
	0x01, 0x00, 0x00, 0x9D, 0x01, 0x00, 0x00, 0x9E, 0x01, 0x00, 0x00, 0x99, 0x01, 0x00, 0x00, 0x12, 
	0x4E, 0x00, 0x86, 0x01, 0x04, 0x00, 0x04, 0xDC, 0x01, 0x20, 0xB1, 0x02, 0x41, 0x0A, 0x00, 0x62, 
	0x01, 0x00, 0x54, 0x01, 0x00, 0x55, 0x06, 0x00, 0x56, 0x00, 0x00, 0x57, 0x01, 0x00, 0x58, 0x00, 
	0x00, 0x59, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x5B, 0x00, 0x00, 0x5C, 0x00
	};

	PRequest = Request;

	ZeroMemory(Request, 0xFFF);
	TransID = BytesRandomWord();
	if (0xFFFF - TransID < 0x1000)
		TransID -= 0x1000;
	
	*(unsigned short *)PRequest = htons(TransID);
	PRequest += 2;

	Mark = PRequest;
	WriteValue(&PRequest, sizeof(PropsNStats) + 2);
	WriteValue(&PRequest, 0x129);
	
	*PRequest++ = RAW_PARAMS;
	WriteValue(&PRequest, 0x2A);

	memcpy_s(PRequest, 0xFFF, PropsNStats, sizeof(PropsNStats));
	PRequest += sizeof(PropsNStats);

	Size = (uint)(PRequest - Request);
	SizeSz = GetWrittenSz(Size << 1);

	PRequest = Request;
	memmove_s(Request + SizeSz, 0xFFF, Request, 0xFFF - SizeSz);
	WriteValue(&PRequest , Size << 1);

	Size += SizeSz;
	
	showmem(Request, Size);
	CipherTCP(&(Keys.SendStream), Request, 3);
	CipherTCP(&(Keys.SendStream), Request + 3, Size - 3);

	printf("Submitting Pros'n'Stats (Updated)..\n");

	if (SendPacketTCP(ParentNode.socket, ParentNode, Request, Size, HTTPS_PORT, &(ParentNode.Connected)))
	{
		CipherTCP(&(Keys.RecvStream), RecvBuffer, RecvBufferSz);
		
		printf("Got Ack..\n");
		showmem(RecvBuffer, RecvBufferSz);
		printf("\n\n");
	}
	else
	{
		printf("No response to request..\n");
		return ;
	}
	printf("\n");
}