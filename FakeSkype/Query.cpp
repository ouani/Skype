#include "Query.h"

void	PingReply(Host Session_SN, ushort Reply2ID)
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
	
	CipherTCP(&(Keys.SendStream), Request, 3);
	CipherTCP(&(Keys.SendStream), Request + 3, Size - 3);

	printf("Sending Ping Response..\n");

	NoWait = 1;
	SendPacketTCP(Session_SN.socket, Session_SN, Request, Size, HTTPS_PORT, &(Session_SN.Connected));
}

void	UDPTestReply(Host Session_SN, ushort Reply2ID, Host Tested)
{
	uchar		Request[0xFFF];
	uchar		Buffer[LOCATION_SZ] = {0};
	ushort		TransID;
	uchar		*PRequest, *Mark;
	uint		Size, SizeSz;
	ObjectDesc	ObjLocation, ObjAddr;

	PRequest = Request;

	ZeroMemory(Request, 0xFFF);
	TransID = BytesRandomWord();
	if (0xFFFF - TransID < 0x1000)
		TransID -= 0x1000;
	
	*(unsigned short *)PRequest = htons(TransID);
	PRequest += 2;

	Mark = PRequest;
	WriteValue(&PRequest, 0x2C);
	WriteValue(&PRequest, 0x1CB);
	*(unsigned short *)PRequest = htons(Reply2ID);
	PRequest += 2;
	
	*PRequest++ = RAW_PARAMS;
	WriteValue(&PRequest, 0x03);

	BuildLocationBlob(Session_SN, &Buffer[0]);

	ObjLocation.Family = OBJ_FAMILY_BLOB;
	ObjLocation.Id = 0x00;
	ObjLocation.Value.Memory.Memory = Buffer;
	ObjLocation.Value.Memory.MsZ = LOCATION_SZ;
	WriteObject(&PRequest, ObjLocation);

	struct in_addr	PublicIP;
	PublicIP.S_un.S_addr = my_public_ip;

	ObjAddr.Family = OBJ_FAMILY_NETADDR;
	ObjAddr.Id = OBJ_ID_TESTED;
	strcpy_s(ObjAddr.Value.Addr.ip, MAX_IP_LEN + 1, inet_ntoa(PublicIP));
	ObjAddr.Value.Addr.port = GetListeningPort();
	WriteObject(&PRequest, ObjAddr);

	ObjAddr.Family = OBJ_FAMILY_NETADDR;
	ObjAddr.Id = OBJ_ID_TESTED;
	ObjAddr.Value.Addr = Tested;
	WriteObject(&PRequest, ObjAddr);

	Size = (uint)(PRequest - Request);
	SizeSz = GetWrittenSz(Size << 1);

	PRequest = Request;
	memmove_s(Request + SizeSz, 0xFF, Request, 0xFF - SizeSz);
	WriteValue(&PRequest , Size << 1);

	Size += SizeSz;
	
	CipherTCP(&(Keys.SendStream), Request, 3);
	CipherTCP(&(Keys.SendStream), Request + 3, Size - 3);

	printf("Sending UDPTest Response..\n");

	NoWait = 1;
	SendPacketTCP(Session_SN.socket, Session_SN, Request, Size, HTTPS_PORT, &(Session_SN.Connected));
}

void	SessionPropReply(Host Session_SN, ushort Reply2ID)
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
	WriteValue(&PRequest, 0x233);
	*(unsigned short *)PRequest = htons(Reply2ID);
	PRequest += 2;
	
	*PRequest++ = RAW_PARAMS;
	WriteValue(&PRequest, 0x00);

	Size = (uint)(PRequest - Request);
	SizeSz = GetWrittenSz(Size << 1);

	PRequest = Request;
	memmove_s(Request + SizeSz, 0xFF, Request, 0xFF - SizeSz);
	WriteValue(&PRequest , Size << 1);

	Size += SizeSz;
	
	CipherTCP(&(Keys.SendStream), Request, 3);
	CipherTCP(&(Keys.SendStream), Request + 3, Size - 3);

	printf("Sending Session Accept..\n");

	NoWait = 1;
	SendPacketTCP(Session_SN.socket, Session_SN, Request, Size, HTTPS_PORT, &(Session_SN.Connected));
}

void	HandleQuery(Host Session_SN, uchar *Query, int Size)
{
	uchar		*Browser;
	SResponse	Response;
	CLocation	TesterLocation;
	Host		Tested;
	SessProp	*SessionProposal;
	
	Browser = Query;

	while (Size > 0)
	{
		Response.Objs = NULL;
		Response.NbObj = 0;
		TCPResponseManager(&Browser, (uint *)&Size, &Response);

		switch (Response.Cmd / 8)
		{
		case CMD_QUERY_IPING:
			printf("Received Incoming Initial Ping..\n");
			for (uint Idx = 0; Idx < Response.NbObj; Idx++)
			{
				switch (Response.Objs[Idx].Id)
				{
				case OBJ_ID_PINGER:
					printf("Ping Coming From : %s.. Let's Reply..\n", Response.Objs[Idx].Value.Memory.Memory);
					PingReply(Session_SN, Response.Reply2ID);
					break;
				default:
					break;
				}
			}
			break;
		case CMD_QUERY_SESSION:
			printf("Received session proposal..\n");
		
			SessionProposal = (SessProp *)malloc(sizeof(SessProp));
			SessionProposal->Relays = new queue<Host>;
			SessionProposal->SessID = BytesRandomWord() % 0x7FFF;
			*(uint *)(SessionProposal->PeerChallenge) = BytesRandom();
			*(uint *)(SessionProposal->PeerChallenge + 4) = BytesRandom();

			printf("Challenge to propose to Peer : ");
			showmem((uchar *)SessionProposal->PeerChallenge, 0x08);

			SessionProposal->CreatedSID = 0x00;
			SessionProposal->LocalCreatedSID = 0x00;

			for (uint Idx = 0; Idx < Response.NbObj; Idx++)
			{
				if (Response.Objs[Idx].ObjListInfos.Id == -1)
				{
					switch(Response.Objs[Idx].Id)
					{
					case OBJ_ID_SESPROPOSER:
						LocationBlob2Location(Response.Objs[Idx].Value.Memory.Memory, &(SessionProposal->ProposerLocation), Response.Objs[Idx].Value.Memory.MsZ);
						printf("Proposer Node : ");
						DumpLocation(&(SessionProposal->ProposerLocation));
						break;
					case OBJ_ID_SESCHALLENG:
						printf("Session Challenge : ");
						showmem(Response.Objs[Idx].Value.Table, sizeof(Response.Objs[Idx].Value.Table));
						memcpy_s(SessionProposal->Challenge, sizeof(SessionProposal->Challenge), Response.Objs[Idx].Value.Table, sizeof(SessionProposal->Challenge));
						break;
					case OBJ_ID_PEERSESSID:
						printf("Peer Choosen Session ID : 0x%x\n", Response.Objs[Idx].Value.Nbr);
						SessionProposal->PeerSessID = Response.Objs[Idx].Value.Nbr;
					default:
						break;
					}
				}
			}

			uint		NbObjLists;
			Memory_U	RelaysInfos;
			
			RelaysInfos.Memory = (uchar *)malloc(0xFF);
			ZeroMemory(RelaysInfos.Memory, 0xFF);
			RelaysInfos.MsZ = 0xFF;
			Browser = RelaysInfos.Memory;

			NbObjLists = DefNbObjList(Response);
			for (uint Rank = 0; Rank < NbObjLists + 1; Rank++)
			{
				Host	Relay;
				uint	State, ObjOccur;

				State = ObjOccur = 0;
				for (uint Idx = 0; Idx < Response.NbObj; Idx++)
				{
					if ((Response.Objs[Idx].ObjListInfos.Id == 0x07) && (Response.Objs[Idx].ObjListInfos.Rank == Rank))
					{
						if (!ObjOccur)
						{
							memcpy_s(Browser, 0xFF, "\x05\x07\x41\x03", 0x04);
							Browser += 0x04;
							ObjOccur = 1;
						}
						WriteObject(&Browser, Response.Objs[Idx]);
						switch(Response.Objs[Idx].Id)
						{
						case OBJ_ID_RELAY:
							printf("Proposed Relay : %s:%d\n", Response.Objs[Idx].Value.Addr.ip, Response.Objs[Idx].Value.Addr.port);
							strcpy_s(Relay.ip, MAX_IP_LEN + 1, Response.Objs[Idx].Value.Addr.ip);
							Relay.port = Response.Objs[Idx].Value.Addr.port;
							State += 1;
							break;
						case OBJ_ID_SID2DEC:
							printf("Session To Declare on this relay : 0x%x\n", Response.Objs[Idx].Value.Nbr);
							Relay.SessionID2Declare = Response.Objs[Idx].Value.Nbr;
							State += 1;
						default:
							break;
						}
					}
				}
				if (State == 2)
					SessionProposal->Relays->push(Relay);
			}
			RelaysInfos.MsZ = (uint)(Browser - RelaysInfos.Memory);
			SessionProposal->RelaysInfos = RelaysInfos;

			printf("Accepted session.. Let's initialize..\n");

			uchar	RecvCopy[0xFFFF];
			int		RecvSzCopy;

			ZeroMemory(RecvCopy, 0xFFFF);
			memcpy_s(RecvCopy, 0xFFFF, Query, Size);
			RecvSzCopy = Size;

			SessionPropReply(Session_SN, Response.Reply2ID);
			InitSession(SessionProposal);

			ZeroMemory(RecvBuffer, 0xFFFF);
			memcpy_s(Query, 0xFFFF, RecvCopy, RecvSzCopy);
			Size = RecvSzCopy;			
			break;
		case CMD_QUERY_UDPTEST:
			printf("Received UDP Test report..\n");
			Tested.port = 0;
			for (uint Idx = 0; Idx < Response.NbObj; Idx++)
			{
				switch(Response.Objs[Idx].Id)
				{
				case OBJ_ID_TESTED:
					printf("Peer Tested my UDP Address : %s:%d\n", Response.Objs[Idx].Value.Addr.ip, Response.Objs[Idx].Value.Addr.port);
					if (Tested.port == 0)
						Tested = Response.Objs[Idx].Value.Addr;
					break;
				case OBJ_ID_TESTER:
					LocationBlob2Location(Response.Objs[Idx].Value.Memory.Memory, &TesterLocation, Response.Objs[Idx].Value.Memory.MsZ);
					printf("Tester Node : ");
					DumpLocation(&TesterLocation);
					printf("Should UDP Test %s:%d\n", TesterLocation.PVAddr.ip, TesterLocation.PVAddr.port);
					break;
				default:
					break;
				}
			}
			UDPTestReply(Session_SN, Response.Reply2ID, Tested);
			break;
		default:
			printf("Unhandled Query.. Sending ACK..\n");
			SendACK(Response.PacketID, Session_SN.socket, Session_SN, HTTPS_PORT, &(Session_SN.Connected), &Keys);
			break;
		}
		printf("\n");
	}
}