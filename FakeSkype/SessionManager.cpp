#include "SessionManager.h"

static int			Connected = 0;
static SOCKET		TCPSock;
static sockaddr_in	LocalBind;
static TCPKeyPair	RelayKeys;

CConsoleLogger		ThreadConsole;
SessProp			*SessionProposal;
uint				RelayOK = 0;

#define				TPRINTF	ThreadConsole.printf

//FIXME : PUT SYNCHRONISATION ON RECVBUFFER & ALL OVER THE CODE

int	ChkChallenge(Memory_U Solution, uchar *PeerChallenge, Memory_U RsaPubKey)
{
	RSA				*SkypeRSA;
	uchar			UnRSA[0xFFF];
	uchar			*PostProcessed;
	uint			PPsZ, Save;
	int				Suite;

	SkypeRSA = RSA_new();
	BN_hex2bn(&(SkypeRSA->n), Bin2HexStr(RsaPubKey.Memory, MODULUS_SZ));
	BN_hex2bn(&(SkypeRSA->e), "10001");
	PPsZ = Solution.MsZ;
	Solution.MsZ -= PPsZ;
	Save = PPsZ;
	PPsZ = 0x80;
	ZeroMemory(UnRSA, 0xFFF);
	PPsZ = RSA_public_decrypt(PPsZ, Solution.Memory, UnRSA, SkypeRSA, RSA_NO_PADDING);
	RSA_free(SkypeRSA);

	if (PPsZ == 0xFFFFFFFF)
		return (0);

	Suite = Save - PPsZ;
	Solution.Memory += PPsZ;
	PostProcessed = FinalizeLoginDatas(UnRSA, &PPsZ, (Suite > 0) ? Solution.Memory : NULL, Suite);

	if (PostProcessed == NULL)
	{
		printf("Bad Datas [METADATAS] Finalization..\n");
		return 0;
	}

	return (!!!memcmp(PostProcessed, PeerChallenge, 0x08));
}

int	GetAesFinalKeyPart(uchar *AesKeyPart, Memory_U KeyPartBlob)
{
	uchar			UnRSA[0xFFF];
	uint			PPsZ;

	ZeroMemory(UnRSA, 0xFFF);
	PPsZ = RSA_private_decrypt(KeyPartBlob.MsZ, KeyPartBlob.Memory, UnRSA, GLoginD.RSAKeys, RSA_NO_PADDING);

	if (PPsZ == 0xFFFFFFFF)
		return (0);

	SpecialSHA(UnRSA, PPsZ, AesKeyPart, 16);

	return (1);
}

uint	BuildUserPacket(Host Relay, uchar **Buffer, ushort InternTID, ushort Cmd, AesStream_S *AesStream, uint NbObj, ...)
{
	uchar		TmpDatas[0xFFF] = {0};
	uchar		*Mark, *Browser;
	uint		Size = 0, SizeSz = 0, Crc32 = 0;
	ushort		Crc16 = 0;
	ushort		TrickyID;
	ObjectDesc	Obj2Write;
	va_list		ap;

	if (InternTID == 0xFFFF)
	{
		InternTID = BytesRandomWord();
		if (0xFFFF - InternTID < 0x1000)
			InternTID -= 0x1000;

	}

	Browser = TmpDatas;
	Mark = Browser;

	WriteValue(&Browser, InternTID);
	WriteValue(&Browser, Cmd);

	*Browser++ = RAW_PARAMS;
	WriteValue(&Browser, NbObj);

	va_start(ap, NbObj);

	while (NbObj--)
	{
		Obj2Write = va_arg(ap, ObjectDesc);
		WriteObject(&Browser, Obj2Write);
	}

	va_end(ap);

	Crc16 = crc16(Mark, (uint)(Browser - Mark), 0);
	*Browser++ = *((uchar *)(&Crc16) + 1);
	*Browser++ = *((uchar *)(&Crc16) + 0);

	Size = (uint)(Browser - Mark);

	((uint *)AesStream->ivec)[0] = htonl(AesStream->AesSalt);
	((uint *)AesStream->ivec)[1] = htonl(AesStream->AesSalt);
	((uint *)AesStream->ivec)[3] = htonl(AesStream->IvecIdx << 0x10);
	AES_ctr128_encrypt(Mark, Mark, Size, &(AesStream->Key), AesStream->ivec, AesStream->ecount_buf, &(AesStream->Idx));
	AesStream->Idx = 0;
	AesStream->IvecIdx++;

	Crc32 = crc32(Mark, Size, -1);
	*Browser++ = *((uchar *)(&Crc32) + 0);
	*Browser++ = *((uchar *)(&Crc32) + 1);

	Size = (uint)(Browser - Mark);
	SizeSz = GetWrittenSz((Size + 1) + (Size + 1) + 5);

	TrickyID = (ushort)(((Relay.SessionID2Declare << 1) ^ crc32(Mark, Size, -1)) & 0xFFFF);

	Browser = TmpDatas;
	memmove_s(TmpDatas + SizeSz + 3, 0xFFF, TmpDatas, 0xFFF - SizeSz - 3);
	
	WriteValue(&Browser , (Size + 1) + (Size + 1) + 5);
	*Browser++ = 0x05;
	*Browser++ = *((uchar *)(&TrickyID) + 1);
	*Browser++ = *((uchar *)(&TrickyID) + 0);

	Size += SizeSz + 3;

	CipherTCP(&(RelayKeys.SendStream), Mark, 3);
	CipherTCP(&(RelayKeys.SendStream), Mark + 3, Size - 3);

	memcpy_s(*Buffer, 0xFFF, TmpDatas, Size);
	*Buffer += Size;

	return (Size);
}

int		UserCommandManager(Host Relay, SessProp *SessionProposal, SResponse Response, uchar **BRBrowser, uint *BRSize)
{
	uint	Idx = 0;

	switch (Response.Cmd)
	{
	case CMD_USR_7A:			
		for (Idx = 0; Idx < Response.NbObj; Idx++)
		{
			/*if (Response.Objs[Idx].Id == 0x13)
				if (Response.Objs[Idx].Value.Nbr != 0x00)
					return (0);*/
		}

		*BRSize += BuildUserPacket(Relay, BRBrowser, Response.PacketID, 0x47, SessionProposal->AesStreamOut, 0);
		SessionProposal->AesStreamOut->IvecIdx = 0;

		cprintf(FOREGROUND_BLUE, "Session Successfully established..\n");

		break;
	case CMD_USR_7D:			
		printf("Cumulative capabilities received..\n");

		*BRSize += BuildUserPacket(Relay, BRBrowser, Response.PacketID, 0x47, SessionProposal->AesStreamOut, 0);
		SessionProposal->AesStreamOut->IvecIdx = 0;

		break;
	case CMD_USR_53:
		printf("Got AuthCert from Peer.. Valid Or Not ?..\n");

		for (Idx = 0; Idx < Response.NbObj; Idx++)
		{
			if (Response.Objs[Idx].Id == 0x03)
			{
				Memory_U	SentAuthCert;

				SentAuthCert = GetDirBlobMetaDatas(Response.Objs[Idx].Value.Memory.Memory, Response.Objs[Idx].Value.Memory.MsZ);

				if (strstr((char *)SentAuthCert.Memory, (char *)"buddy_authorized"))
					printf("Valid AuthCert..\n");
				else
					cprintf(FOREGROUND_RED, "Invalid AuthCert\n");
			}		
		}

		*BRSize += BuildUserPacket(Relay, BRBrowser, Response.PacketID, 0x47, SessionProposal->AesStreamOut, 0);
		SessionProposal->AesStreamOut->IvecIdx = 0;
		*BRSize += BuildUserPacket(Relay, BRBrowser, 0xFFFF, 0x58, SessionProposal->AesStreamOut, 0);
		SessionProposal->AesStreamOut->IvecIdx = 0;

		break;
	case CMD_USR_6D:
		*BRSize += BuildUserPacket(Relay, BRBrowser, Response.PacketID, 0x47, SessionProposal->AesStreamOut, 0);
		SessionProposal->AesStreamOut->IvecIdx = 0;

		if (ManageSessionCMD(Relay, SessionProposal, BRBrowser, Response, BRSize) == -1)
			return (0);

		break;
	case CMD_USR_47:
		printf("User ACK Received for packet 0x%x\n", Response.PacketID);
		break;
	case CMD_USR_7B:
		printf("Cmd 0x7B received..\n");

		*BRSize += BuildUserPacket(Relay, BRBrowser, Response.PacketID, 0x47, SessionProposal->AesStreamOut, 0);
		SessionProposal->AesStreamOut->IvecIdx = 0;

		break;
	case CMD_USR_58:
		printf("Cmd 0x58 (Fan Notification & Hint-ABout Stuffs) received..\n");

		*BRSize += BuildUserPacket(Relay, BRBrowser, Response.PacketID, 0x47, SessionProposal->AesStreamOut, 0);
		SessionProposal->AesStreamOut->IvecIdx = 0;

		break;
	case CMD_USR_4C:
		ObjectDesc	ObjNbr, ObjNbr2;

		printf("Cmd 0x4C (Session Properties Stuffs) received..\n");

		*BRSize += BuildUserPacket(Relay, BRBrowser, Response.PacketID, 0x47, SessionProposal->AesStreamOut, 0);
		SessionProposal->AesStreamOut->IvecIdx = 0;
		
		ObjNbr.Family = OBJ_FAMILY_NBR;
		ObjNbr.Id = 0x02;
		ObjNbr.Value.Nbr = 0x00;

		ObjNbr2.Family = OBJ_FAMILY_NBR;
		ObjNbr2.Id = 0x06;
		ObjNbr2.Value.Nbr = 0x00; //UNDEFINED

		*BRSize += BuildUserPacket(Relay, BRBrowser, 0xFFFF, 0x4D, SessionProposal->AesStreamOut, 2, ObjNbr, ObjNbr2);
		SessionProposal->AesStreamOut->IvecIdx = 0;
		
		break;
	default :
		printf("Unsupported UserCMD (0x%x)..\n", Response.Cmd);
		break;
	}
	return (1);
}

int	PeerAuthEnd(Host Relay)
{
	uchar		AesKeyInitBlob[32] = {0};
	uchar		AuthDatas[0xFFF] = {0};
	uchar		AesKeyPartSK[0x80] = {0};
	uchar		AesKeyPart[0x10] = {0};
	uchar		*Browser, *Mark;
	uint		Size = 0, Idx = 0, Crc32 = 0, SizeSz = 0;
	ushort		Crc16 = 0;
	ushort		InternTID, TrickyID;
	RSA			*SkypeRSA;
	ObjectDesc	ObjNbr, ObjAuthCert, ObjAesPart;

	Browser = AuthDatas;

	InternTID = BytesRandomWord();
	if (0xFFFF - InternTID < 0x1000)
		InternTID -= 0x1000;

	Mark = Browser;

	WriteValue(&Browser, InternTID ^ 0x768);
	WriteValue(&Browser, 0x57);

	*Browser++ = RAW_PARAMS;
	WriteValue(&Browser, 0x04);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x19;
	ObjNbr.Value.Nbr = 0x01;
	WriteObject(&Browser, ObjNbr);

	GenSessionKey(&(AesKeyPartSK[0]), 0x80);
	SpecialSHA(AesKeyPartSK, 0x80, &(SessionProposal->AesKeyBlob[16]), 0x10);

	SkypeRSA = RSA_new();
	BN_hex2bn(&(SkypeRSA->n), Bin2HexStr(SessionProposal->PeerContact->RsaPubKey.Memory, SessionProposal->PeerContact->RsaPubKey.MsZ));
	BN_hex2bn(&(SkypeRSA->e), "10001");
	RSA_public_encrypt(0x80, AesKeyPartSK, AesKeyPartSK, SkypeRSA, RSA_NO_PADDING);
	RSA_free(SkypeRSA);

	ObjAesPart.Family = OBJ_FAMILY_BLOB;
	ObjAesPart.Id = 0x06;
	ObjAesPart.Value.Memory.Memory = &AesKeyPartSK[0];
	ObjAesPart.Value.Memory.MsZ = 0x80;
	WriteObject(&Browser, ObjAesPart);

	ObjAuthCert.Family = OBJ_FAMILY_BLOB;
	ObjAuthCert.Id = 0x11;
	ObjAuthCert.Value.Memory = GetAuthCert(Contacts, SessionProposal->PeerContact);
	WriteObject(&Browser, ObjAuthCert);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x14;
	ObjNbr.Value.Nbr = 0x00;
	WriteObject(&Browser, ObjNbr);

	Crc16 = crc16(Mark, (uint)(Browser - Mark), 0);
	*Browser++ = *((uchar *)(&Crc16) + 1);
	*Browser++ = *((uchar *)(&Crc16) + 0);

	Size = (uint)(Browser - Mark);

	SessionProposal->AesStream->Idx = 0;
	SessionProposal->AesStream->AesSalt = 0;
	ZeroMemory(&(SessionProposal->AesStream->ivec)[0], AES_BLOCK_SIZE);
	ZeroMemory(&(SessionProposal->AesStream->ecount_buf)[0], AES_BLOCK_SIZE);

	SessionProposal->AesStream->IvecIdx = 0;
	AES_set_encrypt_key(AesKeyInitBlob, 256, &(SessionProposal->AesStream->Key));

	((uint *)(SessionProposal->AesStream->ivec))[3] = htonl(SessionProposal->AesStream->IvecIdx << 0x10);
	AES_ctr128_encrypt(Mark, Mark, Size, &(SessionProposal->AesStream->Key), &(SessionProposal->AesStream->ivec)[0], &(SessionProposal->AesStream->ecount_buf)[0], &(SessionProposal->AesStream->Idx));
	SessionProposal->AesStream->IvecIdx++;

	Crc32 = crc32(Mark, Size, -1);
	*Browser++ = *((uchar *)(&Crc32) + 0);
	*Browser++ = *((uchar *)(&Crc32) + 1);

	Size = (uint)(Browser - Mark);
	SizeSz = GetWrittenSz((Size + 1) + (Size + 1) + 5);

	TrickyID = (ushort)(((Relay.SessionID2Declare << 1) ^ crc32(Mark, Size, -1)) & 0xFFFF);

	Browser = AuthDatas;
	memmove_s(AuthDatas + SizeSz + 3, 0xFFF, AuthDatas, 0xFFF - SizeSz - 3);
	
	WriteValue(&Browser , (Size + 1) + (Size + 1) + 5);
	*Browser++ = 0x05;
	*Browser++ = *((uchar *)(&TrickyID) + 1);
	*Browser++ = *((uchar *)(&TrickyID) + 0);

	Size += SizeSz + 3;

	CipherTCP(&(RelayKeys.SendStream), AuthDatas, 3);
	CipherTCP(&(RelayKeys.SendStream), AuthDatas + 3, Size - 3);

	printf("Authenticating to peer (End / Buddy Status Related Part & AES) (0x%x, 0x%x)..\n", InternTID, TrickyID);

	SuperWait = 1;
	if (SendPacketTCP(TCPSock, Relay, AuthDatas, Size, HTTPS_PORT, &Connected))
	{
		CipherTCP(&(RelayKeys.RecvStream), RecvBuffer, RecvBufferSz);

		printf("Peer Auth#End Response..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		//printf("\n\n");
	}
	else
	{
		printf("No Response.. Skipping Relay %s..\n", Relay.ip);
		return (0);
	}

	uint	AesSaltBase = ((SessionProposal->PeerSessID & 0xFFFF) << 0x10) + (SessionProposal->SessID & 0xFFFF);
	uint	NotAesSaltBase = 0;

	SessionProposal->AesStream->Idx = 0;
	SessionProposal->AesStream->AesSalt = 0;
	ZeroMemory(&(SessionProposal->AesStream->ivec)[0], AES_BLOCK_SIZE);
	ZeroMemory(&(SessionProposal->AesStream->ecount_buf)[0], AES_BLOCK_SIZE);

	SessionProposal->AesStream->IvecIdx = 1;
	AES_set_encrypt_key(SessionProposal->AesKeyBlob, 256, &(SessionProposal->AesStream->Key));

	SessionProposal->AesStream->AesSalt = AesSaltBase;

	SessionProposal->AesStreamOut->Idx = 0;
	SessionProposal->AesStreamOut->AesSalt = 0;
	ZeroMemory(&(SessionProposal->AesStreamOut->ivec)[0], AES_BLOCK_SIZE);
	ZeroMemory(&(SessionProposal->AesStreamOut->ecount_buf)[0], AES_BLOCK_SIZE);

	SessionProposal->AesStreamOut->IvecIdx = 0;
	AES_set_encrypt_key(SessionProposal->AesKeyBlob, 256, &(SessionProposal->AesStreamOut->Key));

	__asm
	{
		push eax
		mov  eax, AesSaltBase
		not	 eax
		mov  NotAesSaltBase, eax
		pop eax
	}

	SessionProposal->AesStreamOut->AesSalt = NotAesSaltBase;
	
	SResponse	Response;

	uchar		BackResponse[0xFFF];
	uchar		*BRBrowser;
	uint		BRSize;

	while (1)
	{
		BRSize = 0;
		ZeroMemory(BackResponse, 0xFFF);
		
		BRBrowser = BackResponse;
		Browser = RecvBuffer;

		while (RecvBufferSz > 0)
		{
			Response.Objs = NULL;
			Response.NbObj = 0;

			UserPacketManager(&Browser, (uint *)&RecvBufferSz, &Response, SessionProposal->AesStream, -1);

			for (Idx = 0; Idx < Response.NbObj; Idx++)
				DumpObj(Response.Objs[Idx]);

			if (UserCommandManager(Relay, SessionProposal, Response, &BRBrowser, &BRSize) == 0)
				return (0);
		}

		printf("Responding Back..\n");

		SuperWait = 1;
		if (SendPacketTCP(TCPSock, Relay, BackResponse, BRSize, HTTPS_PORT, &Connected))
		{
			CipherTCP(&(RelayKeys.RecvStream), RecvBuffer, RecvBufferSz);

			printf("Peer Response..\n");
		}
		else
		{
			printf("No Response.. Skipping Relay %s..\n", Relay.ip);
			return (0);
		}
	}

	/*for (Idx = 0; Idx < Response.NbObj; Idx++)
			DumpObj(Response.Objs[Idx]);*/

	return (1);
}

int	PeerAuth(Host Relay)
{
	uchar		AesKeyInitBlob[32] = {0};
	uchar		AuthDatas[0xFFF] = {0};
	uchar		Buffer[LOCATION_SZ] = {0};
	uchar		SignedChallenge[0x80] = {0};
	uchar		ivec[AES_BLOCK_SIZE] = {0};
	uchar		ecount_buf[AES_BLOCK_SIZE] = {0};
	uchar		*Browser, *Mark;
	uint		Size = 0, Idx = 0, Crc32 = 0, SizeSz = 0;
	ushort		Crc16 = 0;
	ushort		InternTID, TrickyID;
	Memory_U	SolvedChall;
	ObjectDesc	ObjNbr, ObjLocation, ObjPeerChallenge, ObjDirBlob, ObjChallenge;

	Browser = AuthDatas;

	SessionProposal->AesStream = (AesStream_S *)malloc(sizeof(AesStream_S));
	SessionProposal->AesStreamOut = (AesStream_S *)malloc(sizeof(AesStream_S));

	InternTID = BytesRandomWord();
	if (0xFFFF - InternTID < 0x1000)
		InternTID -= 0x1000;

	Mark = Browser;

	WriteValue(&Browser, InternTID ^ 0x234);
	WriteValue(&Browser, 0x44);

	*Browser++ = RAW_PARAMS;
	WriteValue(&Browser, 0x0E);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x03;
	ObjNbr.Value.Nbr = SessionProposal->SessID;
	WriteObject(&Browser, ObjNbr);

	BuildLocationBlob(Session_SN, &Buffer[0]);

	ObjLocation.Family = OBJ_FAMILY_BLOB;
	ObjLocation.Id = 0x01;
	ObjLocation.Value.Memory.Memory = Buffer;
	ObjLocation.Value.Memory.MsZ = LOCATION_SZ;
	WriteObject(&Browser, ObjLocation);

	ObjPeerChallenge.Family = OBJ_FAMILY_TABLE;
	ObjPeerChallenge.Id = 0x09;
	memcpy_s(ObjPeerChallenge.Value.Table, sizeof(ObjPeerChallenge.Value.Table), SessionProposal->PeerChallenge, sizeof(ObjPeerChallenge.Value.Table));
	WriteObject(&Browser, ObjPeerChallenge);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x1B;
	ObjNbr.Value.Nbr = 0x07;		//NAT TYPE
	WriteObject(&Browser, ObjNbr);

	memcpy_s(Browser, 0xFFF, SessionProposal->RelaysInfos.Memory, SessionProposal->RelaysInfos.MsZ);
	Browser += SessionProposal->RelaysInfos.MsZ;

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x16;
	ObjNbr.Value.Nbr = 0x01;
	WriteObject(&Browser, ObjNbr);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x1A;
	ObjNbr.Value.Nbr = 0x00;
	WriteObject(&Browser, ObjNbr);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x1D;
	ObjNbr.Value.Nbr = 0x00;
	WriteObject(&Browser, ObjNbr);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x1E;
	ObjNbr.Value.Nbr = 0x00;
	WriteObject(&Browser, ObjNbr);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x02;
	ObjNbr.Value.Nbr = htonl(my_public_ip);
	WriteObject(&Browser, ObjNbr);

	ObjDirBlob.Family = OBJ_FAMILY_BLOB;
	ObjDirBlob.Id = 0x05;
	ObjDirBlob.Value.Memory.Memory = DirBlob;
	ObjDirBlob.Value.Memory.MsZ = 0x148;
	WriteObject(&Browser, ObjDirBlob);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x0D;
	ObjNbr.Value.Nbr = 0x02;
	WriteObject(&Browser, ObjNbr);

	uchar	ChallengeCp[0x09] = {0};

	memcpy_s(ChallengeCp, sizeof(ChallengeCp), SessionProposal->Challenge, sizeof(SessionProposal->Challenge));
	MemReverse(ChallengeCp, sizeof(ChallengeCp) - 1);
	BuildUnFinalizedDatas(ChallengeCp, sizeof(ChallengeCp), SignedChallenge);
	RSA_private_encrypt(sizeof(SignedChallenge), SignedChallenge, SignedChallenge, GLoginD.RSAKeys, RSA_NO_PADDING);

	ObjChallenge.Family = OBJ_FAMILY_BLOB;
	ObjChallenge.Id = 0x0A;
	ObjChallenge.Value.Memory.Memory = SignedChallenge;
	ObjChallenge.Value.Memory.MsZ = sizeof(SignedChallenge);
	WriteObject(&Browser, ObjChallenge);

	Crc16 = crc16(Mark, (uint)(Browser - Mark), 0);
	*Browser++ = *((uchar *)(&Crc16) + 1);
	*Browser++ = *((uchar *)(&Crc16) + 0);

	Size = (uint)(Browser - Mark);

	SessionProposal->AesStream->Idx = 0;
	SessionProposal->AesStream->AesSalt = 0;
	ZeroMemory(&(SessionProposal->AesStream->ivec)[0], AES_BLOCK_SIZE);
	ZeroMemory(&(SessionProposal->AesStream->ecount_buf)[0], AES_BLOCK_SIZE);

	SessionProposal->AesStream->IvecIdx = 0;
	AES_set_encrypt_key(AesKeyInitBlob, 256, &(SessionProposal->AesStream->Key));
	
	((uint *)(SessionProposal->AesStream->ivec))[3] = htonl(SessionProposal->AesStream->IvecIdx << 0x10);
	AES_ctr128_encrypt(Mark, Mark, Size, &(SessionProposal->AesStream->Key), &(SessionProposal->AesStream->ivec)[0], &(SessionProposal->AesStream->ecount_buf)[0], &(SessionProposal->AesStream->Idx));
	SessionProposal->AesStream->IvecIdx++;

	Crc32 = crc32(Mark, Size, -1);
	*Browser++ = *((uchar *)(&Crc32) + 0);
	*Browser++ = *((uchar *)(&Crc32) + 1);

	Size = (uint)(Browser - Mark);
	SizeSz = GetWrittenSz((Size + 1) + (Size + 1) + 5);

	TrickyID = (ushort)((Relay.SessionID2Declare << 1) ^ crc32(Mark, Size, -1));

	Browser = AuthDatas;
	memmove_s(AuthDatas + SizeSz + 3, 0xFFF, AuthDatas, 0xFFF - SizeSz - 3);
	
	WriteValue(&Browser , (Size + 1) + (Size + 1) + 5);
	*Browser++ = 0x05;
	*Browser++ = *((uchar *)(&TrickyID) + 1);
	*Browser++ = *((uchar *)(&TrickyID) + 0);

	Size += SizeSz + 3;

	CipherTCP(&(RelayKeys.SendStream), AuthDatas, 3);
	CipherTCP(&(RelayKeys.SendStream), AuthDatas + 3, Size - 3);

	printf("Authenticating to peer..\n");

	SuperWait = 1;
	if (SendPacketTCP(TCPSock, Relay, AuthDatas, Size, HTTPS_PORT, &Connected))
	{
		CipherTCP(&(RelayKeys.RecvStream), RecvBuffer, RecvBufferSz);

		printf("Peer Auth Response..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		//printf("\n\n");
	}
	else
	{
		printf("No Response.. Skipping Relay %s..\n", Relay.ip);
		return (0);
	}

	SResponse	Response;
	int			KnownLedgeState;
	
	KnownLedgeState = 0;
	Browser = RecvBuffer;
	
	SessionProposal->PeerContact = (Contact *)malloc(sizeof(Contact));
	ZeroMemory(SessionProposal->PeerContact, sizeof(Contact));
	SessionProposal->PeerContact->Locations = new list<CLocation>;
	SessionProposal->PeerContact->DisplayName = NULL;
	SessionProposal->PeerContact->InternalName = NULL;
	SessionProposal->PeerContact->BuddyStatus = 0;
	SessionProposal->PeerContact->AuthCert.Memory = NULL;
	SessionProposal->PeerContact->AuthCert.MsZ = 0;
	SessionProposal->PeerContact->OnLineStatus = 1;

	ZeroMemory(SessionProposal->AesKeyBlob, 32);

	ZeroMemory(&SolvedChall, sizeof(SolvedChall));

	Response.Objs = NULL;
	Response.NbObj = 0;

	UserPacketManager(&Browser, (uint *)&RecvBufferSz, &Response, SessionProposal->AesStream, 1);

	for (Idx = 0; Idx < Response.NbObj; Idx++)
			DumpObj(Response.Objs[Idx]);

	switch (Response.Cmd)
	{
	case CMD_USR_45:
		int	SolutionState;

		SolutionState = 0;
		
		printf("Successfully Auth..\n");
		for (Idx = 0; Idx < Response.NbObj; Idx++)
		{
			switch (Response.Objs[Idx].Id)
			{
			case OBJ_ID_USRDBLOB:
				if (DirBlob2Contact(Response.Objs[Idx].Value.Memory.Memory, Response.Objs[Idx].Value.Memory.MsZ, SessionProposal->PeerContact))
				{
					printf("User Identity Successfully Decoded..\n");
					printf("RSA PUB KEY FROM CMD_45\n");
					showmem(SessionProposal->PeerContact->RsaPubKey.Memory, SessionProposal->PeerContact->RsaPubKey.MsZ);
					printf("\n");
					SolutionState += 1;
					KnownLedgeState += 1;
				}
				else
				{
					printf("Failed to Decode User Identity..\n");
					return (0);
				}
				break;
			case OBJ_ID_SOLVEDCHALL:
				SolvedChall = Response.Objs[Idx].Value.Memory;
				break;
			case OBJ_ID_AESPART1:
				if (GetAesFinalKeyPart(&(SessionProposal->AesKeyBlob[0]), Response.Objs[Idx].Value.Memory) == 0)
				{
					printf("Failed To Get Part of AesKey..\n");
					return (0);
				}
				else
				{
					printf("Successfully got Part of AesKey..\n");
					KnownLedgeState += 1;
				}
				break;
			default :
				printf("Non critical Object %d:%d..\n", Response.Objs[Idx].Family, Response.Objs[Idx].Id);
				break;
			}
		}
		if ((SolvedChall.MsZ) && (SolutionState))
		{
			if (ChkChallenge(SolvedChall, (uchar *)SessionProposal->PeerChallenge, SessionProposal->PeerContact->RsaPubKey))
			{
				printf("Peer successfully solved Challenge..\n");
				KnownLedgeState += 1;
			}
			else
			{
				printf("Peer failed to solve Challenge..\n");
				return (0);
			}
		}
		else
		{
			printf("Unable to check Peer solution to Challenge..\n");
			return (0);
		}
		break;
	default:
		printf("Unmanaged User Cmd %d\n", Response.Cmd);
		break;
	}

	printf("\n");

	if (KnownLedgeState != 3)
		return (0);
	return (1);
}

int	UDPConnect(Host Relay)
{
	uchar			Request[0xFF];
	ProbeHeader		*PHeader;
	ushort			TransID;
	uchar			*PRequest, *Mark;
	int				BaseSz;
	uint			PSize;
	sockaddr_in		LocalBind;
	SOCKET			RUDPSock;
	ObjectDesc		ObjNbr;

	RUDPSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	ZeroMemory((char *)&LocalBind, sizeof(LocalBind));
	LocalBind.sin_family = AF_INET;
	LocalBind.sin_addr.s_addr = htonl(INADDR_ANY);
	LocalBind.sin_port = htons(DEF_LPORT);
	bind(RUDPSock, (struct sockaddr *)&LocalBind, sizeof(LocalBind));

	BaseSz = 0x09;

	ZeroMemory(Request, 0xFF);

	TransID = BytesRandomWord();
	if (0xFFFF - TransID < 0x1000)
		TransID -= 0x1000;

	PHeader = (ProbeHeader *)Request;
	PHeader->TransID = htons(TransID);
	PHeader->PacketType = PKT_TYPE_OBFSUK;
	PHeader->IV = htonl(GenIV());

	PRequest = Request + sizeof(*PHeader);
	Mark = PRequest;

	WriteValue(&PRequest, BaseSz + GetWrittenSz(Relay.SessionID2Declare));
	WriteValue(&PRequest, 0x2E2);
	*(unsigned short *)PRequest = htons(TransID - 1);
	PRequest += 2;

	*PRequest++ = RAW_PARAMS;
	WriteValue(&PRequest, 0x02);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x03;
	ObjNbr.Value.Nbr = Relay.SessionID2Declare;
	WriteObject(&PRequest, ObjNbr);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x13;
	ObjNbr.Value.Nbr = 0x01;
	WriteObject(&PRequest, ObjNbr);

	PSize = (uint)(PRequest - Mark);

	PHeader->Crc32 = htonl(crc32(Mark, PSize, -1));

	showmem(Request, sizeof(ProbeHeader) + PSize);

	Cipher(Mark, PSize, htonl(my_public_ip), htonl(inet_addr(Relay.ip)), htons(PHeader->TransID), htonl(PHeader->IV), 0);

	if (SendPacket(RUDPSock, Relay, Request, sizeof(ProbeHeader) + PSize))
	{
		struct in_addr	PublicIP;

		PublicIP.S_un.S_addr = my_public_ip;
		if (UnCipherObfuscated(RecvBuffer, RecvBufferSz, inet_ntoa(PublicIP), Relay.ip) == 0)
		{
			printf("Unable to uncipher Packet..\n");
			return (0);
		}
		printf("UDP Connect Response Received..\n");
		showmem(RecvBuffer, RecvBufferSz);
		printf("\n\n");
	}
	else
	{
		printf("No Response to UDP Connect..\n");
		return (0);
	}

	return (1);
}

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
	WriteValue(&PRequest, 0x08 + GetWrittenSz(SessionProposal->Relays->front().SessionID2Declare) + GetWrittenSz(SessionProposal->SessID));
	WriteValue(&PRequest, 0x252);
	*(unsigned short *)PRequest = htons(TransID - 1);
	PRequest += 2;
	
	*PRequest++ = RAW_PARAMS;
	WriteValue(&PRequest, 0x02);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x04;
	ObjNbr.Value.Nbr = SessionProposal->Relays->front().SessionID2Declare;
	WriteObject(&PRequest, ObjNbr);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x03;
	ObjNbr.Value.Nbr = SessionProposal->SessID;
	WriteObject(&PRequest, ObjNbr);

	Size = (uint)(PRequest - Request);
	SizeSz = GetWrittenSz(Size << 1);

	PRequest = Request;
	memmove_s(Request + SizeSz, 0xFF, Request, 0xFF - SizeSz);
	WriteValue(&PRequest , Size << 1);

	Size += SizeSz;

	//showmem(Request, Size);
	//printf("\n");
	
	CipherTCP(&(RelayKeys.SendStream), Request, 3);
	CipherTCP(&(RelayKeys.SendStream), Request + 3, Size - 3);

	printf("Declaring session..\n");

	if (SendPacketTCP(TCPSock, Relay, Request, Size, HTTPS_PORT, &Connected))
	{
		CipherTCP(&(RelayKeys.RecvStream), RecvBuffer, RecvBufferSz);

		printf("Session Declare Response..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		//printf("\n\n");
	}
	else
	{
		printf("No Response.. Skipping Relay %s..\n", Relay.ip);
		return (0);
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
		case CMD_SESSIONOK:
			printf("Session Declared with success..\n");
			break;
		case CMD_SESSIONERROR:
			printf("Session declaration error.. Session doesn't exist.. Aborting..\n");
			return (0);
			break;
		case CMD_UDPCONNECT:
			uchar	RecvCopy[0xFFFF];
			int		RecvSzCopy;

			printf("UDP Connect request.. Sending Ack..\n");
			ZeroMemory(RecvCopy, 0xFFFF);
			memcpy_s(RecvCopy, 0xFFFF, RecvBuffer, RecvBufferSz);
			RecvSzCopy = RecvBufferSz;

			SendACK(Response.PacketID, TCPSock, Relay, HTTPS_PORT, &Connected, &RelayKeys);
			UDPConnect(Relay);

			ZeroMemory(RecvBuffer, 0xFFFF);
			memcpy_s(RecvBuffer, 0xFFFF, RecvCopy, RecvSzCopy);
			RecvBufferSz = RecvSzCopy;					
			break;
		default:
			printf("Unmanaged Cmd %d\n", Response.Cmd / 8);
			break;
		}
	}
	return (1);
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
	
	printf("Sending Our Seed..\n");
	//showmem(Packet, sizeof(TCPCtrlPacketHeader) + 35);
	//printf("\n\n");

	if (SendPacketTCP(TCPSock, Relay, Packet, sizeof(TCPCtrlPacketHeader) + 35, HTTPS_PORT, &Connected))
	{
		printf("Send Seed Response..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		printf("\n\n");
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
		printf("Skipping Host %s..\n", Relay.ip);
		return 0;
	}

	UncipherObfuscatedTCPCtrlPH(RecvBuffer);

	RHeader = (TCPCtrlPacketHeader *)RecvBuffer;
	if ((htonl(RHeader->Cookie_1) == 0x01) && (htonl(RHeader->Cookie_2) == 0x03))
	{
		printf("Remote Seed : 0x%x\n", htonl(RHeader->Seed));
		
		InitKey(&(RelayKeys.RecvStream), htonl(RHeader->Seed));
		CipherTCP(&(RelayKeys.RecvStream), RecvBuffer + sizeof(TCPCtrlPacketHeader) - 2, RecvBufferSz - sizeof(TCPCtrlPacketHeader) + 2);

		printf("Key Exchange Response [Decrypted]..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		printf("\n\n");

		printf("Keys Pair Initialized..\n");
	}
	else
	{
		printf("Bad Key Exchange Response.. Leaving Relay..\n");
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

	printf("Sending https HandShake to Relay %s:%d\n", Relay.ip, Relay.port);
	//showmem(HttpsHSPacket, HHSP_SIZE);
	//printf("\n\n");

	if (SendPacketTCP(TCPSock, Relay, HttpsHSPacket, HHSP_SIZE, HTTPS_PORT, &Connected))
	{
		printf("HandShake Response..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		printf("\n\n");
	}
	else
	{
		printf("Relay %s:%d not responding..\n", Relay.ip, Relay.port);
		return 0;
	}
	RHeader = (HttpsPacketHeader *)RecvBuffer;
	if (strncmp((const char *)RHeader->MAGIC, HTTPS_HSR_MAGIC, strlen(HTTPS_HSR_MAGIC)))
	{
		printf("Bad Handshake Response.. Leaving Relay %s:%d\n", Relay.ip, Relay.port);
		return 0;
	}
	printf("Relay OK.. Handing Over.. %s:%d\n", Relay.ip, Relay.port);
	return (RelayExchangeKeys(Relay, (htons(RHeader->ResponseLen) + sizeof(HttpsPacketHeader) != RecvBufferSz), htons(RHeader->ResponseLen)));
}

DWORD WINAPI	InitSessionThreadProc(LPVOID Param)
{
	uint		ReUse = 1;
	Host		CurRelay;

	SessionProposal = (SessProp *)Param;

	/*ThreadConsole.Create("FakeSkype Thread - Initializing Session with peer..", -1, -1, NULL, CONSOLEHELPER_EXE);
	ThreadConsole.SetAsDefaultOutput();*/

	printf("Initializing Session [%x]..\n\n", SessionProposal->SessID);

	TCPSock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(TCPSock, SOL_SOCKET, SO_REUSEADDR, (const char *)&ReUse, sizeof(ReUse));

	CurRelay = SessionProposal->Relays->front();
	if (RelayHandShake(CurRelay) == 0)
		goto End;
	if (PeerAuth(CurRelay) == 0)
		goto End;
	if (PeerAuthEnd(CurRelay) == 0)
		goto End;
	RelayOK = 1;
End:
	return (0);
	
	/*ThreadConsole.ResetDefaultOutput();
	ThreadConsole.Close();*/
	
	ExitThread(0);
}

void	InitSession(SessProp *SessionProposal)
{
	HANDLE	hThread;
	DWORD	ThreadID;

	while (!SessionProposal->Relays->empty())
	{
		//InitSessionThreadProc((LPVOID)SessionProposal);

		hThread = CreateThread(NULL, 0, InitSessionThreadProc, (LPVOID)SessionProposal, 0, &ThreadID); 
		WaitForSingleObject(hThread, INFINITE);

		Connected = 0;
		closesocket(TCPSock);

		if (RelayOK)
			break;
		SessionProposal->Relays->pop();
	}
}