#include "Events.h"

Host	EventsServers[] = {{"212.8.163.76", 12350},
						   {"212.72.49.142", 12350},
						   {"195.215.8.142", 12350},
						   {0, 0}
				          };

queue<Host>		ESQueue;
queue<Contact>	Contacts;
SOCKET			ESSock;
uchar			*Email = NULL;

static int		Connected = 0;
int				IvecIdx = 0;

void	InitESQueue()
{
	int	Idx;
	
	for (Idx = 0; (EventsServers[Idx].port != 0); Idx++)
		ESQueue.push(EventsServers[Idx]);
}

void	ResetESSock()
{
	uint	ReUse;

	ReUse = 1;
	Connected = 0;
	closesocket(ESSock);
	ESSock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(ESSock, SOL_SOCKET, SO_REUSEADDR, (const char *)&ReUse, sizeof(ReUse));
}

int		SendHandShake2ES(Host CurES)
{
	uchar				HandShakePkt[HANDSHAKE_SZ] = {0};
	HttpsPacketHeader	*HSHeader;

	HSHeader = (HttpsPacketHeader *)HandShakePkt;
	memcpy_s(HSHeader->MAGIC, sizeof(HSHeader->MAGIC), HTTPS_HSR_MAGIC, strlen(HTTPS_HSR_MAGIC));
	HSHeader->ResponseLen = htons(0x00);
	printf("Sending Handshake to Event Server %s..\n", CurES.ip);
	SuperWait = 2;
	if (SendPacketTCP(ESSock, CurES, HandShakePkt, HANDSHAKE_SZ, HTTPS_PORT, &Connected))
	{
		printf("HandShake Response..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		//printf("\n");
		return (1);
	}
	else
		return (0);
}

int		SendAuthentificationBlobES(Host CurES, char *User, char *Pass)
{
	uchar				AuthBlob[0xFFFF] = {0};
	uchar				MD5Result[MD5_DIGEST_LENGTH] = {0};
	uchar				SHAResult[32] = {0};
	uchar				SessionKey[SK_SZ] = {0};
	uchar				ivec[AES_BLOCK_SIZE] = {0};
	uchar				ecount_buf[AES_BLOCK_SIZE] = {0};
	uint				MiscDatas[0x05] = {0};
	uchar				*Browser;
	uchar				*Mark;
	uchar				*MarkObjL;
	uint				Idx, Size, Crc;
	HttpsPacketHeader	*HSHeader;
	AES_KEY				AesKey;
	MD5_CTX				Context;
	RSA					*SkypeRSA;
	ObjectDesc			Obj2000, ObjSessionKey, ObjZBool1, ObjRequestCode, ObjZBool2, ObjUserName, ObjSharedSecret, ObjVer, ObjPubAddr;

	Browser = AuthBlob;

	HSHeader = (HttpsPacketHeader *)Browser;
	memcpy_s(HSHeader->MAGIC, sizeof(HSHeader->MAGIC), HTTPS_HSR_MAGIC, strlen(HTTPS_HSR_MAGIC));
	HSHeader->ResponseLen = htons(0xCD);
	Browser += sizeof(HttpsPacketHeader);
	
	*Browser++ = RAW_PARAMS;
	*Browser++ = 0x03;

	Obj2000.Family = OBJ_FAMILY_NBR;
	Obj2000.Id = OBJ_ID_2000;
	Obj2000.Value.Nbr = 0x2000;
	WriteObject(&Browser, Obj2000);

	GetSessionKey(SessionKey);

	SpecialSHA(SessionKey, SK_SZ, SHAResult, 32);
	AES_set_encrypt_key(SHAResult, 256, &AesKey);

	SkypeRSA = RSA_new();
	BN_hex2bn(&(SkypeRSA->n), SkypeModulus1536[1]);
    BN_hex2bn(&(SkypeRSA->e), "10001");
	RSA_public_encrypt(SK_SZ, SessionKey, SessionKey, SkypeRSA, RSA_NO_PADDING);
	RSA_free(SkypeRSA);

	ObjSessionKey.Family = OBJ_FAMILY_BLOB;
	ObjSessionKey.Id = OBJ_ID_SK;
	ObjSessionKey.Value.Memory.Memory = (uchar *)&SessionKey;
	ObjSessionKey.Value.Memory.MsZ = SK_SZ;
	WriteObject(&Browser, ObjSessionKey);

	ObjZBool1.Family = OBJ_FAMILY_NBR;
	ObjZBool1.Id = OBJ_ID_ZBOOL1;
	ObjZBool1.Value.Nbr = 0x01;
	WriteObject(&Browser, ObjZBool1);

	Mark = Browser;
	HSHeader = (HttpsPacketHeader *)Browser;
	memcpy_s(HSHeader->MAGIC, sizeof(HSHeader->MAGIC), HTTPS_HSRR_MAGIC, strlen(HTTPS_HSRR_MAGIC));
	HSHeader->ResponseLen = htons(0x00);
	Browser += sizeof(HttpsPacketHeader);

	MarkObjL = Browser;
	*Browser++ = RAW_PARAMS;
	*Browser++ = 0x04;

	ObjRequestCode.Family = OBJ_FAMILY_NBR;
	ObjRequestCode.Id = OBJ_ID_REQCODE;
	ObjRequestCode.Value.Nbr = 0x178E;
	WriteObject(&Browser, ObjRequestCode);

	ObjZBool2.Family = OBJ_FAMILY_NBR;
	ObjZBool2.Id = OBJ_ID_ZBOOL2;
	ObjZBool2.Value.Nbr = 0x04;
	WriteObject(&Browser, ObjZBool2);

	ObjUserName.Family = OBJ_FAMILY_STRING;
	ObjUserName.Id = OBJ_ID_USERNAME;
	ObjUserName.Value.Memory.Memory = (uchar *)User;
	ObjUserName.Value.Memory.MsZ = (uchar)strlen(User);
	WriteObject(&Browser, ObjUserName);

	MD5_Init(&Context);
	MD5_Update(&Context, User, (ulong)strlen(User));
	MD5_Update(&Context, CONCAT_SALT, (ulong)strlen(CONCAT_SALT));
	MD5_Update(&Context, Pass, (ulong)strlen(Pass));
	MD5_Final(MD5Result, &Context);

	ObjSharedSecret.Family = OBJ_FAMILY_BLOB;
	ObjSharedSecret.Id = OBJ_ID_USERPASS;
	ObjSharedSecret.Value.Memory.Memory = (uchar *)MD5Result;
	ObjSharedSecret.Value.Memory.MsZ = MD5_DIGEST_LENGTH;
	WriteObject(&Browser, ObjSharedSecret);

	*Browser++ = RAW_PARAMS;
	*Browser++ = 0x03;

	ObjUserName.Family = OBJ_FAMILY_STRING;
	ObjUserName.Id = OBJ_ID_USERNAME;
	ObjUserName.Value.Memory.Memory = (uchar *)User;
	ObjUserName.Value.Memory.MsZ = (uchar)strlen(User);
	WriteObject(&Browser, ObjUserName);

	ObjVer.Family = OBJ_FAMILY_STRING;
	ObjVer.Id = OBJ_ID_VERSION;
	ObjVer.Value.Memory.Memory = (uchar *)VER_STR;
	ObjVer.Value.Memory.MsZ = (uchar)strlen(VER_STR);
	WriteObject(&Browser, ObjVer);

	ObjPubAddr.Family = OBJ_FAMILY_NBR;
	ObjPubAddr.Id = OBJ_ID_PUBADDR;
	ObjPubAddr.Value.Nbr = htonl(my_public_ip);
	WriteObject(&Browser, ObjPubAddr);

	Size = (uint)(Browser - MarkObjL);
	HSHeader->ResponseLen = htons((ushort)Size + 0x02);

	Idx = 0;
	ZeroMemory(ivec, AES_BLOCK_SIZE);
	ZeroMemory(ecount_buf, AES_BLOCK_SIZE);
	AES_ctr128_encrypt(MarkObjL, MarkObjL, Size, &AesKey, ivec, ecount_buf, &Idx);

	Crc = crc32(MarkObjL, Size, -1);
	*Browser++ = *((uchar *)(&Crc) + 0);
	*Browser++ = *((uchar *)(&Crc) + 1);

	Size = (uint)(Browser - AuthBlob);
	
	if (SendPacketTCP(ESSock, CurES, AuthBlob, Size, HTTPS_PORT, &Connected))
		printf("Auth Response Got..\n\n");
	else
	{
		printf(":'(..\n");
		return (0);
	}

	int AESsZ = 0;
	while (AESsZ < RecvBufferSz)
	{
		HSHeader = (HttpsPacketHeader *)(RecvBuffer + AESsZ);
		if (strncmp((const char *)HSHeader->MAGIC, HTTPS_HSRR_MAGIC, strlen(HTTPS_HSRR_MAGIC)))
		{
			printf("Bad Response..\n");
			return (NULL);
		}

		Idx = 0;
		ZeroMemory(ivec, AES_BLOCK_SIZE);
		ZeroMemory(ecount_buf, AES_BLOCK_SIZE);
		ivec[3] = 0x01;
		ivec[7] = 0x01;
		((uint *)ivec)[3] = htonl(IvecIdx << 0x10);
		AES_ctr128_encrypt(RecvBuffer + AESsZ + sizeof(HttpsPacketHeader), RecvBuffer + AESsZ + sizeof(HttpsPacketHeader), htons(HSHeader->ResponseLen) - 0x02, &AesKey, ivec, ecount_buf, &Idx);
		IvecIdx++;
		AESsZ += sizeof(HttpsPacketHeader) + htons(HSHeader->ResponseLen);
	}
	printf("[UNCIPHERED]Auth Response..\n\n");
	//showmem(RecvBuffer, RecvBufferSz);
	//printf("\n\n");

	uchar		*Buffer;
	uint		BSize;
	SResponse	Response;

	Buffer = RecvBuffer;
	BSize = RecvBufferSz;
	Response.Objs = NULL;
	Response.NbObj = 0;
	while (BSize)
	{
		MainArchResponseManager(&Buffer, &BSize, &Response);
		Buffer += 2;
	}

	for (Idx = 0; Idx < Response.NbObj; Idx++)
	{
		switch (Response.Objs[Idx].Id)
		{
		case OBJ_ID_ESAUTHANSWR:
			switch (Response.Objs[Idx].Value.Nbr)
			{
			case ESAUTH_OK:
				printf("Event Server Authentification Successful..\n");
				break;
			default :
				printf("Event Server Authentification Failed.. Bad Credentials..\n");
				ExitProcess(0);
				break;
			}
			break;
		default :
			printf("Non critical Object %d:%d..\n", Response.Objs[Idx].Family, Response.Objs[Idx].Id);
			break;
		}
	}

	printf("\n\n");
	return (1);
}

uchar					*RequestHashList(Host CurES, char *User, char *Pass, uint *NbHashes)
{
	double				PlatForm;
	uchar				Blob[0xFFFF] = {0};
	uchar				MD5Result[MD5_DIGEST_LENGTH] = {0};
	uchar				SHAResult[32] = {0};
	uchar				SessionKey[SK_SZ] = {0};
	uchar				ivec[AES_BLOCK_SIZE] = {0};
	uchar				ecount_buf[AES_BLOCK_SIZE] = {0};
	uchar				*Browser;
	uchar				*Mark;
	uchar				*MarkObjL;
	uchar				*Result;
	uint				Idx, Size, Crc;
	HttpsPacketHeader	*HSHeader;
	AES_KEY				AesKey;
	MD5_CTX				Context;
	ObjectDesc			ObjRequestCode, ObjZBool2, ObjUserName, ObjSharedSecret, ObjPlatForm, ObjVer, ObjPubAddr;

	Browser = Blob;

	GetSessionKey(SessionKey);

	SpecialSHA(SessionKey, SK_SZ, SHAResult, 32);
	AES_set_encrypt_key(SHAResult, 256, &AesKey);

	Mark = Browser;
	HSHeader = (HttpsPacketHeader *)Browser;
	memcpy_s(HSHeader->MAGIC, sizeof(HSHeader->MAGIC), HTTPS_HSRR_MAGIC, strlen(HTTPS_HSRR_MAGIC));
	HSHeader->ResponseLen = htons(0x00);
	Browser += sizeof(HttpsPacketHeader);

	MarkObjL = Browser;
	*Browser++ = RAW_PARAMS;
	*Browser++ = 0x04;

	ObjRequestCode.Family = OBJ_FAMILY_NBR;
	ObjRequestCode.Id = OBJ_ID_REQCODE;
	ObjRequestCode.Value.Nbr = 0x178C;
	WriteObject(&Browser, ObjRequestCode);

	ObjZBool2.Family = OBJ_FAMILY_NBR;
	ObjZBool2.Id = OBJ_ID_ZBOOL2;
	ObjZBool2.Value.Nbr = 0x08;
	WriteObject(&Browser, ObjZBool2);

	ObjUserName.Family = OBJ_FAMILY_STRING;
	ObjUserName.Id = OBJ_ID_USERNAME;
	ObjUserName.Value.Memory.Memory = (uchar *)User;
	ObjUserName.Value.Memory.MsZ = (uchar)strlen(User);
	WriteObject(&Browser, ObjUserName);

	MD5_Init(&Context);
	MD5_Update(&Context, User, (ulong)strlen(User));
	MD5_Update(&Context, CONCAT_SALT, (ulong)strlen(CONCAT_SALT));
	MD5_Update(&Context, Pass, (ulong)strlen(Pass));
	MD5_Final(MD5Result, &Context);

	ObjSharedSecret.Family = OBJ_FAMILY_BLOB;
	ObjSharedSecret.Id = OBJ_ID_USERPASS;
	ObjSharedSecret.Value.Memory.Memory = (uchar *)MD5Result;
	ObjSharedSecret.Value.Memory.MsZ = MD5_DIGEST_LENGTH;
	WriteObject(&Browser, ObjSharedSecret);

	*Browser++ = RAW_PARAMS;
	*Browser++ = 0x04;

	PlatForm = PlatFormSpecific();

	ObjPlatForm.Family = OBJ_FAMILY_TABLE;
	ObjPlatForm.Id = OBJ_ID_PLATFORM;
	memcpy_s(ObjPlatForm.Value.Table, sizeof(ObjPlatForm.Value.Table), (uchar *)&PlatForm, sizeof(ObjPlatForm.Value.Table));
	WriteObject(&Browser, ObjPlatForm);

	ObjUserName.Family = OBJ_FAMILY_STRING;
	ObjUserName.Id = OBJ_ID_USERNAME;
	ObjUserName.Value.Memory.Memory = (uchar *)User;
	ObjUserName.Value.Memory.MsZ = (uchar)strlen(User);
	WriteObject(&Browser, ObjUserName);

	ObjVer.Family = OBJ_FAMILY_STRING;
	ObjVer.Id = OBJ_ID_VERSION;
	ObjVer.Value.Memory.Memory = (uchar *)VER_STR;
	ObjVer.Value.Memory.MsZ = (uchar)strlen(VER_STR);
	WriteObject(&Browser, ObjVer);

	ObjPubAddr.Family = OBJ_FAMILY_NBR;
	ObjPubAddr.Id = OBJ_ID_PUBADDR;
	ObjPubAddr.Value.Nbr = htonl(my_public_ip);
	WriteObject(&Browser, ObjPubAddr);

	Size = (uint)(Browser - MarkObjL);
	HSHeader->ResponseLen = htons((ushort)Size + 0x02);

	Idx = 0;
	ZeroMemory(ivec, AES_BLOCK_SIZE);
	ZeroMemory(ecount_buf, AES_BLOCK_SIZE);
	AES_ctr128_encrypt(MarkObjL, MarkObjL, Size, &AesKey, ivec, ecount_buf, &Idx);

	Crc = crc32(MarkObjL, Size, -1);
	*Browser++ = *((uchar *)(&Crc) + 0);
	*Browser++ = *((uchar *)(&Crc) + 1);

	Size = (uint)(Browser - Blob);
	
	if (SendPacketTCP(ESSock, CurES, Blob, Size, HTTPS_PORT, &Connected))
		printf("GET_HASH Response Got..\n\n");
	else
	{
		printf(":'(..\n");
		return (NULL);
	}

	int AESsZ = 0;
	while (AESsZ < RecvBufferSz)
	{
		HSHeader = (HttpsPacketHeader *)(RecvBuffer + AESsZ);
		if (strncmp((const char *)HSHeader->MAGIC, HTTPS_HSRR_MAGIC, strlen(HTTPS_HSRR_MAGIC)))
		{
			printf("Bad Response..\n");
			return (NULL);
		}

		Idx = 0;
		ZeroMemory(ivec, AES_BLOCK_SIZE);
		ZeroMemory(ecount_buf, AES_BLOCK_SIZE);
		ivec[3] = 0x01;
		ivec[7] = 0x01;
		((uint *)ivec)[3] = htonl(IvecIdx << 0x10);
		AES_ctr128_encrypt(RecvBuffer + AESsZ + sizeof(HttpsPacketHeader), RecvBuffer + AESsZ + sizeof(HttpsPacketHeader), htons(HSHeader->ResponseLen) - 0x02, &AesKey, ivec, ecount_buf, &Idx);
		IvecIdx++;
		AESsZ += sizeof(HttpsPacketHeader) + htons(HSHeader->ResponseLen);
	}
	printf("[UNCIPHERED]GET_HASH Response..\n\n");
	//showmem(RecvBuffer, RecvBufferSz);
	//printf("\n\n");

	uchar		*Buffer;
	uint		BSize;
	SResponse	Response;

	Buffer = RecvBuffer;
	BSize = RecvBufferSz;
	Response.Objs = NULL;
	Response.NbObj = 0;
	while (BSize)
	{
		MainArchResponseManager(&Buffer, &BSize, &Response);
		Buffer += 2;
	}

	for (Idx = 0; Idx < Response.NbObj; Idx++)
	{
		switch (Response.Objs[Idx].Id)
		{
		case OBJ_ID_ESAUTHANSWR:
			printf("Obselete authentification auth response..\n");
			break;
		case OBJ_ID_ESHASHLIST:
			printf("Received %d hashes..\n\n", Response.Objs[Idx].Value.Memory.MsZ / 0x04);				
			Result = Response.Objs[Idx].Value.Memory.Memory;
			*NbHashes = Response.Objs[Idx].Value.Memory.MsZ / 0x04;
			break;
		default :
			printf("Non critical Object %d:%d..\n", Response.Objs[Idx].Family, Response.Objs[Idx].Id);
			break;
		}
	}
		
	printf("\n\n");
	return (Result);
}

void	RequestHashListDetails(Host CurES, char *User, char *Pass, uint *HashList, uint NbHashes)
{
	double				PlatForm;
	uchar				Blob[0xFFFF] = {0};
	uchar				MD5Result[MD5_DIGEST_LENGTH] = {0};
	uchar				SHAResult[32] = {0};
	uchar				SessionKey[SK_SZ] = {0};
	uchar				ivec[AES_BLOCK_SIZE] = {0};
	uchar				ecount_buf[AES_BLOCK_SIZE] = {0};
	uchar				UnRSA[0xFFF];
	uchar				RsaKey[MODULUS_SZ] = {0};
	uchar				*Browser;
	uchar				*Mark;
	uchar				*MarkObjL;
	uint				Idx, Size, Crc;
	HttpsPacketHeader	*HSHeader;
	AES_KEY				AesKey;
	MD5_CTX				Context;
	RSA					*SkypeRSA;
	ObjectDesc			ObjRequestCode, ObjZBool2, ObjUserName, ObjSharedSecret, ObjHash, ObjPlatForm, ObjVer, ObjPubAddr;

	Browser = Blob;

	for (uint HashIdx = 0; HashIdx < NbHashes; HashIdx++)
	{
		GetSessionKey(SessionKey);

		SpecialSHA(SessionKey, SK_SZ, SHAResult, 32);
		AES_set_encrypt_key(SHAResult, 256, &AesKey);

		Mark = Browser;
		HSHeader = (HttpsPacketHeader *)Browser;
		memcpy_s(HSHeader->MAGIC, sizeof(HSHeader->MAGIC), HTTPS_HSRR_MAGIC, strlen(HTTPS_HSRR_MAGIC));
		HSHeader->ResponseLen = htons(0x00);
		Browser += sizeof(HttpsPacketHeader);

		MarkObjL = Browser;
		*Browser++ = RAW_PARAMS;
		*Browser++ = 0x04;

		ObjRequestCode.Family = OBJ_FAMILY_NBR;
		ObjRequestCode.Id = OBJ_ID_REQCODE;
		ObjRequestCode.Value.Nbr = 0x1788;
		WriteObject(&Browser, ObjRequestCode);

		ObjZBool2.Family = OBJ_FAMILY_NBR;
		ObjZBool2.Id = OBJ_ID_ZBOOL2;
		ObjZBool2.Value.Nbr = 0x08;
		WriteObject(&Browser, ObjZBool2);

		ObjUserName.Family = OBJ_FAMILY_STRING;
		ObjUserName.Id = OBJ_ID_USERNAME;
		ObjUserName.Value.Memory.Memory = (uchar *)User;
		ObjUserName.Value.Memory.MsZ = (uchar)strlen(User);
		WriteObject(&Browser, ObjUserName);

		MD5_Init(&Context);
		MD5_Update(&Context, User, (ulong)strlen(User));
		MD5_Update(&Context, CONCAT_SALT, (ulong)strlen(CONCAT_SALT));
		MD5_Update(&Context, Pass, (ulong)strlen(Pass));
		MD5_Final(MD5Result, &Context);

		ObjSharedSecret.Family = OBJ_FAMILY_BLOB;
		ObjSharedSecret.Id = OBJ_ID_USERPASS;
		ObjSharedSecret.Value.Memory.Memory = (uchar *)MD5Result;
		ObjSharedSecret.Value.Memory.MsZ = MD5_DIGEST_LENGTH;
		WriteObject(&Browser, ObjSharedSecret);

		*Browser++ = RAW_PARAMS;
		*Browser++ = 0x05;

		ObjHash.Family = OBJ_FAMILY_NBR;
		ObjHash.Id = OBJ_ID_HASH;
		ObjHash.Value.Nbr = htonl(HashList[HashIdx]);
		WriteObject(&Browser, ObjHash);

		PlatForm = PlatFormSpecific();

		ObjPlatForm.Family = OBJ_FAMILY_TABLE;
		ObjPlatForm.Id = OBJ_ID_PLATFORM;
		memcpy_s(ObjPlatForm.Value.Table, sizeof(ObjPlatForm.Value.Table), (uchar *)&PlatForm, sizeof(ObjPlatForm.Value.Table));
		WriteObject(&Browser, ObjPlatForm);

		ObjUserName.Family = OBJ_FAMILY_STRING;
		ObjUserName.Id = OBJ_ID_USERNAME;
		ObjUserName.Value.Memory.Memory = (uchar *)User;
		ObjUserName.Value.Memory.MsZ = (uchar)strlen(User);
		WriteObject(&Browser, ObjUserName);

		ObjVer.Family = OBJ_FAMILY_STRING;
		ObjVer.Id = OBJ_ID_VERSION;
		ObjVer.Value.Memory.Memory = (uchar *)VER_STR;
		ObjVer.Value.Memory.MsZ = (uchar)strlen(VER_STR);
		WriteObject(&Browser, ObjVer);

		ObjPubAddr.Family = OBJ_FAMILY_NBR;
		ObjPubAddr.Id = OBJ_ID_PUBADDR;
		ObjPubAddr.Value.Nbr = htonl(my_public_ip);
		WriteObject(&Browser, ObjPubAddr);

		Size = (uint)(Browser - MarkObjL);
		HSHeader->ResponseLen = htons((ushort)Size + 0x02);

		Idx = 0;
		ZeroMemory(ivec, AES_BLOCK_SIZE);
		ZeroMemory(ecount_buf, AES_BLOCK_SIZE);
		AES_ctr128_encrypt(MarkObjL, MarkObjL, Size, &AesKey, ivec, ecount_buf, &Idx);

		Crc = crc32(MarkObjL, Size, -1);
		*Browser++ = *((uchar *)(&Crc) + 0);
		*Browser++ = *((uchar *)(&Crc) + 1);
	}

	Size = (uint)(Browser - Blob);
	
	if (SendPacketTCP(ESSock, CurES, Blob, Size, HTTPS_PORT, &Connected))
		printf("GET_HASH_DETAILS Response Got..\n\n");
	else
	{
		printf(":'(..\n");
		return ;
	}

	int AESsZ = 0;
	while (AESsZ < RecvBufferSz)
	{
		HSHeader = (HttpsPacketHeader *)(RecvBuffer + AESsZ);
		if (strncmp((const char *)HSHeader->MAGIC, HTTPS_HSRR_MAGIC, strlen(HTTPS_HSRR_MAGIC)))
		{
			printf("Bad Response..\n");
			return ;
		}

		Idx = 0;
		ZeroMemory(ivec, AES_BLOCK_SIZE);
		ZeroMemory(ecount_buf, AES_BLOCK_SIZE);
		ivec[3] = 0x01;
		ivec[7] = 0x01;
		((uint *)ivec)[3] = htonl(IvecIdx << 0x10);
		AES_ctr128_encrypt(RecvBuffer + AESsZ + sizeof(HttpsPacketHeader), RecvBuffer + AESsZ + sizeof(HttpsPacketHeader), htons(HSHeader->ResponseLen) - 0x02, &AesKey, ivec, ecount_buf, &Idx);
		IvecIdx++;

		uchar		*Buffer;
		uint		BSize;
		SResponse	Response;

		Buffer = RecvBuffer + AESsZ;
		BSize = htons(HSHeader->ResponseLen) + sizeof(HttpsPacketHeader);
		Response.Objs = NULL;
		Response.NbObj = 0;
		while ((int)BSize > 0)
		{
			MainArchResponseManager(&Buffer, &BSize, &Response);
			Buffer += 2;
		}

		char		Type = 0;
		uchar		*DisplayName = NULL;
		uchar		*InternalName = NULL;
		Memory_U	AuthCert;
		AuthCert.Memory = NULL;
		AuthCert.MsZ = 0;
		int			BuddyStatus = 0;
		Contact		CurC;

		ZeroMemory(&CurC, sizeof(CurC));
		CurC.Locations = new list<CLocation>;
		for (Idx = 0; Idx < Response.NbObj; Idx++)
		{
			switch (Response.Objs[Idx].Id)
			{
			case OBJ_ID_ESAUTHANSWR:
				printf("Obselete authentification auth response..\n");
				break;
			case OBJ_ID_DISPLAYNAME:
				uchar	*DName;

				DName = Response.Objs[Idx].Value.Memory.Memory;
				Type = *DName;
				switch (*DName)
				{
				case 'u':
					printf("User Contact displayname (%s)..\n", DName + 2);
					DisplayName = DName + 2;
					break;
				case 'g':
					printf("Group %s, actually ignored..\n", DName + 2);
					break;
				case 'p':
					if (strcmp((const char *)(DName + 2), "email") == 0)
						printf("Account email address as Blob..\n");
					else
						printf("Unmanaged p-type contact (%s)..\n", DName + 2);
					break;
				default :
					printf("Unmanaged contact type (%c)..\n", *DName);
					break;
				}
				break;
			case OBJ_ID_UBLOB:
				SResponse	BlobR;
				uchar		*Blob;

				Blob = Response.Objs[Idx].Value.Memory.Memory;
				ZeroMemory(&BlobR, sizeof(BlobR));
				BlobR.Objs = NULL;
				BlobR.NbObj = 0;
				printf("Contact Blob..\n");

				if (Type == 'p')
				{
					Email = Blob;
					cprintf(FOREGROUND_BLUE, "Our Email : %s\n", Email);
					break ;
				}

				ManageObjects(&Blob, Response.Objs[Idx].Value.Memory.MsZ, &BlobR);

				if (BlobR.NbObj == 0)
				{
					Email = Blob - 1;
					printf("Our Email : %s\n", Email);
				}
				else
				{
					for (uint BIdx = 0; BIdx < BlobR.NbObj; BIdx++)
					{
						switch (BlobR.Objs[BIdx].Id)
						{
							case OBJ_ID_INTERNALNAM:
								InternalName = BlobR.Objs[BIdx].Value.Memory.Memory;
								printf("Contact Internal Name : %s..\n", InternalName);
								break;
							case OBJ_ID_BUDDYSTATUS:
								BuddyStatus = BlobR.Objs[BIdx].Value.Nbr;
								printf("Contact Buddy Status : %d..(Friend / Pending)\n", BuddyStatus);
								break;
							case OBJ_ID_AUTHCERT:
								AuthCert = BlobR.Objs[BIdx].Value.Memory;
								printf("Contact Auth Cert Added..\n");
								
								uchar	*PostProcessed;
								char	*Key;
								uint	PPsZ, KeyIdx, Save;

 								PPsZ = htonl(*(uint *)BlobR.Objs[BIdx].Value.Memory.Memory) - 4;
								KeyIdx = htonl(*(uint *)(BlobR.Objs[BIdx].Value.Memory.Memory + 4));
								BlobR.Objs[BIdx].Value.Memory.Memory += 8;
								BlobR.Objs[BIdx].Value.Memory.MsZ -= 8;
								
								SkypeRSA = RSA_new();
								Key = KeySelect(KeyIdx);
								BN_hex2bn(&(SkypeRSA->n), Key);
								BN_hex2bn(&(SkypeRSA->e), "10001");
								BlobR.Objs[BIdx].Value.Memory.MsZ -= PPsZ;
								Save = PPsZ;
								ZeroMemory(UnRSA, 0xFFF);
								PPsZ = RSA_public_decrypt(PPsZ, BlobR.Objs[BIdx].Value.Memory.Memory, UnRSA, SkypeRSA, RSA_NO_PADDING);
								RSA_free(SkypeRSA);

								memcpy_s(RsaKey, MODULUS_SZ, UnRSA, MODULUS_SZ);
								
								int Suite;

								Suite = Save - PPsZ;
								BlobR.Objs[BIdx].Value.Memory.Memory += PPsZ;
								PostProcessed = FinalizeLoginDatas(UnRSA, &PPsZ, (Suite > 0) ? BlobR.Objs[BIdx].Value.Memory.Memory : NULL, Suite);
								if (PostProcessed == NULL)
								{
									printf("Bad Datas [Credentials] Finalization..\n");
									break;
								}

								SResponse LoginDatas;

								LoginDatas.Objs = NULL;
								LoginDatas.NbObj = 0;
								ManageObjects(&PostProcessed, PPsZ, &LoginDatas);

								for (uint LdIdx = 0; LdIdx < LoginDatas.NbObj; LdIdx++)
								{
									switch (LoginDatas.Objs[LdIdx].Id)
									{
										case OBJ_ID_LDMODULUS:
											if (LoginDatas.Objs[LdIdx].Family == OBJ_FAMILY_BLOB)
											{
												ZeroMemory(RsaKey, MODULUS_SZ);
												memcpy_s(RsaKey, MODULUS_SZ, LoginDatas.Objs[LdIdx].Value.Memory.Memory, LoginDatas.Objs[LdIdx].Value.Memory.MsZ);
												break;
											}
										default :
											printf("Non critical Object %d:%d..\n", LoginDatas.Objs[LdIdx].Family, LoginDatas.Objs[LdIdx].Id);
											break;
									}
								}

								//Save Contact LoginDatas (Credentials, Expriry, Login etc..)

								SkypeRSA = RSA_new();
								BN_hex2bn(&(SkypeRSA->n), Bin2HexStr(RsaKey, MODULUS_SZ));
								BN_hex2bn(&(SkypeRSA->e), "10001");
								PPsZ = BlobR.Objs[BIdx].Value.Memory.MsZ;
								BlobR.Objs[BIdx].Value.Memory.MsZ -= PPsZ;
								Save = PPsZ;
								ZeroMemory(UnRSA, 0xFFF);
								PPsZ = RSA_public_decrypt(PPsZ, BlobR.Objs[BIdx].Value.Memory.Memory, UnRSA, SkypeRSA, RSA_NO_PADDING);
								RSA_free(SkypeRSA);

								Suite = Save - PPsZ;
								BlobR.Objs[BIdx].Value.Memory.Memory += PPsZ;
								PostProcessed = FinalizeLoginDatas(UnRSA, &PPsZ, (Suite > 0) ? BlobR.Objs[BIdx].Value.Memory.Memory : NULL, Suite);
								if (PostProcessed == NULL)
								{
									printf("Bad Datas [ContactInfos] Finalization..\n");
									break;
								}

								PostProcessed += SHA_DIGEST_LENGTH;
								PPsZ -= SHA_DIGEST_LENGTH;
								
								if (strstr((char *)PostProcessed, (char *)"buddy_authorized"))
									printf("Buddy Authorized\n");
								else
									printf("Buddy UN-Authorized\n");
								break;
							default :
								printf("Non critical Object %d:%d in Blob..\n", BlobR.Objs[BIdx].Family, BlobR.Objs[BIdx].Id);
								break;
						}
					}
				}
				break;
			default :
				printf("Non critical Object %d:%d..\n", Response.Objs[Idx].Family, Response.Objs[Idx].Id);
				break;
			}
		}
		if ((Type = 'u') && (DisplayName != NULL) && (InternalName != NULL) && (AuthCert.Memory != NULL) && (AuthCert.MsZ != 0))
		{
			CurC.DisplayName = DisplayName;
			CurC.InternalName = InternalName;
			CurC.BuddyStatus = BuddyStatus;
			CurC.AuthCert = AuthCert;

			CurC.OnLineStatus = -1;
			Contacts.push(CurC);
		}
		AESsZ += sizeof(HttpsPacketHeader) + htons(HSHeader->ResponseLen);
	}
	printf("\n\n");
}

void	EventCheck(Host CurES, char *User)
{
	uchar			Request[0xFFF];
	ProbeHeader		*PHeader;
	ushort			TransID;
	uchar			*PRequest, *Mark;
	int				BaseSz;
	uint			PSize;
	ObjectDesc		ObjNbr, ObjUser, ObjVer, ObjPubAddr;
	SOCKET			ESUDPSock;
	sockaddr_in		LocalBind;
	
	ESUDPSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	ZeroMemory((char *)&LocalBind, sizeof(LocalBind));
	LocalBind.sin_family = AF_INET;
	LocalBind.sin_addr.s_addr = htonl(INADDR_ANY);
	LocalBind.sin_port = htons(DEF_LPORT);
	bind(ESUDPSock, (struct sockaddr *)&LocalBind, sizeof(LocalBind));

	BaseSz = 0x1F + (int)strlen(User);

	ZeroMemory(Request, 0xFFF);

	TransID = BytesRandomWord();
	PHeader = (ProbeHeader *)Request;
	PHeader->TransID = htons(TransID);
	PHeader->PacketType = PKT_TYPE_OBFSUK;
	PHeader->IV = htonl(GenIV());

	PRequest = Request + sizeof(*PHeader);
	Mark = PRequest;

	WriteValue(&PRequest, BaseSz);
	WriteValue(&PRequest, 0xBC02);
	*(unsigned short *)PRequest = htons(TransID - 1);
	PRequest += 2;

	*PRequest++ = RAW_PARAMS;
	WriteValue(&PRequest, 0x04);

	ObjNbr.Family = OBJ_FAMILY_NBR;
	ObjNbr.Id = 0x2D;
	ObjNbr.Value.Nbr = 0x00;
	WriteObject(&PRequest, ObjNbr);

	ObjUser.Family = OBJ_FAMILY_STRING;
	ObjUser.Id = 0x04;
	ObjUser.Value.Memory.Memory = (uchar *)User;
	ObjUser.Value.Memory.MsZ = (int)strlen(User);
	WriteObject(&PRequest, ObjUser);

	ObjVer.Family = OBJ_FAMILY_STRING;
	ObjVer.Id = OBJ_ID_VERSION;
	ObjVer.Value.Memory.Memory = (uchar *)VER_STR;
	ObjVer.Value.Memory.MsZ = (uchar)strlen(VER_STR);
	WriteObject(&PRequest, ObjVer);

	ObjPubAddr.Family = OBJ_FAMILY_NBR;
	ObjPubAddr.Id = OBJ_ID_PUBADDR;
	ObjPubAddr.Value.Nbr = htonl(my_public_ip);
	WriteObject(&PRequest, ObjPubAddr);

	PSize = (uint)(PRequest - Mark);

	PHeader->Crc32 = htonl(crc32(Mark, PSize, -1));

	Cipher(Mark, PSize, htonl(my_public_ip), htonl(inet_addr(CurES.ip)), htons(PHeader->TransID), htonl(PHeader->IV), 0);

	if (SendPacket(ESUDPSock, CurES, Request, sizeof(ProbeHeader) + PSize))
	{
		struct in_addr	PublicIP;

		PublicIP.S_un.S_addr = my_public_ip;
		if (UnCipherObfuscated(RecvBuffer, RecvBufferSz, inet_ntoa(PublicIP), CurES.ip) == 0)
		{
			printf("Unable to uncipher Packet..\n");
			return ;
		}
		printf("Ignored Event Server Notification..\n");
		showmem(RecvBuffer, RecvBufferSz);
		printf("\n\n");
	}
	else
	{
		printf("No Event Server Notification..\n");
		return ;
	}
}

void	EventContacts(char *User, char *Pass)
{
	uint		ReUse = 1;
	Host		CurES;
	uchar		*HashList;
	uint		NbHashes = 0;

	SetConsoleTitle("FakeSkype - Fetching Contact List..");

	InitESQueue();
	
	ESSock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(ESSock, SOL_SOCKET, SO_REUSEADDR, (const char *)&ReUse, sizeof(ReUse));

	while (!ESQueue.empty())
	{
		CurES = ESQueue.front();
		if (SendHandShake2ES(CurES))
		{
			EventCheck(CurES, User);
			printf("Event Server %s OK ! Let's authenticate..\n", CurES.ip);
			if (SendAuthentificationBlobES(CurES, User, Pass))
			{
				HashList = RequestHashList(CurES, User, Pass, &NbHashes);
				RequestHashListDetails(CurES, User, Pass, (uint *)HashList, NbHashes);
				closesocket(ESSock);
				return ;
			}
		}
		if (Connected)
			ResetESSock();
		ESQueue.pop();
	}

	closesocket(ESSock);

	printf("Event Contact Failed..\n");
	ExitProcess(0);
}