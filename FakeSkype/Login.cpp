#include "Login.h"

Host	LoginServers[] = {{"194.165.188.79", 33033},
						  {"193.88.6.13", 33033},
						  {"212.72.49.141", 33033},
						  {"80.160.91.5", 33033},
						  {"195.215.8.141", 33033},
						  {0, 0}
				         };

queue<Host>		LSQueue;
SOCKET			LSSock;
SLoginDatas		GLoginD;
static int		Connected = 0;

void	InitLSQueue()
{
	int	Idx;
	
	for (Idx = 0; (LoginServers[Idx].port != 0); Idx++)
		LSQueue.push(LoginServers[Idx]);
}

void	ResetLSSock()
{
	uint	ReUse;

	ReUse = 1;
	Connected = 0;
	closesocket(LSSock);
	LSSock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(LSSock, SOL_SOCKET, SO_REUSEADDR, (const char *)&ReUse, sizeof(ReUse));
}

int		SendHandShake2LS(Host CurLS)
{
	uchar				HandShakePkt[HANDSHAKE_SZ] = {0};
	HttpsPacketHeader	*HSHeader;

	HSHeader = (HttpsPacketHeader *)HandShakePkt;
	memcpy_s(HSHeader->MAGIC, sizeof(HSHeader->MAGIC), HTTPS_HSR_MAGIC, strlen(HTTPS_HSR_MAGIC));
	HSHeader->ResponseLen = htons(0x00);
	printf("Sending Handshake to Login Server %s..\n", CurLS.ip);
	SuperWait = 2;
	if (SendPacketTCP(LSSock, CurLS, HandShakePkt, HANDSHAKE_SZ, HTTPS_PORT, &Connected))
	{
		printf("HandShake Response..\n");
		//showmem(RecvBuffer, RecvBufferSz);
		//printf("\n");
		return (1);
	}
	else
		return (0);
}

int	SendAuthentificationBlobLS(Host CurLS, char *User, char *Pass)
{
	double				PlatForm;
	uchar				AuthBlob[0xFFFF] = {0};
	uchar				MD5Result[MD5_DIGEST_LENGTH] = {0};
	uchar				SHAResult[32] = {0};
	uchar				SessionKey[SK_SZ] = {0};
	uchar				Modulus[MODULUS_SZ * 2] = {0};
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
	RSA					*Keys;
	RSA					*SkypeRSA;
	ObjectDesc			Obj2000, ObjSessionKey, ObjZBool1, ObjRequestCode, ObjZBool2, ObjUserName, ObjSharedSecret, ObjModulus, ObjPlatForm, ObjLang, ObjMiscDatas, ObjVer, ObjPubAddr;

	printf("Generating RSA Keys Pair (Size = %d Bits)..\n", KEYSZ);
	Keys = RSA_generate_key(KEYSZ * 2, RSA_F4, NULL, NULL);
	if (Keys == NULL)
	{
		printf("Error generating Keys..\n\n");
		return (0);
	}

	//printf("Modulus N..\n");
	Idx = BN_bn2bin(Keys->n, Modulus);
	//showmem(Modulus, MODULUS_SZ);
	//printf("Modulus D\n");
	Idx = BN_bn2bin(Keys->d, Modulus + Idx);
	//showmem(Modulus + MODULUS_SZ, MODULUS_SZ);
	//printf("\n");

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
	ObjRequestCode.Value.Nbr = 0x1399;
	WriteObject(&Browser, ObjRequestCode);

	ObjZBool2.Family = OBJ_FAMILY_NBR;
	ObjZBool2.Id = OBJ_ID_ZBOOL2;
	ObjZBool2.Value.Nbr = 0x01;
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
	*Browser++ = 0x06;

	ObjModulus.Family = OBJ_FAMILY_BLOB;
	ObjModulus.Id = OBJ_ID_MODULUS;
	ObjModulus.Value.Memory.Memory = (uchar *)Modulus;
	ObjModulus.Value.Memory.MsZ = MODULUS_SZ;
	WriteObject(&Browser, ObjModulus);

	PlatForm = PlatFormSpecific();

	ObjPlatForm.Family = OBJ_FAMILY_TABLE;
	ObjPlatForm.Id = OBJ_ID_PLATFORM;
	memcpy_s(ObjPlatForm.Value.Table, sizeof(ObjPlatForm.Value.Table), (uchar *)&PlatForm, sizeof(ObjPlatForm.Value.Table));
	WriteObject(&Browser, ObjPlatForm);

	ObjLang.Family = OBJ_FAMILY_STRING;
	ObjLang.Id = OBJ_ID_LANG;
	ObjLang.Value.Memory.Memory = (uchar *)LANG_STR;
	ObjLang.Value.Memory.MsZ = (uchar)strlen(LANG_STR);
	WriteObject(&Browser, ObjLang);

	FillMiscDatas(MiscDatas);
	ObjMiscDatas.Family = OBJ_FAMILY_INTLIST;
	ObjMiscDatas.Id = OBJ_ID_MISCD;
	ObjMiscDatas.Value.Memory.Memory = (uchar *)MiscDatas;
	ObjMiscDatas.Value.Memory.MsZ = 0x05;
	WriteObject(&Browser, ObjMiscDatas);

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

	SuperWait = 1;
	if (SendPacketTCP(LSSock, CurLS, AuthBlob, Size, HTTPS_PORT, &Connected))
		printf("Auth Response Got..\n\n");
	else
	{
		printf(":'(..\n");
		return (-1);
	}

	/*unsigned char data[222] = {
	0x17, 0x03, 0x01, 0x00, 0xD9, 0x73, 0xC4, 0x06, 0x08, 0xFF, 0x1F, 0xFE, 0xED, 0x64, 0xB8, 0x49, 
	0x4D, 0xD8, 0xBE, 0xCD, 0xC9, 0xEF, 0x63, 0x74, 0x6D, 0x7F, 0x1D, 0x9B, 0xE6, 0x91, 0xFC, 0x14, 
	0xC6, 0x01, 0xDD, 0x79, 0xD6, 0xEA, 0x3B, 0xB3, 0xB6, 0x20, 0x03, 0x5E, 0x05, 0xEB, 0xFC, 0xAA, 
	0x46, 0x35, 0x7B, 0xAF, 0x5A, 0x59, 0x01, 0xFA, 0xBB, 0xB6, 0x1F, 0x81, 0x6D, 0x34, 0x85, 0x39, 
	0x93, 0xBB, 0x9B, 0x5B, 0xCC, 0x21, 0xD4, 0xCC, 0x85, 0x39, 0x27, 0x62, 0x69, 0xBC, 0x05, 0x48, 
	0xF2, 0x19, 0x88, 0xD3, 0x86, 0xD3, 0x10, 0x0D, 0xE1, 0x36, 0x08, 0x14, 0xC9, 0xC3, 0x52, 0x8B, 
	0x86, 0x42, 0x8D, 0x1F, 0x25, 0x02, 0x2E, 0x82, 0x48, 0xDC, 0x0C, 0x5C, 0x66, 0x5E, 0x34, 0x1A, 
	0x00, 0x3B, 0x4F, 0x6D, 0x54, 0x2E, 0x02, 0x91, 0x3E, 0xE1, 0xD7, 0x47, 0xC9, 0x04, 0xA0, 0xB2, 
	0xBD, 0x60, 0x49, 0xE1, 0xB8, 0x79, 0xB3, 0x1A, 0xE5, 0x14, 0x12, 0xC8, 0x0C, 0x37, 0xB3, 0x23, 
	0x2E, 0xBD, 0xD7, 0x9F, 0x47, 0xA3, 0xE1, 0xAD, 0x21, 0xEF, 0xF0, 0x79, 0x7E, 0x72, 0x28, 0x29, 
	0xCA, 0xAF, 0x29, 0xDD, 0xE4, 0xDC, 0x2C, 0x9C, 0x52, 0x07, 0xC5, 0x33, 0x9D, 0x65, 0xE3, 0x06, 
	0x14, 0x12, 0xEA, 0xF7, 0x7F, 0x1B, 0x79, 0xA2, 0x65, 0xA2, 0x5C, 0x68, 0x74, 0x13, 0x97, 0x41, 
	0xFE, 0x83, 0x2B, 0x13, 0x56, 0x56, 0x57, 0x1F, 0xCC, 0x65, 0xA0, 0x46, 0xEA, 0x0C, 0x18, 0x8B, 
	0x59, 0x9C, 0xE1, 0x9E, 0x59, 0x68, 0x43, 0x94, 0x2D, 0x1E, 0xC3, 0x4F, 0x7F, 0x04
	};

	ZeroMemory(RecvBuffer, sizeof(RecvBuffer));
	memcpy_s(RecvBuffer, sizeof(RecvBuffer), data, sizeof(data));*/

	HSHeader = (HttpsPacketHeader *)RecvBuffer;
	if (strncmp((const char *)HSHeader->MAGIC, HTTPS_HSRR_MAGIC, strlen(HTTPS_HSRR_MAGIC)))
	{
		printf("Bad Response..\n");
		return (-1);
	}

	Idx = 0;
	ZeroMemory(ivec, AES_BLOCK_SIZE);
	ZeroMemory(ecount_buf, AES_BLOCK_SIZE);
	ivec[3] = 0x01;
	ivec[7] = 0x01;
	AES_ctr128_encrypt(RecvBuffer + sizeof(HttpsPacketHeader), RecvBuffer + sizeof(HttpsPacketHeader), htons(HSHeader->ResponseLen) - 0x02, &AesKey, ivec, ecount_buf, &Idx);
	
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
		case OBJ_ID_LOGINANSWER:
			switch (Response.Objs[Idx].Value.Nbr)
			{
			case LOGIN_OK:
				cprintf(FOREGROUND_BLUE, "Login Successful..\n");
				GLoginD.RSAKeys = Keys;
				break;
			default :
				cprintf(FOREGROUND_RED, "Login Failed.. Bad Credentials..\n");
				ExitProcess(0);
				break;
			}
			break;
		case OBJ_ID_CIPHERDLOGD:
			GLoginD.SignedCredentials.Memory = MemDup(Response.Objs[Idx].Value.Memory.Memory, Response.Objs[Idx].Value.Memory.MsZ);
			GLoginD.SignedCredentials.MsZ = Response.Objs[Idx].Value.Memory.MsZ;
			
			uchar	*PostProcessed;
			char	*Key;
			uint	KeyIdx, PPsZ;

			KeyIdx = htonl(*(uint *)Response.Objs[Idx].Value.Memory.Memory);
			Response.Objs[Idx].Value.Memory.Memory += 4;
			Response.Objs[Idx].Value.Memory.MsZ -= 4;
			
			SkypeRSA = RSA_new();
			Key = KeySelect(KeyIdx);
			BN_hex2bn(&(SkypeRSA->n), Key);
			BN_hex2bn(&(SkypeRSA->e), "10001");
			PPsZ = RSA_public_decrypt(Response.Objs[Idx].Value.Memory.MsZ, Response.Objs[Idx].Value.Memory.Memory, Response.Objs[Idx].Value.Memory.Memory, SkypeRSA, RSA_NO_PADDING);
			RSA_free(SkypeRSA);
			
			PostProcessed = FinalizeLoginDatas(Response.Objs[Idx].Value.Memory.Memory, &PPsZ, NULL, 0);
			Response.Objs[Idx].Value.Memory.Memory += PPsZ;

			if (PostProcessed == NULL)
			{
				printf("Bad Datas Finalization..\n");
				return (0);
			}
			//showmem(PostProcessed, PPsZ);
			//printf("\n");

			SResponse LoginDatas;

			LoginDatas.Objs = NULL;
			LoginDatas.NbObj = 0;
			ManageObjects(&PostProcessed, PPsZ, &LoginDatas);

			for (uint LdIdx = 0; LdIdx < LoginDatas.NbObj; LdIdx++)
			{
				switch (LoginDatas.Objs[LdIdx].Id)
				{
					case OBJ_ID_LDUSER:
						GLoginD.User = LoginDatas.Objs[LdIdx].Value.Memory.Memory;
						break;
					case OBJ_ID_LDEXPIRY:
						GLoginD.Expiry = LoginDatas.Objs[LdIdx].Value.Nbr;
						break;
					case OBJ_ID_LDMODULUS:
						GLoginD.Modulus = LoginDatas.Objs[LdIdx].Value.Memory;
						//showmem(LoginDatas.Objs[LdIdx].Value.Memory.Memory, LoginDatas.Objs[LdIdx].Value.Memory.MsZ);
						//printf("\n\n");
						break;
					default :
						printf("Non critical Object %d:%d..\n", LoginDatas.Objs[LdIdx].Family, LoginDatas.Objs[LdIdx].Id);
						break;
				}
			}
			cprintf(FOREGROUND_BLUE, "User <%s> Logged in.. Credentials Expiry : %d\n", GLoginD.User, GLoginD.Expiry);
			cprintf(FOREGROUND_BLUE, "Login Data Saved..\n");
			break;
		default :
			printf("Non critical Object %d:%d..\n", Response.Objs[Idx].Family, Response.Objs[Idx].Id);
			break;
		}
	}

	printf("\n\n");
	return (1);
}

void	PerformLogin(char *User, char *Pass)
{ 
	uint			ReUse = 1;
	int				LogRes;
	Host			CurLS;

	SetConsoleTitle("FakeSkype - Performing Login..");

	InitLSQueue();
	
	LSSock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(LSSock, SOL_SOCKET, SO_REUSEADDR, (const char *)&ReUse, sizeof(ReUse));

	while (!LSQueue.empty())
	{
		CurLS = LSQueue.front();
		if (SendHandShake2LS(CurLS))
		{
			/*LogRes = -1;
			while (LogRes == -1)
			{*/
				printf("Login Server %s OK ! Let's authenticate..\n", CurLS.ip);
				LogRes = SendAuthentificationBlobLS(CurLS, User, Pass);

				if (LogRes == 1)
				{
					closesocket(LSSock);
					return ;
				}

				/*if (LogRes == -1)
				{
					if (Connected)
						ResetLSSock();
					Sleep(5000);
					SendHandShake2LS(CurLS);
				}
			}*/
		}
		if (Connected)
			ResetLSSock();
		LSQueue.pop();
	}

	closesocket(LSSock);
	
	printf("Login Failed..\n");
	ExitProcess(0);
}