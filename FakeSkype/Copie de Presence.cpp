#include "Presence.h"

Host	EventServers[] = {{"212.72.49.142", 12350},
						  {"195.215.8.142", 12350},
						  {0, 0}
				         };

queue<Host>		ESQueue;
SOCKET			ESSock;

void	InitESQueue()
{
	int	Idx;
	
	for (Idx = 0; (EventServers[Idx].port != 0); Idx++)
		ESQueue.push(EventServers[Idx]);
}

int		 SendPresenceCore(char *UserName, Host CurES)
{
	/*double				PlatForm;
	uchar				AuthBlob[0xFFFF] = {0};
	uchar				MD5Result[MD5_DIGEST_LENGTH] = {0};
	uchar				SHAResult[32] = {0};
	uchar				SessionKey[SK_SZ] = {0};
	uchar				Modulus[MODULUS_SZ] = {0};
	uchar				ivec[AES_BLOCK_SIZE] = {0};
	uchar				ecount_buf[AES_BLOCK_SIZE] = {0};
	uint				MiscDatas[0x05] = {0};
	uchar				*Browser;
	uchar				*Mark;
	uchar				*MarkObjL;
	uint				Idx, Rander, Size, Crc;
	HttpsPacketHeader	*HSHeader;
	AES_KEY				AesKey;
	MD5_CTX				Context;
	RSA					*Keys;
	RSA					*SkypeRSA;
	ObjectDesc			Obj2000, ObjSessionKey, ObjZBool1, ObjRequestCode, ObjZBool2, ObjUserName, ObjSharedSecret, ObjModulus, ObjPlatForm, ObjLang, ObjMiscDatas, ObjVer, ObjPubAddr;

	printf("Generating RSA Keys Pair (Size = %d Bits)..\n", KEYSZ);
	Keys = RSA_generate_key(KEYSZ, RSA_F4, NULL, NULL);
	if (Keys == NULL)
		printf("Error generating Keys..\n\n");
	else
	{
		printf("Keys Generated..\n");
		printf("RSA Size = %d\n", RSA_size(Keys));
		printf("Public Modulus (N):\n");
        printf("%s\n",BN_bn2hex(Keys->n));
        printf("Public Exponent (E):\n");
        printf("%s\n",BN_bn2hex(Keys->e));
        printf("Private Exponent (D):\n");
        printf("%s\n",BN_bn2hex(Keys->d));
		printf("\n\n");
	}
	
	Idx = BN_bn2bin(Keys->n, Modulus);
	Idx = BN_bn2bin(Keys->d, Modulus + Idx);

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

	Rander = BytesRandom();
	for (Idx = 0; Idx < SK_SZ; Idx++)
	{
		Rander = Update(Rander);
		SessionKey[Idx] = ((uchar *)&Rander)[sizeof(Rander) - 1];
		//SessionKey[Idx] = (uchar)(Idx + 1);
	}

	SpecialSHA(SessionKey, SHAResult);
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
	showmem(AuthBlob, Size);

	if (SendPacketTCP(LSSock, CurLS, AuthBlob, Size, HTTPS_PORT, &Connected))
	{
		printf("Auth Response..\n\n");
		showmem(RecvBuffer, RecvBufferSz);
		printf("\n\n");
	}
	else
	{
		printf(":'(..\n");
		return ;
	}

	HSHeader = (HttpsPacketHeader *)RecvBuffer;
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
	AES_ctr128_encrypt(RecvBuffer + sizeof(HttpsPacketHeader), RecvBuffer + sizeof(HttpsPacketHeader), htons(HSHeader->ResponseLen) - 0x02, &AesKey, ivec, ecount_buf, &Idx);
	printf("[UNCIPHERED]Auth Response..\n\n");
	showmem(RecvBuffer, RecvBufferSz);
	printf("\n\n");*/
	return (0);
}

void	 SendPresence(char *UserName)
{
	Host			CurES;

	InitESQueue();
	
	ESSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	
	while (!ESQueue.empty())
	{
		CurES = ESQueue.front();
		if (SendPresenceCore(UserName, CurES))
		{
			printf("Presence successfully sent to %s:%d via UDP..\n", CurES.ip, CurES.port);
			Sleep(1200000);
			return ;
		}
		ESQueue.pop();
	}
	closesocket(ESSock);
}