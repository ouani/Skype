#include "DirBlobManager.h"

int					DirBlob2Contact(uchar *DirBlob, uint DbSize, Contact *DestContact)
{
	uchar			UnRSA[0xFFF];
	uchar			RsaKey[MODULUS_SZ] = {0};
	RSA				*SkypeRSA;
	uchar			*PostProcessed;
	char			*Key;
	uint			PPsZ, KeyIdx, Save;
	int				Suite;

	PPsZ = htonl(*(uint *)DirBlob) - 4;
	KeyIdx = htonl(*(uint *)(DirBlob + 4));
	DirBlob += 8;
	DbSize -= 8;
	
	SkypeRSA = RSA_new();
	Key = KeySelect(KeyIdx);
	BN_hex2bn(&(SkypeRSA->n), Key);
	BN_hex2bn(&(SkypeRSA->e), "10001");
	DbSize -= PPsZ;
	Save = PPsZ;
	ZeroMemory(UnRSA, 0xFFF);
	PPsZ = RSA_public_decrypt(PPsZ, DirBlob, UnRSA, SkypeRSA, RSA_NO_PADDING);
	RSA_free(SkypeRSA);
	
	Suite = Save - PPsZ;
	DirBlob += PPsZ;
	PostProcessed = FinalizeLoginDatas(UnRSA, &PPsZ, ((Save - PPsZ) > 0) ? DirBlob : NULL, (Save - PPsZ));
	if (PostProcessed == NULL)
	{
		printf("Bad Datas [Credentials] Finalization..\n");
		return (0);
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
					DestContact->RsaPubKey = LoginDatas.Objs[LdIdx].Value.Memory;
					break;
				}
				break;
			case OBJ_ID_PEERLOGIN:
				DestContact->DisplayName = (uchar *)_strdup((char *)LoginDatas.Objs[LdIdx].Value.Memory.Memory);
				DestContact->InternalName = (uchar *)_strdup((char *)LoginDatas.Objs[LdIdx].Value.Memory.Memory);
				break;
			default :
				printf("Non critical Object %d:%d..\n", LoginDatas.Objs[LdIdx].Family, LoginDatas.Objs[LdIdx].Id);
				break;
		}
	}

	SkypeRSA = RSA_new();
	BN_hex2bn(&(SkypeRSA->n), Bin2HexStr(RsaKey, MODULUS_SZ));
	BN_hex2bn(&(SkypeRSA->e), "10001");
	PPsZ = DbSize;
	DbSize -= PPsZ;
	Save = PPsZ;
	PPsZ = 0x80;
	ZeroMemory(UnRSA, 0xFFF);
	PPsZ = RSA_public_decrypt(PPsZ, DirBlob, UnRSA, SkypeRSA, RSA_NO_PADDING);
	RSA_free(SkypeRSA);

	Suite = Save - PPsZ;
	DirBlob += PPsZ;
	PostProcessed = FinalizeLoginDatas(UnRSA, &PPsZ, (Suite > 0) ? DirBlob : NULL, Suite);
	if (PostProcessed == NULL)
	{
		printf("Bad Datas [METADATAS] Finalization..\n");
		return (0);
	}

	PostProcessed += SHA_DIGEST_LENGTH;
	PPsZ -= SHA_DIGEST_LENGTH;

	SResponse ContactInfos;

	ContactInfos.Objs = NULL;
	ContactInfos.NbObj = 0;
	ManageObjects(&PostProcessed, PPsZ, &ContactInfos);

	for (uint CiIdx = 0; CiIdx < ContactInfos.NbObj; CiIdx++)
	{
		switch (ContactInfos.Objs[CiIdx].Id)
		{
			case OBJ_ID_CIRNAME:
				DestContact->RealDName = _strdup((char *)ContactInfos.Objs[CiIdx].Value.Memory.Memory);
				break;
			case OBJ_ID_CILANG:
				DestContact->Langue = _strdup((char *)ContactInfos.Objs[CiIdx].Value.Memory.Memory);
				break;
			case OBJ_ID_CIREGION:
				DestContact->Region = _strdup((char *)ContactInfos.Objs[CiIdx].Value.Memory.Memory);
				break;
			case OBJ_ID_CIVILLE:
				DestContact->Ville = _strdup((char *)ContactInfos.Objs[CiIdx].Value.Memory.Memory);
				break;
			case OBJ_ID_CILOCATION:
				CLocation		ContactLocation;

				LocationBlob2Location(ContactInfos.Objs[CiIdx].Value.Memory.Memory, &ContactLocation, ContactInfos.Objs[CiIdx].Value.Memory.MsZ);
				DestContact->Locations->push_back(ContactLocation);
				break;
			default :
				break;
		}
	}
	return (1);
}

Memory_U			GetDirBlobMetaDatas(uchar *DirBlob, uint DbSize)
{
	uchar			UnRSA[0xFFF];
	uchar			RsaKey[MODULUS_SZ] = {0};
	RSA				*SkypeRSA;
	uchar			*PostProcessed;
	char			*Key;
	uint			PPsZ, KeyIdx, Save;
	int				Suite;
	Memory_U		Result;

	Result.Memory = NULL;
	Result.MsZ = 0;

	PPsZ = htonl(*(uint *)DirBlob) - 4;
	KeyIdx = htonl(*(uint *)(DirBlob + 4));
	DirBlob += 8;
	DbSize -= 8;
	
	SkypeRSA = RSA_new();
	Key = KeySelect(KeyIdx);
	BN_hex2bn(&(SkypeRSA->n), Key);
	BN_hex2bn(&(SkypeRSA->e), "10001");
	DbSize -= PPsZ;
	Save = PPsZ;
	ZeroMemory(UnRSA, 0xFFF);
	PPsZ = RSA_public_decrypt(PPsZ, DirBlob, UnRSA, SkypeRSA, RSA_NO_PADDING);
	RSA_free(SkypeRSA);
	
	Suite = Save - PPsZ;
	DirBlob += PPsZ;
	PostProcessed = FinalizeLoginDatas(UnRSA, &PPsZ, ((Save - PPsZ) > 0) ? DirBlob : NULL, (Save - PPsZ));
	if (PostProcessed == NULL)
	{
		printf("Bad Datas [Credentials] Finalization..\n");
		return (Result);
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
				break;
		}
	}

	SkypeRSA = RSA_new();
	BN_hex2bn(&(SkypeRSA->n), Bin2HexStr(RsaKey, MODULUS_SZ));
	BN_hex2bn(&(SkypeRSA->e), "10001");
	PPsZ = DbSize;
	DbSize -= PPsZ;
	Save = PPsZ;
	PPsZ = 0x80;
	ZeroMemory(UnRSA, 0xFFF);
	PPsZ = RSA_public_decrypt(PPsZ, DirBlob, UnRSA, SkypeRSA, RSA_NO_PADDING);
	RSA_free(SkypeRSA);

	Suite = Save - PPsZ;
	DirBlob += PPsZ;
	PostProcessed = FinalizeLoginDatas(UnRSA, &PPsZ, (Suite > 0) ? DirBlob : NULL, Suite);
	if (PostProcessed == NULL)
	{
		printf("Bad Datas [METADATAS] Finalization..\n");
		return (Result);
	}

	PostProcessed += SHA_DIGEST_LENGTH;
	PPsZ -= SHA_DIGEST_LENGTH;

	Result.Memory = PostProcessed;
	Result.MsZ = PPsZ;

	return (Result);
}

void				DumpDirBlobMetaDatas(uchar *DirBlob, uint DbSize)
{
	uchar			UnRSA[0xFFF];
	uchar			RsaKey[MODULUS_SZ] = {0};
	RSA				*SkypeRSA;
	uchar			*PostProcessed;
	char			*Key;
	uint			PPsZ, KeyIdx, Save;
	int				Suite;

	PPsZ = htonl(*(uint *)DirBlob) - 4;
	KeyIdx = htonl(*(uint *)(DirBlob + 4));
	DirBlob += 8;
	DbSize -= 8;
	
	SkypeRSA = RSA_new();
	Key = KeySelect(KeyIdx);
	BN_hex2bn(&(SkypeRSA->n), Key);
	BN_hex2bn(&(SkypeRSA->e), "10001");
	DbSize -= PPsZ;
	Save = PPsZ;
	ZeroMemory(UnRSA, 0xFFF);
	PPsZ = RSA_public_decrypt(PPsZ, DirBlob, UnRSA, SkypeRSA, RSA_NO_PADDING);
	RSA_free(SkypeRSA);
	
	Suite = Save - PPsZ;
	DirBlob += PPsZ;
	PostProcessed = FinalizeLoginDatas(UnRSA, &PPsZ, ((Save - PPsZ) > 0) ? DirBlob : NULL, (Save - PPsZ));
	if (PostProcessed == NULL)
	{
		printf("Bad Datas [Credentials] Finalization..\n");
		return ;
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
					showmem(RsaKey, MODULUS_SZ);
					break;
				}
			default :
				printf("Non critical Object %d:%d..\n", LoginDatas.Objs[LdIdx].Family, LoginDatas.Objs[LdIdx].Id);
				break;
		}
	}

	SkypeRSA = RSA_new();
	BN_hex2bn(&(SkypeRSA->n), Bin2HexStr(RsaKey, MODULUS_SZ));
	BN_hex2bn(&(SkypeRSA->e), "10001");
	PPsZ = DbSize;
	DbSize -= PPsZ;
	Save = PPsZ;
	PPsZ = 0x80;
	ZeroMemory(UnRSA, 0xFFF);
	PPsZ = RSA_public_decrypt(PPsZ, DirBlob, UnRSA, SkypeRSA, RSA_NO_PADDING);
	RSA_free(SkypeRSA);

	Suite = Save - PPsZ;
	DirBlob += PPsZ;
	PostProcessed = FinalizeLoginDatas(UnRSA, &PPsZ, (Suite > 0) ? DirBlob : NULL, Suite);
	if (PostProcessed == NULL)
	{
		printf("Bad Datas [METADATAS] Finalization..\n");
		return ;
	}

	PostProcessed += SHA_DIGEST_LENGTH;
	PPsZ -= SHA_DIGEST_LENGTH;

	SResponse MetaDatas;

	MetaDatas.Objs = NULL;
	MetaDatas.NbObj = 0;
	ManageObjects(&PostProcessed, PPsZ, &MetaDatas);

	for (uint CiIdx = 0; CiIdx < MetaDatas.NbObj; CiIdx++)
	{
		DumpObj(MetaDatas.Objs[CiIdx]);
	}
}