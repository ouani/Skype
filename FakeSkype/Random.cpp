#include "Random.h"

static BYTE		RandomSeed[SHA_DIGEST_LENGTH] = {0};
static uchar	SessionKey[SK_SZ] = {0};

unsigned int	BytesSHA1(BYTE *Data, DWORD Length)
{
	BYTE		Buffer[SHA_DIGEST_LENGTH];
	SHA_CTX		Context;

	SHA1_Init(&Context);
	SHA1_Update(&Context, Data, Length);
	SHA1_Final(Buffer, &Context);
	return *(unsigned int *)Buffer;
}

double			BytesSHA1d(BYTE *Data, DWORD Length)
{
	BYTE		Buffer[SHA_DIGEST_LENGTH];
	SHA_CTX		Context;

	SHA1_Init(&Context);
	SHA1_Update(&Context, Data, Length);
	SHA1_Final(Buffer, &Context);
	return *(double *)Buffer;
}

unsigned int	BytesRandom()
{
	BYTE		Buffer[0x464];
	SHA_CTX		Context;
	int			idx;

	idx = 0;
	memcpy(Buffer, RandomSeed, SHA_DIGEST_LENGTH);
	idx += sizeof(RandomSeed);
	GlobalMemoryStatus((LPMEMORYSTATUS)&Buffer[idx]);
	idx += sizeof(MEMORYSTATUS);
	UuidCreate((UUID *)&Buffer[idx]);
	idx += sizeof(UUID);
	GetCursorPos((LPPOINT)&Buffer[idx]);
	idx += sizeof(POINT);
	*(DWORD *)(Buffer + idx) = GetTickCount();
	*(DWORD *)(Buffer + idx + 4) = GetMessageTime();
	*(DWORD *)(Buffer + idx + 8) = GetCurrentThreadId();
	*(DWORD *)(Buffer + idx + 12) = GetCurrentProcessId();
	idx += 16;
	QueryPerformanceCounter((LARGE_INTEGER *)&Buffer[idx]);
	SHA1_Init(&Context);
	SHA1_Update(&Context, Buffer, 0x464);
	SHA1_Update(&Context, "additional salt...", 0x13);
	SHA1_Final(RandomSeed, &Context);
	return BytesSHA1(Buffer, 0x464);
}

double		BytesRandomD()
{
	BYTE		Buffer[0x464];
	SHA_CTX		Context;
	int			idx;

	idx = 0;
	memcpy(Buffer, RandomSeed, SHA_DIGEST_LENGTH);
	idx += sizeof(RandomSeed);
	GlobalMemoryStatus((LPMEMORYSTATUS)&Buffer[idx]);
	idx += sizeof(MEMORYSTATUS);
	UuidCreate((UUID *)&Buffer[idx]);
	idx += sizeof(UUID);
	GetCursorPos((LPPOINT)&Buffer[idx]);
	idx += sizeof(POINT);
	*(DWORD *)(Buffer + idx) = GetTickCount();
	*(DWORD *)(Buffer + idx + 4) = GetMessageTime();
	*(DWORD *)(Buffer + idx + 8) = GetCurrentThreadId();
	*(DWORD *)(Buffer + idx + 12) = GetCurrentProcessId();
	idx += 16;
	QueryPerformanceCounter((LARGE_INTEGER *)&Buffer[idx]);
	SHA1_Init(&Context);
	SHA1_Update(&Context, Buffer, 0x464);
	SHA1_Update(&Context, "additional salt...", 0x13);
	SHA1_Final(RandomSeed, &Context);
	return BytesSHA1d(Buffer, 0x464);
}

unsigned short		BytesRandomWord()
{
	unsigned short	RandomW;
	unsigned int	RandomDW;

	RandomDW = BytesRandom();
	RandomW = *(unsigned short *)&RandomDW;
	RandomW += 0;
	return (RandomW);
}

unsigned char	    *GetNodeId();

double				PlatFormSpecific()
{
	BYTE		Buffer[0x400];
	HKEY		rKey;
	DWORD		BufSz = 0x400;
	int			Idx, Used, ret;

	Used = Idx = 0;
	ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion", 0, KEY_QUERY_VALUE, &rKey);
	if (ret)
		return (0);
	ret = RegQueryValueExA(rKey, "ProductId", NULL, NULL, (LPBYTE)Buffer, &BufSz);
	if (ret)
		return (0);
	RegCloseKey(rKey);

	Used += BufSz;
	ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\8\\DiskController\\0\\DiskPeripheral\\0", 0, KEY_QUERY_VALUE, &rKey);
	if (ret)
		return (0);
	ret = RegQueryValueExA(rKey, "Identifier", NULL, NULL, (LPBYTE)Buffer + Used, &BufSz);
	if (ret)
		return (0);
	RegCloseKey(rKey);

	Used += BufSz;
	ret = GetVolumeInformationA("C:\\", 0, 0, (LPDWORD)(Buffer + Used), 0, 0, 0, 0);
	return BytesSHA1d(Buffer, Used + 0x04);
}

void				FillMiscDatas(unsigned int *Datas)
{
	BYTE		Buffer[0x400];
	HKEY		rKey;
	DWORD		BufSz = 0x400;
	int			ret;
	double		PlatForm;

	PlatForm = PlatFormSpecific();
	Datas[0] = *(unsigned int *)&PlatForm;
	Datas[1] = *(unsigned int *)GetNodeId();

	ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion", 0, KEY_QUERY_VALUE, &rKey);
	if (ret)
		return ;
	ret = RegQueryValueExA(rKey, "ProductId", NULL, NULL, (LPBYTE)Buffer, &BufSz);
	if (ret)
		return ;
	RegCloseKey(rKey);
	Datas[2] = BytesSHA1(Buffer, BufSz);

	ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\8\\DiskController\\0\\DiskPeripheral\\0", 0, KEY_QUERY_VALUE, &rKey);
	if (ret)
		return ;
	ret = RegQueryValueExA(rKey, "Identifier", NULL, NULL, (LPBYTE)Buffer, &BufSz);
	if (ret)
		return ;
	RegCloseKey(rKey);
	Datas[3] = BytesSHA1(Buffer, BufSz);

	ret = GetVolumeInformationA("C:\\", 0, 0, (LPDWORD)Buffer, 0, 0, 0, 0);
	Datas[4] = BytesSHA1(Buffer, 0x04);
}

void	SpecialSHA(uchar *SessionKey, uint SkSz, uchar *SHAResult, uint ResSz)
{
	SHA_CTX		Context;
	uchar		Buffer[SHA_DIGEST_LENGTH];
	char		*Salts[] = {"\x00\x00\x00\x00", "\x00\x00\x00\x01"};
	uint		Idx = 0;
	uint		ResSzSave = ResSz;

	if (ResSz > 40)
		return ;
	while (ResSz > 20)
	{
		SHA1_Init(&Context);
		SHA1_Update(&Context, Salts[Idx], 0x04);
		SHA1_Update(&Context, SessionKey, SkSz);
		SHA1_Final(Buffer, &Context);
		memcpy_s(SHAResult + (Idx * SHA_DIGEST_LENGTH), ResSzSave, Buffer, SHA_DIGEST_LENGTH);
		Idx++;
		ResSz -= SHA_DIGEST_LENGTH;
	}

	SHA1_Init(&Context);
	SHA1_Update(&Context, Salts[Idx], 0x04);
	SHA1_Update(&Context, SessionKey, SkSz);
	SHA1_Final(Buffer, &Context);
	memcpy_s(SHAResult + (Idx * SHA_DIGEST_LENGTH), ResSzSave, Buffer, ResSz);
}

void		BuildUnFinalizedDatas(uchar *Datas, uint Size, uchar *Result)
{
	uchar			*Mark;
	uint			Idx;
	SHA_CTX			MDCtx;

	Result[0x00] = 0x4B;	
	for (Idx = 1; Idx < (0x80 - (Size + SHA_DIGEST_LENGTH) - 2); Idx++)
		Result[Idx] = 0xBB;
	Result[Idx++] = 0xBA;

	Mark = Result + Idx;

	memcpy_s(Result + Idx, Size + SHA_DIGEST_LENGTH, Datas, Size);
	Idx += Size;

	SHA1_Init(&MDCtx);
	SHA1_Update(&MDCtx, Mark, Size);
	SHA1_Final(Result + Idx, &MDCtx);
	Idx += SHA_DIGEST_LENGTH;
	
	Result[Idx] = 0xBC;
}

uchar		*FinalizeLoginDatas(uchar *Buffer, uint *Size, uchar *Suite, int SuiteSz)
{
	int		Idx;
	uchar	*Result;
	SHA_CTX	Context;
	uchar	SHARes[SHA_DIGEST_LENGTH] = {0};

	Idx = 0;
	if (Buffer[*Size - 1] != 0xBC)
		return (NULL);
	if (SuiteSz)
	{
		if (*Buffer != 0x6A)
			return (NULL);
		*Size = 0x6A + SuiteSz;
		Idx += 1;
		goto Copy;
	}
	while ((Buffer[Idx] & 0x0F) == 0x0B)
		Idx++;
	if ((Buffer[Idx] & 0x0F) != 0x0A)
		return (NULL);
	Idx += 1;
	*Size = (*Size - 0x15) - Idx;

Copy:
	Result = (uchar *)malloc(*Size);
	memcpy_s(Result, *Size, Buffer + Idx, *Size - SuiteSz);
	if (SuiteSz)
		memcpy_s(Result + (*Size - SuiteSz), SuiteSz, Suite, SuiteSz);

	SHA1_Init(&Context);
	SHA1_Update(&Context, Result, *Size);
	/*SHA1_Update(&Context, Result, *Size - SuiteSz);
	if (SuiteSz)
		SHA1_Update(&Context, Suite, SuiteSz);*/
	SHA1_Final(SHARes, &Context);

	if (strncmp((char *)SHARes, (char *)(Buffer + Idx + (*Size - SuiteSz)), SHA_DIGEST_LENGTH))
	{
		printf("Bad SHA Digest for unencrypted Datas..\n");
		free(Result);
		return (NULL);
	}

	return (Result);
}

void			GenSessionKey(uchar *Buffer, uint Size)
{
	uint		Idx, Rander;

	Rander = BytesRandom();
	for (Idx = 0; Idx < Size; Idx++)
	{
		Rander = Update(Rander);
		Buffer[Idx] = ((uchar *)&Rander)[sizeof(Rander) - 1];
		//Buffer[Idx] = (uchar)(Idx + 1);
	}
	Buffer[0] = 0x01;
}

void			GetSessionKey(uchar *Buffer)
{
	static int	Init = 0;
	uint		Idx, Rander;

	if (!Init)
	{
		Rander = BytesRandom();
		for (Idx = 0; Idx < SK_SZ; Idx++)
		{
			Rander = Update(Rander);
			SessionKey[Idx] = ((uchar *)&Rander)[sizeof(Rander) - 1];
			//SessionKey[Idx] = (uchar)(Idx + 1);
			//SessionKey[Idx] = 0;
		}
		SessionKey[0] = 0x01;
		Init = 1;
	}
	for (Idx = 0; Idx < SK_SZ; Idx++)
		Buffer[Idx] = SessionKey[Idx];
}
