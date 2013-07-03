#include "ResponseManager.h"

ushort		LastPID = 0;

void		ManageObjects(uchar **Buffer, uint Size, SResponse *Response)
{
	uchar	Mode;

	Mode = **Buffer;
	*Buffer += 1;
	switch (Mode)
	{
	case RAW_PARAMS:
		Response->NbObj += DecodeRawObjects(Buffer, Size - 1, Response, &(Response->Objs), Response->NbObj);
		break;
	case EXT_PARAMS:
		Response->NbObj += DecodeExtObjects(Buffer, Size - 1, Response, &(Response->Objs), Response->NbObj);
		break;
	default:
		break;
	}
}

void		UDPResponseManager(uchar **Buffer, uint *BufferSz, SResponse *Response)
{
	uint			Size;
	uchar			*Mark = NULL;

 	Mark = *Buffer;
	Response->Reply2ID = -1;

	Response->PacketID = htons(*(ushort *)*Buffer);
	LastPID = Response->PacketID;
	*Buffer += 2;
	printf("UDP Packet : 0x%x\n", Response->PacketID);
	if (**Buffer != 0x02)
	{
		printf("Not an UDP Obfuscated packet..\n");
		return ;
	}
	*Buffer += 1;
	*Buffer += 8;
	ReadValue(Buffer, &Size);
	ReadValue(Buffer, &(Response->Cmd));
	Response->Reply2ID = htons(*(ushort *)*Buffer);
	*Buffer += 2;
	printf("Reply to Packet : 0x%x, Cmd #0x%x, Size : 0x%x\n", Response->Reply2ID, Response->Cmd, Size);
	Size -= 2;
	ManageObjects(Buffer, Size, Response);
	*BufferSz -= (int)(*Buffer - Mark);
}

void		UserPacketManager(uchar **Buffer, uint *BufferSz, SResponse *Response, AesStream_S *AesStream, uint HolyStream)
{
	uint	PacketSz;
	ushort	CtrlKey;
	uchar	*Mark = NULL;

 	Mark = *Buffer;

	Response->PacketID = Response->Reply2ID = 0x0000;

	if (HolyStream == -1)
		goto UnTouchAES;

	AesStream->Idx = 0;
	AesStream->AesSalt = 0;
	ZeroMemory(AesStream->ivec, sizeof(AesStream->ivec));
	ZeroMemory(AesStream->ecount_buf, sizeof(AesStream->ecount_buf));

	if (HolyStream)
	{
		uchar	InitKey[0x20];
		
		AesStream->IvecIdx = 0;
		ZeroMemory(InitKey, 0x20);
		AES_set_encrypt_key(InitKey, 256, &(AesStream->Key));
	}

UnTouchAES:

	ReadValue(Buffer, &PacketSz);
	
	PacketSz -= 5;
	PacketSz /= 2;
	PacketSz -= 1;

	if (**Buffer != 0x05)
	{
		printf("Not a User packet..\n");
		return ;
	}
	*Buffer += 1;
	CtrlKey = htons(*(ushort *)*Buffer);
	*Buffer += 2;

	((uint *)AesStream->ivec)[0] = htonl(AesStream->AesSalt);
	((uint *)AesStream->ivec)[1] = htonl(AesStream->AesSalt);
	((uint *)AesStream->ivec)[3] = htonl(AesStream->IvecIdx << 0x10);
	AES_ctr128_encrypt(*Buffer, *Buffer, PacketSz - 2, &(AesStream->Key), AesStream->ivec, AesStream->ecount_buf, &(AesStream->Idx));

	AesStream->Idx = 0;
	AesStream->IvecIdx++;

	ReadValueW(Buffer, &(Response->PacketID));
	LastPID = Response->PacketID;
	ReadValueW(Buffer, &(Response->Cmd));

	printf("User Packet 0x%x, Cmd #0x%x, Size : 0x%x\n", Response->PacketID, Response->Cmd, PacketSz);

	ManageObjects(Buffer, PacketSz - GetWrittenSz(Response->PacketID) - GetWrittenSz(Response->Cmd) - 4, Response);
	*Buffer += 4; //CRC VALUES

	if (Response->PacketID == 0x0000)
		Response->PacketID = LastPID;

	*BufferSz -= (int)(*Buffer - Mark);
}

void		TCPResponseManager(uchar **Buffer, uint *BufferSz, SResponse *Response)
{
	static uint	GlobPacketSz = 0;
	static uint GlobPacketSzSave = 0;
	
	uint		PartPacketSz, PartPacketSzSave;
	uchar		*Mark, *InitMark, *EndBuffer;
	
	Mark = InitMark = EndBuffer = NULL;

	InitMark = *Buffer;
	Response->PacketID = Response->Reply2ID = 0x0000;
	PartPacketSz = PartPacketSzSave = 0;

	if (!GlobPacketSz)
	{
		ReadValue(Buffer, &GlobPacketSz);
		GlobPacketSz >>= 1;
		GlobPacketSzSave = GlobPacketSz;

		Response->PacketID = htons(*(ushort *)*Buffer);
		LastPID = Response->PacketID;
		*Buffer += 2;
		GlobPacketSz -= 2;
		printf("Packet : 0x%x\n", Response->PacketID);
	}

	ReadValue(Buffer, &PartPacketSz);
	PartPacketSzSave = PartPacketSz;
	Mark = *Buffer;
	ReadValueW(Buffer, &(Response->Cmd));

	printf("Cmd #0x%x, Size : 0x%x\n", Response->Cmd, PartPacketSz);

	PartPacketSz += GetWrittenSz(Response->Cmd) + GetWrittenSz(PartPacketSz);

	switch (Response->Cmd & 0x07)
	{
	case 0x01:
		break;
	case 0x02:
	case 0x03:
		Response->Reply2ID = htons(*(ushort *)*Buffer);
		*Buffer += 2;
		printf("Reply to Packet : 0x%x\n", Response->Reply2ID);
		break;
	default:
		break;
	}

	EndBuffer = Mark + PartPacketSzSave + GetWrittenSz(Response->Cmd);
	ManageObjects(Buffer, (uint)(EndBuffer - *Buffer), Response);
	*Buffer = EndBuffer;

	if (Response->PacketID == 0x0000)
		Response->PacketID = LastPID;

	GlobPacketSz -= PartPacketSz;

	if (!GlobPacketSz)
		GlobPacketSzSave = 0;
	//*BufferSz -= GlobPacketSzSave + GetWrittenSz(GlobPacketSzSave);
	*BufferSz -= (uint)(*Buffer - InitMark);
}

void		OLDTCPResponseManager(uchar **Buffer, uint *BufferSz, SResponse *Response, int Suite)
{
	uint			Size;
	uchar			*Mark = NULL;
	static int		Rest = 0;
	static uint		GSize = 0;

	Mark = *Buffer;
	Response->Reply2ID = -1;

	if (!Rest)
	{
		ReadValue(Buffer, &GSize);
		GSize >>= 1;
		GSize += GetWrittenSz(GSize);
		Response->PacketID = htons(*(ushort *)*Buffer);
		LastPID = Response->PacketID;
		*Buffer += 2;
		printf("Packet : 0x%x\n", Response->PacketID);
	}
	ReadValue(Buffer, &Size);
	ReadValue(Buffer, &(Response->Cmd));
	if (!Suite)
	{
		Response->Reply2ID = htons(*(ushort *)*Buffer);
		*Buffer += 2;
		printf("Reply to Packet : 0x%x, Cmd #0x%x, Size : 0x%x\n", Response->Reply2ID, Response->Cmd, Size);
		Size -= 2;
	}

	ManageObjects(Buffer, Size, Response);
	
	GSize -= (int)(*Buffer - Mark);
	if (GSize)// && (Suite))
		Rest = 1;
	if (!GSize)
		Rest = 0;
	
	*BufferSz -= (int)(*Buffer - Mark);
	if (*BufferSz <= 0)
		Rest = 0;

	if (Response->PacketID == 0x0000)
		Response->PacketID = LastPID;
	//printf("Packet contain %d objects..\n", Response->NbObj);
}


void		MainArchResponseManager(uchar **Buffer, uint *BufferSz, SResponse *Response)
{
	HttpsPacketHeader	*HSHeader;
	uchar				*BufferEnd, *Mark;
	int					Size;

	HSHeader = (HttpsPacketHeader *)*Buffer;
	*Buffer += sizeof(HttpsPacketHeader);
	*BufferSz -= sizeof(HttpsPacketHeader) ;
	BufferEnd = *Buffer + (htons(HSHeader->ResponseLen) - 2);

	Size = (uint)htons(HSHeader->ResponseLen) - 2;
	Mark = *Buffer;
	while (*Buffer != BufferEnd)
	{
		Size -= (int)(*Buffer - Mark);
		Mark = *Buffer;
		ManageObjects(Buffer, Size, Response);
	}
	*BufferSz -= htons(HSHeader->ResponseLen);
	//printf("Packet contain %d objects..\n", Response->NbObj);
}
