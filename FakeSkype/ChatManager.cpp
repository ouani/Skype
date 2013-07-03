#include "ChatManager.h"

map	<uint, char *>	ChatMsgs;

void	BuildHeader2Send(Host Relay, SessProp *SessionProposal, uchar **ResponseBuffer, uint *BRSize, uint *SeqNbr, char *Msg)
{
	uint		Mid;
	uchar		ResponseCMDDatas[0xFFF] = {0};
	ObjectDesc	ObjSid, ObjSeq, ObjBlob;
	ObjectDesc	RCDObjNbr, RCDObjStr;
	uchar		*RCDBrowser;
	uchar		*RCDMark;
	uint		ListID = 0;

	do
	{
		Mid = BytesRandom();
	}
	while (ChatMsgs.find(Mid) != ChatMsgs.end());

	ListID = Mid - 0x01;

	//printf("ListID : 0x%x, Mid : 0x%x\n", ListID, Mid);

	ChatMsgs[Mid] = _strdup(Msg);

	ObjSid.Family = OBJ_FAMILY_NBR;
	ObjSid.Id = 0x01;
	ObjSid.Value.Nbr = SessionProposal->LocalCreatedSID;

	ObjSeq.Family = OBJ_FAMILY_NBR;
	ObjSeq.Id = 0x03;
	ObjSeq.Value.Nbr = *SeqNbr;
	*SeqNbr += 1;

	RCDBrowser = ResponseCMDDatas;
	RCDMark = RCDBrowser;

	*RCDBrowser++ = RAW_PARAMS;
	WriteValue(&RCDBrowser, 0x05);

	RCDObjNbr.Family = OBJ_FAMILY_NBR;
	RCDObjNbr.Id = 0x01;
	RCDObjNbr.Value.Nbr = 0x13;				//HereAreSomeHeaders
	WriteObject(&RCDBrowser, RCDObjNbr);

	RCDObjNbr.Family = OBJ_FAMILY_NBR;
	RCDObjNbr.Id = 0x0F;
	RCDObjNbr.Value.Nbr = ListID;
	WriteObject(&RCDBrowser, RCDObjNbr);

	*RCDBrowser++ = 0x05;
	WriteValue(&RCDBrowser, 0x14);

	*RCDBrowser++ = RAW_PARAMS;
	WriteValue(&RCDBrowser, 0x03);

	RCDObjNbr.Family = OBJ_FAMILY_NBR;
	RCDObjNbr.Id = 0x09;
	RCDObjNbr.Value.Nbr = Mid;
	WriteObject(&RCDBrowser, RCDObjNbr);

	RCDObjNbr.Family = OBJ_FAMILY_NBR;
	RCDObjNbr.Id = 0x0A;
	RCDObjNbr.Value.Nbr = Mid;
	WriteObject(&RCDBrowser, RCDObjNbr);

	RCDObjNbr.Family = OBJ_FAMILY_NBR;
	RCDObjNbr.Id = 0x15;
	RCDObjNbr.Value.Nbr = 0xDEADBEEF;	//SORT OF CRC
	WriteObject(&RCDBrowser, RCDObjNbr);

	size_t	MemberListSz = strlen((char *)GLoginD.User) + strlen((char *)SessionProposal->PeerContact->InternalName) + 2;
	char	*MemberList = (char *)malloc(MemberListSz);

	ZeroMemory(MemberList, MemberListSz);

	strcat_s(MemberList, MemberListSz, (char *)GLoginD.User);
	strcat_s(MemberList, MemberListSz, " ");
	strcat_s(MemberList, MemberListSz, (char *)SessionProposal->PeerContact->InternalName);

	RCDObjStr.Family = OBJ_FAMILY_STRING;
	RCDObjStr.Id = 0x12;
	RCDObjStr.Value.Memory.Memory = (uchar *)MemberList;
	RCDObjStr.Value.Memory.MsZ = (int)strlen(MemberList);
	WriteObject(&RCDBrowser, RCDObjStr);

	*RCDBrowser++ = 0x05;
	WriteValue(&RCDBrowser, 0x2F);

	*RCDBrowser++ = RAW_PARAMS;
	WriteValue(&RCDBrowser, 0x01);

	RCDObjNbr.Family = OBJ_FAMILY_NBR;
	RCDObjNbr.Id = 0x02;
	RCDObjNbr.Value.Nbr = 0x01;
	WriteObject(&RCDBrowser, RCDObjNbr);

	ObjBlob.Family = OBJ_FAMILY_BLOB;
	ObjBlob.Id = 0x04;
	ObjBlob.Value.Memory.Memory = RCDMark;
	ObjBlob.Value.Memory.MsZ = (uint)(RCDBrowser - RCDMark);

	*BRSize += BuildUserPacket(Relay, ResponseBuffer, 0xFFFF, 0x6D, SessionProposal->AesStreamOut, 3, ObjSid, ObjSeq, ObjBlob);
	SessionProposal->AesStreamOut->IvecIdx = 0;

	cprintf(YELLOW, "%s says :\n", (char *)GLoginD.User);
	cprintf(YELLOW, "%s\n\n", Msg);
}

void	BuildBody2Send(Host Relay, SessProp *SessionProposal, uchar **ResponseBuffer, uint *BRSize, uint *SeqNbr, queue<uint> MidList)
{
	uchar		ResponseCMDDatas[0xFFF] = {0};
	ObjectDesc	ObjSid, ObjSeq, ObjBlob;
	ObjectDesc	RCDObjNbr, RCDObjBlob;
	uchar		*RCDBrowser;
	uchar		*RCDMark;

	ObjSid.Family = OBJ_FAMILY_NBR;
	ObjSid.Id = 0x01;
	ObjSid.Value.Nbr = SessionProposal->LocalCreatedSID;

	ObjSeq.Family = OBJ_FAMILY_NBR;
	ObjSeq.Id = 0x03;
	ObjSeq.Value.Nbr = *SeqNbr;
	*SeqNbr += 1;

	RCDBrowser = ResponseCMDDatas;
	RCDMark = RCDBrowser;

	uint	NbValidBodies = 0;
	queue<uint>	Copy = MidList;

	while (!Copy.empty())
	{
		if (ChatMsgs.find(Copy.front()) != ChatMsgs.end())
			NbValidBodies += 1;
		Copy.pop();
	}

	*RCDBrowser++ = RAW_PARAMS;
	WriteValue(&RCDBrowser, 0x01 + NbValidBodies);

	RCDObjNbr.Family = OBJ_FAMILY_NBR;
	RCDObjNbr.Id = 0x01;
	RCDObjNbr.Value.Nbr = 0x2B;				//HereAreSomeHeaders
	WriteObject(&RCDBrowser, RCDObjNbr);

	uint	CurMid;

	while (!MidList.empty())
	{
		if (ChatMsgs.find(MidList.front()) == ChatMsgs.end())
		{
			printf("Invalid Mid Specified For Requested Body (0x%x)..\n", MidList.front());
			goto SkipMid;
		}
		CurMid = MidList.front();
		printf("Sending Body 0x%x (-> %s)..\n", CurMid, ChatMsgs[CurMid]);

		*RCDBrowser++ = 0x05;
		WriteValue(&RCDBrowser, 0x20);

		*RCDBrowser++ = RAW_PARAMS;
		WriteValue(&RCDBrowser, 0x05);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x0A;
		RCDObjNbr.Value.Nbr = CurMid;		//MID
		WriteObject(&RCDBrowser, RCDObjNbr);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x00;
		RCDObjNbr.Value.Nbr = 0x00;			//STORE_AGE
		WriteObject(&RCDBrowser, RCDObjNbr);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x01;
		RCDObjNbr.Value.Nbr = 0x02;			//UIC_ID
		WriteObject(&RCDBrowser, RCDObjNbr);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x02;
		RCDObjNbr.Value.Nbr = crc32(GLoginD.SignedCredentials.Memory, GLoginD.SignedCredentials.MsZ, -1);	//UIC_CRC
		WriteObject(&RCDBrowser, RCDObjNbr);

		/*printf("UIC CRC : 0x%x\n", RCDObjNbr.Value.Nbr);
		showmem(GLoginD.SignedCredentials.Memory, GLoginD.SignedCredentials.MsZ);
		printf("\n");*/

		uchar		EncapsulatedMsg[0x400] = {0};
		uchar		Buffer[LOCATION_SZ] = {0};
		uchar		*EMsgBrowser = EncapsulatedMsg;
		ObjectDesc	EMsgStr, EMsgNbr, EMsgLocation;
		
		*EMsgBrowser++ = RAW_PARAMS;
		WriteValue(&EMsgBrowser, 0x06);

		EMsgNbr.Family = OBJ_FAMILY_NBR;
		EMsgNbr.Id = 0x00;
		EMsgNbr.Value.Nbr = 0x03;
		WriteObject(&EMsgBrowser, EMsgNbr);

		BuildLocationBlob(Session_SN, &Buffer[0]);

		EMsgLocation.Family = OBJ_FAMILY_BLOB;
		EMsgLocation.Id = 0x03;
		EMsgLocation.Value.Memory.Memory = Buffer;
		EMsgLocation.Value.Memory.MsZ = LOCATION_SZ;
		WriteObject(&EMsgBrowser, EMsgLocation);

		EMsgNbr.Family = OBJ_FAMILY_NBR;
		EMsgNbr.Id = 0x05;
		EMsgNbr.Value.Nbr = GetLocalTimeEpoch();	//TIMESTAMP
		WriteObject(&EMsgBrowser, EMsgNbr);

		EMsgNbr.Family = OBJ_FAMILY_NBR;
		EMsgNbr.Id = 0x06;
		EMsgNbr.Value.Nbr = GLoginD.Expiry;			//UIC RENEWAL
		WriteObject(&EMsgBrowser, EMsgNbr);

		EMsgNbr.Family = OBJ_FAMILY_NBR;
		EMsgNbr.Id = 0x07;
		EMsgNbr.Value.Nbr = CurMid;					//MID
		WriteObject(&EMsgBrowser, EMsgNbr);

		EMsgStr.Family = OBJ_FAMILY_STRING;
		EMsgStr.Id = 0x02;
		EMsgStr.Value.Memory.Memory = (uchar *)ChatMsgs[CurMid];
		EMsgStr.Value.Memory.MsZ = (int)strlen(ChatMsgs[CurMid]);
		WriteObject(&EMsgBrowser, EMsgStr);

		uchar	EMsg2Sign[0x800] = {0};
		uint	BufIdx = 0;
		SHA_CTX	Context;

		SHA1_Init(&Context);
		SHA1_Update(&Context, GLoginD.SignedCredentials.Memory, GLoginD.SignedCredentials.MsZ);
		SHA1_Update(&Context, SessionProposal->CreatedSStrID, strlen(SessionProposal->CreatedSStrID));
		SHA1_Final(&EMsg2Sign[BufIdx], &Context);
		BufIdx += SHA_DIGEST_LENGTH;
		memcpy_s(&EMsg2Sign[BufIdx], 0x800, SessionProposal->CreatedSStrID, strlen(SessionProposal->CreatedSStrID));
		BufIdx += (uint)strlen(SessionProposal->CreatedSStrID);
		memcpy_s(&EMsg2Sign[BufIdx], 0x800, &EncapsulatedMsg[0], (uint)(EMsgBrowser - EncapsulatedMsg));
		BufIdx += (uint)(EMsgBrowser - EncapsulatedMsg);

		uchar	SignedEMsg[0x80] = {0};
		SHA_CTX	Context2;
		uint	CopyTil = 0;

		SignedEMsg[0x80 - 0x01] = 0xBC;
		SHA1_Init(&Context2);
		SHA1_Update(&Context2, EMsg2Sign, BufIdx);
		SHA1_Final(&SignedEMsg[0x80 - (SHA_DIGEST_LENGTH + 1)], &Context2);
		SignedEMsg[0x00] = 0x6A;
		for (CopyTil = 0x01; CopyTil < 0x80 - (SHA_DIGEST_LENGTH + 1); CopyTil++)
			SignedEMsg[CopyTil] = EMsg2Sign[CopyTil - 0x01];

		RSA_private_encrypt(sizeof(SignedEMsg), SignedEMsg, SignedEMsg, GLoginD.RSAKeys, RSA_NO_PADDING);

		uint	ENSMsgSz = 0x80 + (BufIdx - (CopyTil - 1));
		uchar	*ENSMsg = (uchar *)malloc(ENSMsgSz);
		
		ZeroMemory(ENSMsg, ENSMsgSz);
		memcpy_s(ENSMsg, ENSMsgSz, SignedEMsg, 0x80);
		memcpy_s(ENSMsg + 0x80, ENSMsgSz, EMsg2Sign + CopyTil - 1, BufIdx - (CopyTil - 1));

		RCDObjBlob.Family = OBJ_FAMILY_BLOB;
		RCDObjBlob.Id = 0x03;
		RCDObjBlob.Value.Memory.Memory = ENSMsg;
		RCDObjBlob.Value.Memory.MsZ = ENSMsgSz;
		WriteObject(&RCDBrowser, RCDObjBlob);

SkipMid:
		MidList.pop();
	}

	ObjBlob.Family = OBJ_FAMILY_BLOB;
	ObjBlob.Id = 0x04;
	ObjBlob.Value.Memory.Memory = RCDMark;
	ObjBlob.Value.Memory.MsZ = (uint)(RCDBrowser - RCDMark);

	*BRSize += BuildUserPacket(Relay, ResponseBuffer, 0xFFFF, 0x6D, SessionProposal->AesStreamOut, 3, ObjSid, ObjSeq, ObjBlob);
	SessionProposal->AesStreamOut->IvecIdx = 0;
}

void	BuildUIC2Send(Host Relay, SessProp *SessionProposal, uchar **ResponseBuffer, uint *BRSize, uint *SeqNbr, uint UicID)
{
	uchar		ResponseCMDDatas[0xFFF] = {0};
	ObjectDesc	ObjSid, ObjSeq, ObjBlob;
	ObjectDesc	RCDObjNbr, RCDObjBlob;
	uchar		*RCDBrowser;
	uchar		*RCDMark;

	ObjSid.Family = OBJ_FAMILY_NBR;
	ObjSid.Id = 0x01;
	ObjSid.Value.Nbr = SessionProposal->LocalCreatedSID;

	ObjSeq.Family = OBJ_FAMILY_NBR;
	ObjSeq.Id = 0x03;
	ObjSeq.Value.Nbr = *SeqNbr;
	*SeqNbr += 1;

	RCDBrowser = ResponseCMDDatas;
	RCDMark = RCDBrowser;

	*RCDBrowser++ = RAW_PARAMS;
	WriteValue(&RCDBrowser, 0x03);

	RCDObjNbr.Family = OBJ_FAMILY_NBR;
	RCDObjNbr.Id = 0x01;
	RCDObjNbr.Value.Nbr = 0x1E;				//HereIsUICFor
	WriteObject(&RCDBrowser, RCDObjNbr);

	RCDObjNbr.Family = OBJ_FAMILY_NBR;
	RCDObjNbr.Id = 0x0C;
	RCDObjNbr.Value.Nbr = UicID;			//UIC_ID
	WriteObject(&RCDBrowser, RCDObjNbr);

	RCDObjBlob.Family = OBJ_FAMILY_BLOB;
	RCDObjBlob.Id = 0x0B;
	RCDObjBlob.Value.Memory = GLoginD.SignedCredentials;	//UIC
	WriteObject(&RCDBrowser, RCDObjBlob);

	ObjBlob.Family = OBJ_FAMILY_BLOB;
	ObjBlob.Id = 0x04;
	ObjBlob.Value.Memory.Memory = RCDMark;
	ObjBlob.Value.Memory.MsZ = (uint)(RCDBrowser - RCDMark);

	*BRSize += BuildUserPacket(Relay, ResponseBuffer, 0xFFFF, 0x6D, SessionProposal->AesStreamOut, 3, ObjSid, ObjSeq, ObjBlob);
	SessionProposal->AesStreamOut->IvecIdx = 0;
}
