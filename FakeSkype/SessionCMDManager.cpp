#include "SessionManager.h"

int		ManageSessionCMD(Host Relay, SessProp *SessionProposal, uchar **ResponseBuffer, SResponse Response, uint *BRSize)
{
	uint		Idx, Cmd, SessID;
	uchar		ResponseCMDDatas[0xFFF] = {0};
	ObjectDesc	*SoughtObj;
	ObjectDesc	ObjSid, ObjSeq, ObjBlob, ObjV, ObjPrevSid;
	SResponse	SessCMDDatas;
	Memory_U	Tmp;
	static uint	SeqNbr = 0;
	static uint	InitialHeaderID = 0;
	static char	*ChatPeerName = NULL;

	Idx = 0;
	printf("Session Cmd received..\n");

	SoughtObj = GetObjByID(Response, 0x01, -1, -1);
	if (SoughtObj == NULL)
		return (-1);

	SessID = SoughtObj->Value.Nbr;
	
	if ((SessionProposal->CreatedSID == 0) && (SessionProposal->LocalCreatedSID == 0))
	{
		SessionProposal->CreatedSID = Response.Objs[Idx].Value.Nbr;
		SessionProposal->LocalCreatedSID = BytesRandom();
		printf("Created Session SID : 0x%x(%u) {Local SID : 0x%x(%u)}\n\n", Response.Objs[Idx].Value.Nbr, Response.Objs[Idx].Value.Nbr, SessionProposal->LocalCreatedSID, SessionProposal->LocalCreatedSID);
	}
	else
		printf("Command's SID : 0x%x(%u)..\n\n", Response.Objs[Idx].Value.Nbr, Response.Objs[Idx].Value.Nbr);

	SoughtObj = GetObjByID(Response, 0x04, -1, -1);
	if (SoughtObj == NULL)
	{
		cprintf(FOREGROUND_BLUE, "No SessionCMD..\n\n");
		return (0);
	}

	SessCMDDatas.Objs = NULL;
	SessCMDDatas.NbObj = 0;

	Tmp = SoughtObj->Value.Memory;
	ManageObjects(&(Tmp.Memory), Tmp.MsZ, &SessCMDDatas);

	SoughtObj = GetObjByID(SessCMDDatas, 0x01, -1, -1);
	if (SoughtObj == NULL)
		return (-1);

	Cmd = SoughtObj->Value.Nbr;

	ObjectDesc	RCDObjNbr;
	uchar		*RCDBrowser;
	uchar		*RCDMark;
	uint		ObjListIdx;

	switch(Cmd)
	{
	case 0x0D: //LetBeSyncBuddies (-> SendMeCredentialsAndStuff (0x23))
		cprintf(FOREGROUND_BLUE, "LetBeSyncBuddies Received.. Response : SendMeCredentialsAndStuff..\n");

		SoughtObj = GetObjByID(SessCMDDatas, 0x02, -1, -1);
		if (SoughtObj == NULL)
		{
			printf("No String ID for created session..\n");
			return (-1);
		}

		SessionProposal->CreatedSStrID = _strdup((char *)SoughtObj->Value.Memory.Memory);
		printf("Created Session String ID : %s\n", SessionProposal->CreatedSStrID);

		ObjSid.Family = OBJ_FAMILY_NBR;
		ObjSid.Id = 0x01;
		ObjSid.Value.Nbr = SessionProposal->LocalCreatedSID;

		ObjSeq.Family = OBJ_FAMILY_NBR;
		ObjSeq.Id = 0x03;
		ObjSeq.Value.Nbr = SeqNbr;
		SeqNbr += 1;

		RCDBrowser = ResponseCMDDatas;
		RCDMark = RCDBrowser;

		*RCDBrowser++ = RAW_PARAMS;
		WriteValue(&RCDBrowser, 0x01);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x01;
		RCDObjNbr.Value.Nbr = 0x23;				//SendMeCredentialsAndStuff
		WriteObject(&RCDBrowser, RCDObjNbr);

		ObjBlob.Family = OBJ_FAMILY_BLOB;
		ObjBlob.Id = 0x04;
		ObjBlob.Value.Memory.Memory = RCDMark;
		ObjBlob.Value.Memory.MsZ = (uint)(RCDBrowser - RCDMark);

		ObjV.Family = OBJ_FAMILY_NBR;
		ObjV.Id = 0x07;
		ObjV.Value.Nbr = 0x08;

		ObjPrevSid.Family = OBJ_FAMILY_NBR;
		ObjPrevSid.Id = 0x02;
		ObjPrevSid.Value.Nbr = SessionProposal->CreatedSID;

		*BRSize += BuildUserPacket(Relay, ResponseBuffer, 0xFFFF, 0x6D, SessionProposal->AesStreamOut, 5, ObjSid, ObjSeq, ObjBlob, ObjV, ObjPrevSid);
		SessionProposal->AesStreamOut->IvecIdx = 0;

		break;
	case 0x2A: //HereAreMyCredentials
		cprintf(FOREGROUND_BLUE, "HereAreMyCredentials (FROM CRED) Received.. Response : [SESSIONCMDACK]..\n");

		printf("Skipping (FROM) Credentials Saving..\n");

		//SEND SESSION CMD ACK NOT INDISPENSABLE

		break;
	case 0x13: //HereAreSomeHeaders (-> SendMeBodies (0x15))
		uint		NbHeaders;
		ObjectDesc	*SObj9, *SObjA, *SObj;

		cprintf(FOREGROUND_BLUE, "HereAreSomeHeaders Received.. Response : SendMeBodies..\n");

		NbHeaders = 0;

		for (Idx = 0; Idx < SessCMDDatas.NbObj; Idx++)
		{
			if ((SessCMDDatas.Objs[Idx].Id == 0x0A) && (SessCMDDatas.Objs[Idx].ObjListInfos.Id == 0x14))
				NbHeaders++;
		}

		SoughtObj = GetObjByID(SessCMDDatas, 0x0F, -1, -1);
		if (SoughtObj == NULL)
		{
			printf("No ID for Headers List..\n");
			return (-1);
		}

		InitialHeaderID = SoughtObj->Value.Nbr;

		printf("Headers List (0x%x) Size : #%d..\n", SoughtObj->Value.Nbr, NbHeaders);

		ObjSid.Family = OBJ_FAMILY_NBR;
		ObjSid.Id = 0x01;
		ObjSid.Value.Nbr = SessionProposal->LocalCreatedSID;

		ObjSeq.Family = OBJ_FAMILY_NBR;
		ObjSeq.Id = 0x03;
		ObjSeq.Value.Nbr =  SeqNbr;
		SeqNbr += 1;

		RCDBrowser = ResponseCMDDatas;
		RCDMark = RCDBrowser;

		*RCDBrowser++ = RAW_PARAMS;
		WriteValue(&RCDBrowser, 0x01 + NbHeaders);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x01;
		RCDObjNbr.Value.Nbr = 0x15;				//SendMeBodies
		WriteObject(&RCDBrowser, RCDObjNbr);

		ObjListIdx = 1;
		SObj9 = SObjA = SObj = NULL;

		while (NbHeaders--)
		{
			RCDObjNbr.Family = OBJ_FAMILY_NBR;
			RCDObjNbr.Id = 0x0A;

			SObj9 = GetObjByID(SessCMDDatas, 0x09, 0x14, ObjListIdx);
			SObjA = GetObjByID(SessCMDDatas, 0x0A, 0x14, ObjListIdx);
			if ((SObj9 == NULL) && (SObjA == NULL))
			{
				printf("Error Getting Header's Body To Request ID..\n");
				return (-1);
			}
			SObj = (SObjA == NULL) ? SObjA : SObj9;

			RCDObjNbr.Value.Nbr = SObj->Value.Nbr;
			WriteObject(&RCDBrowser, RCDObjNbr);

			ObjListIdx += 1;
		}

		ObjBlob.Family = OBJ_FAMILY_BLOB;
		ObjBlob.Id = 0x04;
		ObjBlob.Value.Memory.Memory = RCDMark;
		ObjBlob.Value.Memory.MsZ = (uint)(RCDBrowser - RCDMark);

		*BRSize += BuildUserPacket(Relay, ResponseBuffer, 0xFFFF, 0x6D, SessionProposal->AesStreamOut, 3, ObjSid, ObjSeq, ObjBlob);
		SessionProposal->AesStreamOut->IvecIdx = 0;

		break;
	case 0x2B: //HereAreBodies (-> IAmSyncingHere(0x10))
		uint		NbBodies;

		cprintf(FOREGROUND_BLUE, "HereAreBodies Received.. Response : [SESSIONCMDACK]..\n");

		NbBodies = 0;

		for (Idx = 0; Idx < SessCMDDatas.NbObj; Idx++)
		{
			if ((SessCMDDatas.Objs[Idx].Id == 0x0A) && (SessCMDDatas.Objs[Idx].ObjListInfos.Id == 0x20))
				NbBodies++;
		}

		ObjListIdx = 1;
		while (NbBodies--)
		{
			uint	MId;

			MId = 0x00;

			printf("Message #%d Properties :\n", ObjListIdx);
			
			SoughtObj = GetObjByID(SessCMDDatas, 0x00, 0x20, ObjListIdx);
			if (SoughtObj == NULL)
				printf("No STORE_AGE..\n");
			else
				printf("STORE_AGE : 0x%x\n", SoughtObj->Value.Nbr);

			SoughtObj = GetObjByID(SessCMDDatas, 0x02, 0x20, ObjListIdx);
			if (SoughtObj == NULL)
				printf("No UID_CRC..\n");
			else
				printf("UID_CRC : 0x%x\n", SoughtObj->Value.Nbr);

			SoughtObj = GetObjByID(SessCMDDatas, 0x0A, 0x20, ObjListIdx);
			if (SoughtObj == NULL)
				printf("No MID..\n");
			else
			{
				printf("MID : 0x%x\n", SoughtObj->Value.Nbr);
				MId = SoughtObj->Value.Nbr;
			}

			SoughtObj = GetObjByID(SessCMDDatas, 0x03, 0x20, ObjListIdx);
			if (SoughtObj == NULL)
				printf("No Message Body (?!?)..\n");
			else
			{
				RSA				*SkypeRSA;
				uchar			UnRSA[0xFFF];
				uchar			*PostProcessed;
				uint			PPsZ, Save;
				int				Suite;

				printf("RSA PUB KEY FROM [HEREAREBODIES]\n");
				showmem(SessionProposal->PeerContact->RsaPubKey.Memory, SessionProposal->PeerContact->RsaPubKey.MsZ);
				printf("\n");

				SkypeRSA = RSA_new();
				BN_hex2bn(&(SkypeRSA->n), Bin2HexStr(SessionProposal->PeerContact->RsaPubKey.Memory, MODULUS_SZ));
				BN_hex2bn(&(SkypeRSA->e), "10001");
				PPsZ = SoughtObj->Value.Memory.MsZ;
				SoughtObj->Value.Memory.MsZ -= PPsZ;
				Save = PPsZ;
				PPsZ = 0x80;
				ZeroMemory(UnRSA, 0xFFF);
				PPsZ = RSA_public_decrypt(PPsZ, SoughtObj->Value.Memory.Memory, UnRSA, SkypeRSA, RSA_NO_PADDING);
				RSA_free(SkypeRSA);

				printf("UnRSA :\n");
				showmem(UnRSA, PPsZ);
				printf("\n");

				if (PPsZ == 0xFFFFFFFF)
				{
					printf("Unable To UnRSA Message Body..\n");
					goto UnRSAFailed;
				}

				Suite = Save - PPsZ;
				SoughtObj->Value.Memory.Memory += PPsZ;

				printf("Suite :\n");
				showmem(SoughtObj->Value.Memory.Memory, Suite);
				printf("\n");

				PostProcessed = FinalizeLoginDatas(UnRSA, &PPsZ, (Suite > 0) ? SoughtObj->Value.Memory.Memory : NULL, Suite);

				if (PostProcessed == NULL)
				{
					printf("Bad Datas [METADATAS] Finalization..\n");

					PPsZ = 0x80;
					PostProcessed = FinalizeLoginDatas(UnRSA, &PPsZ, (Suite > 0) ? SoughtObj->Value.Memory.Memory : NULL, Suite);

					goto UnRSAFailed;
				}

				PostProcessed += SHA_DIGEST_LENGTH;
				PPsZ -= SHA_DIGEST_LENGTH;

				PostProcessed += (uint)strlen(SessionProposal->CreatedSStrID);
				PPsZ -= (uint)strlen(SessionProposal->CreatedSStrID);

				showmem(PostProcessed, PPsZ);
				printf("\n");

				SResponse ChatMsgDatas;

				ChatMsgDatas.Objs = NULL;
				ChatMsgDatas.NbObj = 0;

				ManageObjects(&PostProcessed, PPsZ, &ChatMsgDatas);

				if (MId == InitialHeaderID)
				{
					ChatPeerName = _strdup((char *)SessionProposal->PeerContact->DisplayName);

					/*SoughtObj = GetObjByID(ChatMsgDatas, 0x01, -1, -1);
					if (SoughtObj == NULL)
					{
						printf("No ChatPeer Name Specified.. Using Peer DisplayName\n\n");
						ChatPeerName = _strdup((char *)SessionProposal->PeerContact->DisplayName);
					}
					else
						ChatPeerName = _strdup((char *)SoughtObj->Value.Memory.Memory);*/
				}
				else
				{
					SoughtObj = GetObjByID(ChatMsgDatas, 0x02, -1, -1);
					if (SoughtObj == NULL)
						printf("Empty Message..\n\n");
					else
					{
						cprintf(YELLOW, "%s says :\n", ChatPeerName);
						cprintf(YELLOW, "%s\n\n", SoughtObj->Value.Memory.Memory);
					}
				}

				if (MId != 0)
				{
					ObjSid.Family = OBJ_FAMILY_NBR;
					ObjSid.Id = 0x01;
					ObjSid.Value.Nbr = SessionProposal->LocalCreatedSID;

					ObjSeq.Family = OBJ_FAMILY_NBR;
					ObjSeq.Id = 0x03;
					ObjSeq.Value.Nbr =  SeqNbr;
					SeqNbr += 1;

					RCDBrowser = ResponseCMDDatas;
					RCDMark = RCDBrowser;

					*RCDBrowser++ = RAW_PARAMS;
					WriteValue(&RCDBrowser, 0x06);

					RCDObjNbr.Family = OBJ_FAMILY_NBR;
					RCDObjNbr.Id = 0x01;
					RCDObjNbr.Value.Nbr = 0x10;				//IAmSyncingHere
					WriteObject(&RCDBrowser, RCDObjNbr);

					RCDObjNbr.Family = OBJ_FAMILY_NBR;
					RCDObjNbr.Id = 0x0A;
					RCDObjNbr.Value.Nbr = MId;
					WriteObject(&RCDBrowser, RCDObjNbr);

					RCDObjNbr.Family = OBJ_FAMILY_NBR;
					RCDObjNbr.Id = 0x13;
					RCDObjNbr.Value.Nbr = 0x10;
					WriteObject(&RCDBrowser, RCDObjNbr);

					RCDObjNbr.Family = OBJ_FAMILY_NBR;
					RCDObjNbr.Id = 0x22;
					RCDObjNbr.Value.Nbr = 0x01;
					WriteObject(&RCDBrowser, RCDObjNbr);

					RCDObjNbr.Family = OBJ_FAMILY_NBR;
					RCDObjNbr.Id = 0x23;
					RCDObjNbr.Value.Nbr = 0x01;
					WriteObject(&RCDBrowser, RCDObjNbr);

					RCDObjNbr.Family = OBJ_FAMILY_NBR;
					RCDObjNbr.Id = 0x25;
					RCDObjNbr.Value.Nbr = 0x01;
					WriteObject(&RCDBrowser, RCDObjNbr);

					ObjBlob.Family = OBJ_FAMILY_BLOB;
					ObjBlob.Id = 0x04;
					ObjBlob.Value.Memory.Memory = RCDMark;
					ObjBlob.Value.Memory.MsZ = (uint)(RCDBrowser - RCDMark);

					//*BRSize += BuildUserPacket(Relay, ResponseBuffer, 0xFFFF, 0x6D, SessionProposal->AesStreamOut, 3, ObjSid, ObjSeq, ObjBlob);
					//SessionProposal->AesStreamOut->IvecIdx = 0;
				}
			}
UnRSAFailed:
			ObjListIdx += 1;
		}

		break;
	case 0x24: //HereAreCredentialsAndStuff (-> WeAreSyncBuddies (0x0F), SendYourCredentials(0x29), IAmSyncingHere(0x10))
		cprintf(FOREGROUND_BLUE, "HereAreCredentialsAndStuff (TO CRED) Received.. Response : WeAreSyncBuddies + SendYourCredentials + IAmSyncingHere..\n");

		printf("Skipping (TO) Credentials Saving..\n");

		ObjSid.Family = OBJ_FAMILY_NBR;
		ObjSid.Id = 0x01;
		ObjSid.Value.Nbr = SessionProposal->LocalCreatedSID;

		ObjSeq.Family = OBJ_FAMILY_NBR;
		ObjSeq.Id = 0x03;
		ObjSeq.Value.Nbr =  SeqNbr;
		SeqNbr += 1;

		RCDBrowser = ResponseCMDDatas;
		RCDMark = RCDBrowser;

		*RCDBrowser++ = RAW_PARAMS;
		WriteValue(&RCDBrowser, 0x03);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x01;
		RCDObjNbr.Value.Nbr = 0x0F;				//WeAreSyncBuddies
		WriteObject(&RCDBrowser, RCDObjNbr);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x1C;
		RCDObjNbr.Value.Nbr = 0x01;
		WriteObject(&RCDBrowser, RCDObjNbr);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x1D;
		RCDObjNbr.Value.Nbr = 0x01;
		WriteObject(&RCDBrowser, RCDObjNbr);

		ObjBlob.Family = OBJ_FAMILY_BLOB;
		ObjBlob.Id = 0x04;
		ObjBlob.Value.Memory.Memory = RCDMark;
		ObjBlob.Value.Memory.MsZ = (uint)(RCDBrowser - RCDMark);

		*BRSize += BuildUserPacket(Relay, ResponseBuffer, 0xFFFF, 0x6D, SessionProposal->AesStreamOut, 3, ObjSid, ObjSeq, ObjBlob);
		SessionProposal->AesStreamOut->IvecIdx = 0;

		ZeroMemory(ResponseCMDDatas, sizeof(ResponseCMDDatas));

		ObjSid.Family = OBJ_FAMILY_NBR;
		ObjSid.Id = 0x01;
		ObjSid.Value.Nbr = SessionProposal->LocalCreatedSID;

		ObjSeq.Family = OBJ_FAMILY_NBR;
		ObjSeq.Id = 0x03;
		ObjSeq.Value.Nbr =  SeqNbr;
		SeqNbr += 1;

		RCDBrowser = ResponseCMDDatas;
		RCDMark = RCDBrowser;

		*RCDBrowser++ = RAW_PARAMS;
		WriteValue(&RCDBrowser, 0x01);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x01;
		RCDObjNbr.Value.Nbr = 0x29;				//SendYourCredentials
		WriteObject(&RCDBrowser, RCDObjNbr);

		ObjBlob.Family = OBJ_FAMILY_BLOB;
		ObjBlob.Id = 0x04;
		ObjBlob.Value.Memory.Memory = RCDMark;
		ObjBlob.Value.Memory.MsZ = (uint)(RCDBrowser - RCDMark);

		*BRSize += BuildUserPacket(Relay, ResponseBuffer, 0xFFFF, 0x6D, SessionProposal->AesStreamOut, 3, ObjSid, ObjSeq, ObjBlob);
		SessionProposal->AesStreamOut->IvecIdx = 0;

		ZeroMemory(ResponseCMDDatas, sizeof(ResponseCMDDatas));

		ObjSid.Family = OBJ_FAMILY_NBR;
		ObjSid.Id = 0x01;
		ObjSid.Value.Nbr = SessionProposal->LocalCreatedSID;

		ObjSeq.Family = OBJ_FAMILY_NBR;
		ObjSeq.Id = 0x03;
		ObjSeq.Value.Nbr =  SeqNbr;
		SeqNbr += 1;

		RCDBrowser = ResponseCMDDatas;
		RCDMark = RCDBrowser;

		*RCDBrowser++ = RAW_PARAMS;
		WriteValue(&RCDBrowser, 0x06);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x01;
		RCDObjNbr.Value.Nbr = 0x10;				//IAmSyncingHere
		WriteObject(&RCDBrowser, RCDObjNbr);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x0A;
		RCDObjNbr.Value.Nbr = 0xFFFFFFFF;
		WriteObject(&RCDBrowser, RCDObjNbr);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x13;
		RCDObjNbr.Value.Nbr = 0x10;
		WriteObject(&RCDBrowser, RCDObjNbr);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x22;
		RCDObjNbr.Value.Nbr = 0x01;
		WriteObject(&RCDBrowser, RCDObjNbr);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x23;
		RCDObjNbr.Value.Nbr = 0x01;
		WriteObject(&RCDBrowser, RCDObjNbr);

		RCDObjNbr.Family = OBJ_FAMILY_NBR;
		RCDObjNbr.Id = 0x25;
		RCDObjNbr.Value.Nbr = 0x01;
		WriteObject(&RCDBrowser, RCDObjNbr);

		ObjBlob.Family = OBJ_FAMILY_BLOB;
		ObjBlob.Id = 0x04;
		ObjBlob.Value.Memory.Memory = RCDMark;
		ObjBlob.Value.Memory.MsZ = (uint)(RCDBrowser - RCDMark);

		*BRSize += BuildUserPacket(Relay, ResponseBuffer, 0xFFFF, 0x6D, SessionProposal->AesStreamOut, 3, ObjSid, ObjSeq, ObjBlob);
		SessionProposal->AesStreamOut->IvecIdx = 0;

		//SEND SESSION CMD ACK NOT INDISPENSABLE

		break;
	default :
		printf("UnManaged SessionCMD 0x%x..\n", Cmd);
		break;
	}
	return (1);
}