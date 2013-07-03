#ifndef CHATMANAGER_H
#define CHATMANAGER_H

#include "Common.h"

void	BuildHeader2Send(Host Relay, SessProp *SessionProposal, uchar **ResponseBuffer, uint *BRSize, uint *SeqNbr, char *Msg);
void	BuildBody2Send(Host Relay, SessProp *SessionProposal, uchar **ResponseBuffer, uint *BRSize, uint *SeqNbr, queue<uint> MidList);
void	BuildUIC2Send(Host Relay, SessProp *SessionProposal, uchar **ResponseBuffer, uint *BRSize, uint *SeqNbr, uint UicID);

#endif /*CHATMANAGER_H*/