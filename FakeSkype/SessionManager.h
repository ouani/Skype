#ifndef SESSIONMANAGER_H
#define SESSIONMANAGER_H

#include "Common.h"

uint	BuildUserPacket(Host Relay, uchar **Buffer, ushort InternTID, ushort Cmd, AesStream_S *AesStream, uint NbObj, ...);
void	InitSession(SessProp *SessionProposal);

#endif /*SESSIONMANAGER_H*/