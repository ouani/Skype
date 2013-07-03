#ifndef SESSIONCMDMANAGER_H
#define SESSIONCMDMANAGER_H

#include "Common.h"

int		ManageSessionCMD(Host Relay, SessProp *SessionProposal, uchar **ResponseBuffer, SResponse Response, uint *BRSize);

#endif /*SESSIONCMDMANAGER_H*/