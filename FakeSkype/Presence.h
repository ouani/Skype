#ifndef PRESENCE_H
#define PRESENCE_H

#include "Common.h"

void	BuildLocationBlob(Host Session_SN, uchar *Buffer);
void	SendPresence(Host Session_SN, char *User);

#endif /*PRESENCE_H*/