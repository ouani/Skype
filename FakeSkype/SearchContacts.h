#ifndef SEARCHCONTACTS_H
#define SEARCHCONTACTS_H

#include "Common.h"

Memory_U	GetAuthCert(queue<Contact> ContactsList, Contact *PeerContact);
int			SearchContact(Host Session_SN, char *User, Contact *ContactSH, char *User2Search, queue<Host> Hosts);
void		SearchContactList(Host Session_SN, char *User);
void		InitialPingOnLine(Host Session_SN, char *User);

#endif /*SEARCHCONTACTS_H*/