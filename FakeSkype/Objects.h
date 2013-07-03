#ifndef OBJECTS_H
#define OBJECTS_H

#include "Common.h"

#define	 OBJ_FAMILY_NBR		0x00
#define	 OBJ_FAMILY_TABLE	0x01
#define	 OBJ_FAMILY_NETADDR	0x02
#define	 OBJ_FAMILY_STRING	0x03
#define	 OBJ_FAMILY_BLOB	0x04
#define	 OBJ_FAMILY_OBJLIST	0x05
#define  OBJ_FAMILY_INTLIST	0x06

#define	 OBJ_ID_NODEID		0x0D
#define	 OBJ_ID_LPORT		0x10
#define	 OBJ_ID_UPTIME		0x01
#define	 OBJ_ID_STVL		0x23
#define	 OBJ_ID_2000		0x09
#define  OBJ_ID_SK			0x08
#define  OBJ_ID_ZBOOL1		0x0C
#define  OBJ_ID_REQCODE		0x00
#define  OBJ_ID_ZBOOL2		0x02
#define  OBJ_ID_USERNAME	0x04
#define  OBJ_ID_USERPASS	0x05
#define  OBJ_ID_MODULUS		0x21
#define  OBJ_ID_PLATFORM	0x31
#define  OBJ_ID_LANG		0x36
#define  OBJ_ID_VERSION		0x0D
#define  OBJ_ID_PUBADDR		0x0E
#define  OBJ_ID_MISCD		0x33
#define	 OBJ_ID_STACKVER	0x0B
#define	 OBJ_ID_STACKTS		0x0C
#define	 OBJ_ID_PEERLPORT	0x10
#define	 OBJ_ID_PUBNETADDR	0x11
#define	 OBJ_ID_NBCONNECTED	0x09
#define	 OBJ_ID_LOGINANSWER	0x01
#define	 OBJ_ID_CIPHERDLOGD	0x24
#define	 OBJ_ID_LDUSER		0x00
#define	 OBJ_ID_LDEXPIRY	0x04
#define	 OBJ_ID_LDMODULUS	0x01
#define  OBJ_ID_ESAUTHANSWR	0x0A
#define  OBJ_ID_ESHASHLIST	0x35
#define  OBJ_ID_HASH		0x32
#define  OBJ_ID_DISPLAYNAME	0x34
#define  OBJ_ID_UBLOB		0x33
#define  OBJ_ID_INTERNALNAM	0x10
#define  OBJ_ID_BUDDYSTATUS	0x79
#define  OBJ_ID_AUTHCERT	0x03
#define  OBJ_ID_USER2SEARCH	0x00
#define  OBJ_ID_BCMID		0x00
#define  OBJ_ID_BCMVER		0x01
#define  OBJ_ID_SLOTID		0x00
#define	 OBJ_ID_SLOTNBSN	0x07
#define	 OBJ_ID_SLOTSNADDR	0x03
#define	 OBJ_ID_DIRBLOB		0x0B
#define  OBJ_ID_CIRNAME		0x14
#define  OBJ_ID_CILANG		0x24
#define  OBJ_ID_CIREGION	0x2C
#define  OBJ_ID_CIVILLE		0x30
#define  OBJ_ID_CILOCATION	0x03
#define  OBJ_ID_FWTESTID	0x19
#define  OBJ_ID_FWTESTER	0x11
#define  OBJ_ID_PINGER		0x02
#define  OBJ_ID_TESTED		0x02
#define  OBJ_ID_TESTER		0x00
#define  OBJ_ID_RELAY		0x08
#define  OBJ_ID_SESPROPOSER	0x01
#define  OBJ_ID_SESCHALLENG	0x09
#define  OBJ_ID_SID2DEC		0x03
#define  OBJ_ID_SOLVEDCHALL	0x0A
#define  OBJ_ID_USRDBLOB	0x05
#define  OBJ_ID_AESPART1	0x06
#define	 OBJ_ID_PEERLOGIN	0x00
#define  OBJ_ID_PEERSESSID	0x03

void	    WriteObject(uchar **Buffer, ObjectDesc Object);
void		DumpObj(ObjectDesc Object);
ObjectDesc	*GetObjByID(SResponse Response, uint ID, uint ObjLID, uint ObjRank);
uint		DefNbObjList(SResponse Response);

int			DecodeRawObjects(uchar **Buffer, uint Size, SResponse *Response, ObjectDesc **Objs, int Suffix);
int			DecodeExtObjects(uchar **Buffer, uint Size, SResponse *Response, ObjectDesc **Objs, int Suffix);

#endif /*OBJECTS_H*/