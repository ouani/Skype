#ifndef COMMON_H
#define COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <wincon.h>
#include <malloc.h>
#include <stdarg.h>
#include <queue>
#include <list>

#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>

using namespace std;

#define	 NB_HARD_HOST		7

#define	 NODEID_SZ			8
#define  LOCATION_SZ		0x15
#define	 DEF_LPORT			50025

#define	 HANDSHAKE_SZ		0x05
#define  CONCAT_SALT		"\nskyper\n"
#define  KEYSZ				0x200
#define	 SK_SZ				0xC0
#define  MODULUS_SZ			0x80

#define	 LANG_STR			"fr"
//#define	 VER_STR			"0/2.5.0.151"
#define	 VER_STR			"0/4.2.0.169"

#define	 MAX_IP_LEN			15
#define  HHSP_SIZE			0x48
#define	 HTTPS_PORT			443
#define  HTTPS_HSR_MAGIC	"\x16\x03\x01"
#define  HTTPS_HSRR_MAGIC	"\x17\x03\x01"

#define	 LOGIN_OK			4200
#define	 ESAUTH_OK			0xBB8

#define	 PKT_TYPE_OBFSUK	0x02
#define	 PKT_TYPE_RESEND	0x03
#define	 PKT_TYPE_NACK		0x07
#define  PKT_TYPE_CTRL  	0x03

#define	 CMD_PROBE			0x1B
#define	 CMD_PROBE_REFUSED	0x1D
#define  CMD_PROBE_OK		0x1C
#define	 CMD_CLIENT_REFUSED	0x20
#define	 CMD_CLIENT_OK		0x1F
#define	 CMD_NETSTATS		0x0B
#define	 CMD_BCM			0x2F
#define  CMD_SLOTINFOS		0x08
#define  CMD_SNREGOK		0x0F
#define  CMD_FIREWALL_RES	0x2A
#define	 CMD_QUERY_IPING	0x51
#define  CMD_QUERY_SESSION	0x43
#define  CMD_QUERY_UDPTEST	0x39
#define	 CMD_SESSIONOK		0x4B
#define  CMD_UDPCONNECT		0x54
#define	 CMD_SESSIONERROR	(0x03 / 8)

#define	 CMD_USR_45			0x45	//PeerAuth
#define	 CMD_USR_7A			0x7A	//Session Established
#define	 CMD_USR_7D			0x7D	//Cumulative Capabilites
#define	 CMD_USR_53			0x53	//AuthCert
#define	 CMD_USR_6D			0x6D	//Session_CMD
#define	 CMD_USR_47			0x47	//Usr ACK
#define	 CMD_USR_7B			0x7B	
#define	 CMD_USR_58			0x58
#define	 CMD_USR_4C			0x4C

#define	 RAW_PARAMS			0x41
#define	 EXT_PARAMS			0x42

#define  PROBE_PAYL_LEN		0x00
#define	 CLACPT_PAYL_LEN	0x15

#define	 CONSOLEHELPER_EXE	"C:\\Documents and Settings\\Administrateur\\Bureau\\Skype\\FakeSkype\\FakeSkype\\ConsoleLogger\\ConsoleLoggerHelper.exe"

typedef	 unsigned char		uchar;
typedef	 unsigned short		ushort;
typedef	 unsigned int		uint;
typedef	 unsigned long		ulong;

enum COLORS {
	BLACK = 0,
	BLUE = FOREGROUND_BLUE,
	GREEN = FOREGROUND_GREEN,
	CYAN = FOREGROUND_GREEN | FOREGROUND_BLUE,
	RED = FOREGROUND_RED,
	MAGENTA = FOREGROUND_RED | FOREGROUND_BLUE,
	BROWN = FOREGROUND_RED | FOREGROUND_GREEN,
	LIGHTGRAY = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
	DARKGRAY = FOREGROUND_INTENSITY,
	LIGHTBLUE = FOREGROUND_BLUE | FOREGROUND_INTENSITY,
	LIGHTGREEN = FOREGROUND_GREEN | FOREGROUND_INTENSITY,
	LIGHTCYAN = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
	LIGHTRED = FOREGROUND_RED | FOREGROUND_INTENSITY,
	LIGHTMAGENTA = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
	YELLOW = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
	WHITE = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
};

typedef struct
{
	RC4_KEY	SendStream;
	RC4_KEY	RecvStream;
}	TCPKeyPair;

typedef  struct
{
	char		ip[MAX_IP_LEN + 1];
	int			port;
	SOCKET		socket;
	int			Connected;
	uint		SessionID2Declare;
	TCPKeyPair	Keys;
}				Host;

#pragma	pack(1)
typedef struct
{
	unsigned short TransID;
	unsigned char  FuncID;
	unsigned int   IV;
	unsigned int   Crc32;
}	CipheredPacketHeader;

#pragma	pack(1)
typedef struct
{
	unsigned short TransID;
	unsigned char  PacketType;
	unsigned int   IV;
	unsigned int   Crc32;
}	ProbeHeader;

#pragma	pack(1)
typedef struct
{
	unsigned short TransID;
	unsigned char  PacketType;
	unsigned char  Unknown_COOKIE;
	unsigned int   Challenge;
	unsigned int   Dest;
	unsigned int   Crc32;
}	ResendProbeHeader;

#pragma	pack(1)
typedef struct
{
	unsigned short TransID;
	unsigned char  PacketType;
	unsigned int   PublicIP;
	unsigned int   Challenge;
}	NackPacket;

#pragma	pack(1)
typedef struct
{
	unsigned char  PayLoadLen;
	unsigned short ProbeCmd;
	unsigned short RequestID;
	unsigned char  ParamListType;
	unsigned char  NbObj;
}	ReqBody;

#pragma	pack(1)
typedef struct
{
	unsigned char  PayLoadLen;
	unsigned char  Cmd;
	unsigned short RequestID;
}	ReqBody2;

#pragma	pack(1)
typedef struct
{
	unsigned char  PayLoadLen;
	unsigned short Cmd;
	unsigned short RequestID;
	unsigned char  Unknown_COOKIE;
}	PacketBody;

#pragma	pack(1)
typedef struct
{
	unsigned char  MAGIC[3];
	unsigned short ResponseLen;
}	HttpsPacketHeader;

#pragma	pack(1)
typedef struct
{
	unsigned int   Seed;
	unsigned short ZWord;
	unsigned int   Cookie_1;
	unsigned int   Cookie_2;
	unsigned char  Length;
	unsigned char  Type;
}	TCPCtrlPacketHeader;

typedef struct
{
	uchar	*Memory;
	int 	MsZ;
}	Memory_U;

typedef struct
{
	uint	Family;
	uint	Id;
	typedef struct
	{
		int		Id;
		uint	Rank;
	}			ObjListInfos_S;
	ObjListInfos_S	ObjListInfos;
	typedef union
	{
		Memory_U	Memory;
		uchar	Table[8];		/* Actually DOUBLE int */
		uint	Nbr;
		Host	Addr;
	}			Value_U;
	Value_U	Value;
}	ObjectDesc;

typedef struct
{
	ushort		Cmd;
	ushort		PacketID;
	ushort		Reply2ID;
	uint		NbObj;
	ObjectDesc	*Objs;
}	SResponse;

typedef struct
{
	uchar		*User;
	uint		Expiry;
	RSA			*RSAKeys;
	Memory_U	Modulus;
	Memory_U	SignedCredentials;
}	SLoginDatas;

typedef struct
{
	uchar		NodeID[8];
	uchar		UnkN;
	Host		SNAddr;
	Host		PVAddr;
	uint		OnLineNode;
}	CLocation;

typedef struct
{
	uchar			*DisplayName;
	uchar			*InternalName;
	int				BuddyStatus;

	Memory_U		AuthCert;
	Memory_U		RsaPubKey;

	char			*RealDName;
	char			*Region;
	char			*Ville;
	char			*Langue;

	int				OnLineStatus;
	list<CLocation>	*Locations;
}	Contact;

typedef	struct
{
	int			RecvSz;
	uchar		RecvBuf[0xFFFF];
}	RecvDesc;

typedef	struct
{
	uint		SlotID;
	uint		NbSN;
	uchar		*AssociatedName;
	queue<Host>	*SNodes;
}	SlotInfo;

typedef struct
{
	uint				Idx;
	uint				AesSalt;
	uint				IvecIdx;
	uchar				ivec[AES_BLOCK_SIZE];
	uchar				ecount_buf[AES_BLOCK_SIZE];
	AES_KEY				Key;
}	AesStream_S;

typedef struct
{
	CLocation	ProposerLocation;
	uchar		Challenge[8];
	uchar		PeerChallenge[8];
	short		SessID;
	short		PeerSessID;
	Memory_U	RelaysInfos;

	uchar		AesKeyBlob[32];
	
	AesStream_S	*AesStream;
	AesStream_S	*AesStreamOut;

	Contact		*PeerContact;

	queue<Host>	*Relays;

	uint		LocalCreatedSID;
	uint		CreatedSID;
	char		*CreatedSStrID;
}	SessProp;

#include "Random.h"
#include "crc.h"
#include "InitVector.h"
#include "LocalNode.h"
#include "Cipher.h"
#include "Objects.h"
#include "ResponseManager.h"
#include "Login.h"
#include "HostScan.h"
#include "SearchContacts.h"
#include "ParentNode.h"
#include "Events.h"
#include "Presence.h"
#include "Query.h"
#include "SessionManager.h"
#include "ConsoleLogger.h"
#include "DirBlobManager.h"
#include "SessionCMDManager.h"

extern uchar			RecvBuffer[0xFFFF];
extern int				RecvBufferSz;
extern queue<RecvDesc>	RecvDQueue;
extern uchar			HttpsHandShakeTemplate[];
extern char				*SkypeModulus1536[];
extern char				*SkypeModulus2048[];
extern char				*SkypeModulus4096[];
extern SLoginDatas		GLoginD;
extern queue<Contact>	Contacts;
extern uchar			*Email;
extern uint				NbUserConnected;
extern TCPKeyPair		Keys;
extern Host				Session_SN;
extern uchar			DirBlob[];

extern uint				SuperWait;
extern uint				Blocking;
extern uint				NoWait;

extern ushort			LastPID;

extern unsigned int		my_public_ip;

int		InitProc();
void	EndProc();
void	showmem(uchar *Mem, uint Sz);

void	TSHOWMEM(CConsoleLogger ThreadConsole, uchar *str, int size);
int		TSENDPACKETTCP(CConsoleLogger ThreadConsole, SOCKET Socket, Host CurHost, uchar *Packet, uint Size, ushort CustomPort, int *Connected);

char	*Bin2HexStr(uchar *Bin, uint Size);
uchar	*MemDup(uchar *Mem, uint Size);
void	MemReverse(uchar *Mem, uint Size);
char    *KeySelect(uint KeyDesc);
void    ReadValue(uchar **BufferAddr, void *value);
void	ReadValueW(uchar **BufferAddr, void *Value);
void	WriteValue(uchar **BufferAddr, uint Value);
int		GetWrittenSz(uint Value);

void	cprintf(WORD Color, char *format, ...);

void	FlushSocket(SOCKET Socket, Host CurHost);
int		SendPacket(SOCKET Socket, Host CurHost, uchar *Packet, uint Size);
int		SendPacketTCP(SOCKET Socket, Host CurHost, uchar *Packet, uint Size, ushort CustomPort, int *Connected);
int		SendPacketTCPEx(SOCKET Socket, Host CurHost, uchar *Packet, uint Size, ushort CustomPort, int *Connected);
void	SendACK(ushort PacketID, SOCKET Socket, Host CurHost, ushort CustomPort, int *Connected, TCPKeyPair *Keys);
void	Listen2SN(Host SN);

void	LocationBlob2Location(uchar	*Location, CLocation *ContactLocation, uint BlobSz);
void	DumpLocation(CLocation *Location);

void	DumpTCPPacketObjs(uchar *Datas, uint DSize);

#endif /*COMMON_H*/