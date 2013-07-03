#include "Cipher.h"

#define	 SEED_CRC_LEN	12
#define	 RC4_KLEN		88
#define	 KEY_SERV_ADDR	"192.168.0.9"
#define	 KEY_SERV_PORT	33033

RC4_KEY		RGKey;

SOCKET		KeySock;
sockaddr_in	Server;

void	InitKeyServer()
{
	KeySock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	
	ZeroMemory((char *)&Server, sizeof(Server));
	Server.sin_family = AF_INET;
	Server.sin_port = htons(KEY_SERV_PORT);
	Server.sin_addr.s_addr = inet_addr(KEY_SERV_ADDR);
}

void	EndKeyServer()
{
	closesocket(KeySock);
}

int		GetKey(unsigned char *Key, unsigned int Seed)
{
	int			Res, SSz;
	fd_set		Sockets;

	SSz = sizeof(struct sockaddr_in);
	Res = sendto(KeySock, (char *)&Seed, 0x04, 0, (SOCKADDR *)&Server, SSz);

	FD_ZERO(&Sockets);
	FD_SET(KeySock, &Sockets);
	Res = select(FD_SETSIZE, &Sockets, NULL, NULL, NULL);
	if (Res)
		Res = recvfrom(KeySock, (char *)&Key[0], RC4_KLEN, 0, (SOCKADDR *)&Server, &SSz);

	return (1);
}

void	InitKey(RC4_KEY	*RKey, unsigned int Seed)
{
	unsigned char	Key[RC4_KLEN] = {0};
	int				i;

	for (i = 0; i < 0x14; i++)
		*(unsigned int *)(Key + 4 * i) = Seed;

	if (GetKey(Key, Seed) == 0)
		return ;

	RC4_set_key(RKey, RC4_KLEN - 8, Key);
}

void	UncipherObfuscatedTCPCtrlPH(unsigned char *Ciphered)
{
	unsigned char	Key[RC4_KLEN] = {0};
	unsigned int	Seed, i;
	RC4_KEY			RKeyHeader;

	Seed = htonl(*(unsigned int *)Ciphered);
	
	for (i = 0; i < 0x14; i++)
		*(unsigned int *)(Key + 4 * i) = Seed;

	if (GetKey(Key, Seed) == 0)
		return ;
	
	RC4_set_key(&RKeyHeader, RC4_KLEN - 8, Key);
	RC4(&RKeyHeader, 0x0A, Ciphered + 0x04, Ciphered + 0x04);
}

int		UnCipherObfuscated(unsigned char *Ciphered, unsigned int CipheredLen, char *cip, char *chost_ip)
{
	CipheredPacketHeader	*Header;
	unsigned char	ToCrc[SEED_CRC_LEN] = {0};
	unsigned int	seed, ip, host_ip, i, ResLen;
	unsigned char	Key[RC4_KLEN] = {0};
	unsigned short	TransID;
	RC4_KEY			RKey;

	if (Ciphered[2] != 0x02)
		return (-1);

	Header = (CipheredPacketHeader *)Ciphered;
	ip = htonl(inet_addr(cip));
	host_ip = htonl(inet_addr(chost_ip));
	TransID = htons(Header->TransID);
	
	memcpy(ToCrc, (void *)&host_ip, 4);
	memcpy(ToCrc + 4, (void *)&ip, 4);
	memcpy(ToCrc + 8, (void *)&TransID, 2);

	seed = crc32(ToCrc, SEED_CRC_LEN, -1) ^ htonl(Header->IV);
	
	for (i = 0; i < 0x14; i++)
		*(unsigned int *)(Key + 4 * i) = seed;

	if (GetKey(Key, seed) == 0)
		return (0);
	
	ResLen = CipheredLen - sizeof(CipheredPacketHeader);
	RC4_set_key(&RKey, RC4_KLEN - 8, Key);
	RC4(&RKey, ResLen, Ciphered + sizeof(CipheredPacketHeader), Ciphered + sizeof(CipheredPacketHeader));

	return (crc32(Ciphered + sizeof(CipheredPacketHeader), ResLen, -1) == htonl(Header->Crc32));
}

void	Cipher(unsigned char *Data, unsigned int len, unsigned int ip, unsigned int host_ip, unsigned short TransID, unsigned int IV, BYTE IsResend)
{
	unsigned char	ToCrc[SEED_CRC_LEN] = {0};
	unsigned int	seed, i;
	unsigned char	Key[RC4_KLEN] = {0};
	unsigned char	*Result;
	RC4_KEY			RKey;

	memcpy(ToCrc, (void *)&ip, 4);
	memcpy(ToCrc + 4, (void *)&host_ip, 4);
	memcpy(ToCrc + 8, (void *)&TransID, 2);

	if (!IsResend)
		seed = crc32(ToCrc, SEED_CRC_LEN, -1) ^ IV;
	else
		seed = TransID ^ IV;

	for (i = 0; i < 0x14; i++)
		*(unsigned int *)(Key + 4 * i) = seed;

	if (GetKey(Key, seed) == 0)
		return ;
	
	Result = (unsigned char *)malloc(len);
	RC4_set_key(&RKey, RC4_KLEN - 8, Key);
	RC4(&RKey, len, Data, Data);
}

void	CipherTCP(RC4_KEY *RKey, unsigned char *Data, unsigned int len)
{
	RC4(RKey, len, Data, Data);
}
