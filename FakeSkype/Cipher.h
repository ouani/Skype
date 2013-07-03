#ifndef UNCIPHER_H
#define UNCIPHER_H

#include "Common.h"

void	InitKeyServer();
void	EndKeyServer();

void	InitKey(RC4_KEY	*RKey, unsigned int Seed);

void	UncipherObfuscatedTCPCtrlPH(unsigned char *Ciphered);
int		UnCipherObfuscated(unsigned char *Ciphered, unsigned int CipheredLen, char *cip, char *chost_ip);

void	CipherTCP(RC4_KEY *RKey, unsigned char *Data, unsigned int len);
void	Cipher(unsigned char *Data, unsigned int len, unsigned int ip, unsigned int host_ip, unsigned short TransID, unsigned int IV, BYTE IsResend);

#endif /*UNCIPHER_H*/