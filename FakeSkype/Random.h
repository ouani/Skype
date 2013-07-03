#ifndef RANDOM_H
#define RANDOM_H

#include "Common.h"

uint	BytesSHA1(BYTE *Data, DWORD Length);
double	BytesSHA1d(BYTE *Data, DWORD Length);
uint	BytesRandom();
double	BytesRandomD();
ushort	BytesRandomWord();
double	PlatFormSpecific();
void	FillMiscDatas(unsigned int *Datas);
void	SpecialSHA(uchar *SessionKey, uint SkSz, uchar *SHAResult, uint ResSz);
void	BuildUnFinalizedDatas(uchar *Datas, uint Size, uchar *Result);
uchar	*FinalizeLoginDatas(uchar *Buffer, uint *Size, uchar *Suite, int SuiteSz);
void	GenSessionKey(uchar *Buffer, uint Size);
void	GetSessionKey(uchar *Buffer);

#endif /*RANDOM_H*/