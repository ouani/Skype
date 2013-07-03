#ifndef RESPONSEMANAGER_H
#define RESPONSEMANAGER_H

#include "Common.h"

void		ManageObjects(uchar **Buffer, uint Size, SResponse *Response);
void		UDPResponseManager(uchar **Buffer, uint *BufferSz, SResponse *Response);
void		UserPacketManager(uchar **Buffer, uint *BufferSz, SResponse *Response, AesStream_S *AesStream, uint HolyStream);
void		TCPResponseManager(uchar **Buffer, uint *Size, SResponse *Response);
void		MainArchResponseManager(uchar **Buffer, uint *BufferSz, SResponse *Response);

void		OLDTCPResponseManager(uchar **Buffer, uint *BufferSz, SResponse *Response, int Suite);

#endif /*RESPONSEMANAGER_H*/