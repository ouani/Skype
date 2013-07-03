#ifndef DIRBLOBMANAGER_H
#define DIRBLOBMANAGER_H

#include "Common.h"

int			DirBlob2Contact(uchar *DirBlob, uint DbSize, Contact *DestContact);
Memory_U	GetDirBlobMetaDatas(uchar *DirBlob, uint DbSize);
void		DumpDirBlobMetaDatas(uchar *DirBlob, uint DbSize);

#endif /*DIRBLOBMANAGER_H*/