/*

crc.h

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1992 Tatu Ylonen, Espoo, Finland
                   All rights reserved

Created: Tue Feb 11 14:37:27 1992 ylo

Functions for computing CRC.

*/

#ifndef CRC_H
#define CRC_H

unsigned short crc16(const unsigned char *buf, int len, int salt);

/* This computes a 32 bit CRC of the data in the buffer, and returns the
   CRC.  The polynomial used is 0xedb88320. */
unsigned long crc32(const unsigned char *buf, unsigned int len, int salt);
void		  minicrc32(unsigned int nb, unsigned int *salt);

#endif /* CRC_H */
