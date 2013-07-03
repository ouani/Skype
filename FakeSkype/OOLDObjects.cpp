#include "Objects.h"

int lookup_table1[] = {
	0x000, 0x2A3, 0x37C, 0x67C, 0x6A3, 0x6AE, 0xA84, 0xB74, 0xDAD, 0xF5D, 0xFB2, 0xFD4, 0xFFF
    };
    
int lookup_table2[] = {
	0x000, 0x123, 0x266, 0x2B4, 0x8A2, 0x9F5, 0xCFC, 0xF70, 0xFFF,
    };

int lookup_table3[] = {
	0x000, 0x14D, 0x34C, 0x42B, 0x4A3, 0x6CA, 0x953, 0x9C6, 0xA6C, 0xABB, 0xBAE, 0xC43, 0xC9B, 0xCDD, 0xD31, 0xD93,
	0xDB5
    };

unsigned char *data_cursor;
unsigned char *data_cursor_last;
unsigned char streambyte;

int lookup(int key, int *lookup_table) {
    int idx = 0;
    while (key >= *(lookup_table+idx)) {
        idx++;
    }
    return idx - 1;
}

struct {
   unsigned long int data; // 32 bits holder for the decoder data
   unsigned short int bit; // the decoder is always 1 bit late compared to the byte stream
   unsigned long int max; // maximum value (strict) of the current decoder data
} decoder;

typedef struct {
   int a;
   int b;
   int c;
   int *lookup_table;
} decode_data;

void filldecoder()
{
        // be greedy on the stream until we reach 31 bits produced
        // for the decoder
        while (decoder.max <= 1 << (7 + 2*8)) {
            streambyte=*data_cursor;
            decoder.data = (((decoder.data << 1) | (decoder.bit)) << 7) | (streambyte >> 1);
            decoder.bit = streambyte & 1;
            decoder.max = decoder.max << 8;
            //printf("decoder data produced: %x, max: %x\n", decoder.data, decoder.max);

            data_cursor++;
            
            // exit loop if no more data in the streaming pipe
            if (data_cursor > data_cursor_last) break;
        }
}

int getindex(int *lookup_table)
{
        int d_coded_symbol = 0; // coded symbol extracted from the encoded stream
        int d_index = 0; // index found for the currently analysed d_coded_symbol
         
        filldecoder();
        // here we know that we have at least 1 interesting 12bits sequence        
        // we lookup the index of this sequence in a lookup table
        //d_coded_symbol = decoder.data >> (7 + 3*8 - 12); // we want 12 bits left at least
        d_coded_symbol = decoder.data / (decoder.max >> 12);
        if ((d_coded_symbol >> 12))
           d_coded_symbol = (1 << 12) - 1;
        d_index = lookup(d_coded_symbol, lookup_table);
        //printf("coded symbol: %x found as idx:%d in [%x, %x]\n", d_coded_symbol, d_index, lookup_table[d_index], lookup_table[d_index+1]);

        // now that we consumed a 12 bit sequence,
        // the information inside the decoder be re-evaluated according
        // to the size of the interval
        //decoder.data = decoder.data - ((unsigned long int)lookup_table[d_index] << (7 + 3*8 - 12));
        decoder.data = decoder.data - ((unsigned long int)lookup_table[d_index] * (decoder.max >> 12));
        //decoder.max = ((unsigned long int)lookup_table[d_index+1] - (unsigned long int)lookup_table[d_index]) << (7 + 3*8 - 12);
        if ((lookup_table[d_index+1] >> 12))
           decoder.max = decoder.max - ((unsigned long int)lookup_table[d_index] * (decoder.max >> 12));
        else
           decoder.max = ((unsigned long int)lookup_table[d_index+1] - (unsigned long int)lookup_table[d_index]) * (decoder.max >> 12);
        //printf("decoder data consumed: %x, max: %x\n", decoder.data, decoder.max);
        return d_index;
}

int getindex2(int idx)
{
     int d_coded_symbol = 0; // coded symbol extracted from the encoded stream
     int d_index = 0; // index found for the currently analysed d_coded_symbol
    
     filldecoder();
     d_coded_symbol = decoder.data / (decoder.max >> idx);
     if ((d_coded_symbol >> idx))
        d_coded_symbol = (1 << idx) - 1;

     decoder.data = decoder.data - (d_coded_symbol * (decoder.max >> idx));
     if (((d_coded_symbol + 1) >> idx))
         decoder.max =  decoder.max - (d_coded_symbol * (decoder.max >> idx));
     else
         decoder.max = (decoder.max >> idx);
     return (d_coded_symbol);
}

int sub_getindex(int x, decode_data dd)
{
     int i, j, k, d_index, d_index2, result, idx2pass;
     
     i = 1;
     d_index = getindex(dd.lookup_table);
     if (!(d_index < (i << dd.b)))
     {
        d_index -= dd.c;
        if (!(d_index < dd.a))
        {
           if (x)
              return (0);
           else
           {
              k = sub_getindex(i, dd);
              if (!(k <= (0x20 - dd.a)))
                 return (0);
              else
                 d_index = k + dd.a;
           }
        }
        d_index -= 1;
        i <<= d_index;
        if (d_index <= 0)
           result = i;
        else
        {
            j = 0;
            while (j < d_index)
            {
                idx2pass = ((d_index - j) <= 0x10) ? d_index - j : 0x10;
                d_index2 = getindex2(idx2pass) & 0xFFFF;
                d_index2 <<= j;
                j += idx2pass;
                i += d_index2;
            }
            result = i;
        }
     }
     else
         result = d_index;
     return (result);
}

void	 WriteObject(uchar **Buffer, ObjectDesc Object)
{
	int	IdxDown, IdxUp;

	WriteValue(Buffer, Object.Family);
	WriteValue(Buffer, Object.Id);
	switch(Object.Family)
	{
	case OBJ_FAMILY_NBR:
		WriteValue(Buffer, Object.Value.Nbr);
		break;
	case OBJ_FAMILY_TABLE:
		IdxUp = 0;
		IdxDown = sizeof(Object.Value.Table) - 1;
		while (IdxDown >= 0)
			(*Buffer)[IdxDown--] = Object.Value.Table[IdxUp++];
		*Buffer += sizeof(Object.Value.Table);
		break;
	case OBJ_FAMILY_BLOB:
		WriteValue(Buffer, Object.Value.Memory.MsZ);
		memcpy_s(*Buffer, 0xFFFF, Object.Value.Memory.Memory, Object.Value.Memory.MsZ);
		*Buffer += Object.Value.Memory.MsZ;
		break;
	case OBJ_FAMILY_STRING:
		memcpy_s(*Buffer, 0xFFFF, Object.Value.Memory.Memory, Object.Value.Memory.MsZ);
		*Buffer += Object.Value.Memory.MsZ;
		*(*Buffer) = 0x00;
		*Buffer += 1;
		break;
	case OBJ_FAMILY_INTLIST:
		uint	*IntList;

		IdxUp = 0;
		IntList = (uint *)Object.Value.Memory.Memory;
		WriteValue(Buffer, Object.Value.Memory.MsZ);
		while (IdxUp < Object.Value.Memory.MsZ)
		{
			WriteValue(Buffer, IntList[IdxUp]);
			IdxUp++;
		}
		break;
	default:
		printf("WriteObject : Unmanaged Object Family\n");
		break;
	}
}

void	DumpObj(ObjectDesc Object)
{
	int	Idx;

	printf("ID : 0x%x\n", Object.Id);
	switch(Object.Family)
	{
	case OBJ_FAMILY_NBR:
		printf("Family : OBJ_FAMILY_NBR\n");
		printf("Nbr : 0x%x\n", Object.Value.Nbr);
		break;
	case OBJ_FAMILY_TABLE:
		printf("Family : OBJ_FAMILY_TABLE\n");
		printf("Table :\n");
		showmem(Object.Value.Table, sizeof(Object.Value.Table));
		break;
	case OBJ_FAMILY_NETADDR:
		printf("Family : OBJ_FAMILY_NETADDR\n");
		printf("Addr : %s/%d\n", Object.Value.Addr.ip, Object.Value.Addr.port);
		break;
	case OBJ_FAMILY_BLOB:
		printf("Family : OBJ_FAMILY_BLOB\n");
		printf("Blob :\n");
		showmem(Object.Value.Memory.Memory, Object.Value.Memory.MsZ);
		break;
	case OBJ_FAMILY_STRING:
		printf("Family : OBJ_FAMILY_STRING\n");
		printf("String : %s\n", Object.Value.Memory);
		break;
	case OBJ_FAMILY_INTLIST:
		printf("Family : OBJ_FAMILY_INTLIST\n");
		printf("IntList :\n");
		for (Idx = 0; Idx < Object.Value.Memory.MsZ; Idx++)
			printf("-> 0x%x\n", ((uint *)Object.Value.Memory.Memory)[Idx]);
		break;
	case OBJ_FAMILY_OBJLIST:
		printf("Family : OBJ_FAMILY_OBJLIST\n");
		break;
	default :
		break;
	}
}

int	DecodeRawObjects(uchar **Buffer, uint Size, SResponse *Response, ObjectDesc **Objs, int Suffix)
{
	int				NbObjs, Idx, IdxUp, IdxDown;
	uint			Family, Id, ObjList;
	uchar			*Str, *Mark;
	struct in_addr	IP;
	ObjectDesc		*Object;

	NbObjs = Family = Id = ObjList = 0;
	Mark = *Buffer;

	ReadValue(Buffer, &NbObjs);
	Idx = Suffix;

	while (Idx < NbObjs + Suffix)
	{
		Family = **Buffer;
		*Buffer += 1;
		ReadValue(Buffer, &Id);
		*Objs = (ObjectDesc *)realloc(*Objs, sizeof(ObjectDesc) * (Idx + 1));
		Object = &((*Objs)[Idx]);
		Object->Family = Family;
		Object->Id = Id;
		switch (Family)
		{
		case OBJ_FAMILY_NBR:
			ReadValue(Buffer, &(Object->Value.Nbr));
			break;
		case OBJ_FAMILY_TABLE:
			IdxUp = 0;
			IdxDown = sizeof(Object->Value.Table) - 1;
			while (IdxDown >= 0)
				Object->Value.Table[IdxUp++] = (*Buffer)[IdxDown--];
			*Buffer += sizeof(Object->Value.Table);
			break;
		case OBJ_FAMILY_NETADDR:
			IP.S_un.S_addr = htonl(*(unsigned long *)*Buffer);
			ZeroMemory(Object->Value.Addr.ip, MAX_IP_LEN + 1);
			strcpy_s(Object->Value.Addr.ip, MAX_IP_LEN + 1, inet_ntoa(IP));
			*Buffer += 4;
			Object->Value.Addr.port = *(unsigned short *)(*Buffer);
			*Buffer += 2;
			break;
		case OBJ_FAMILY_BLOB:
			ReadValue(Buffer, &(Object->Value.Memory.MsZ));
			Object->Value.Memory.Memory = (uchar *)malloc(Object->Value.Memory.MsZ);
			memcpy_s(Object->Value.Memory.Memory, Object->Value.Memory.MsZ, *Buffer, Object->Value.Memory.MsZ);
			*Buffer += Object->Value.Memory.MsZ;
			break;
		case OBJ_FAMILY_STRING:
			Str = *Buffer;
			Object->Value.Memory.MsZ = 1;
			while (*Str++ != 0)
				Object->Value.Memory.MsZ += 1;
			Object->Value.Memory.Memory = (uchar *)malloc(Object->Value.Memory.MsZ);
			memcpy_s(Object->Value.Memory.Memory, Object->Value.Memory.MsZ, *Buffer, Object->Value.Memory.MsZ);
			*Buffer += Object->Value.Memory.MsZ;
			break;
		case OBJ_FAMILY_INTLIST:
			ReadValue(Buffer, &(Object->Value.Memory.MsZ));
			Object->Value.Memory.Memory = (uchar *)malloc(Object->Value.Memory.MsZ * sizeof(uint));
			for (IdxUp = 0; IdxUp < Object->Value.Memory.MsZ; IdxUp++)
				ReadValue(Buffer, Object->Value.Memory.Memory + (Idx * sizeof(uint)));
			break;
		case OBJ_FAMILY_OBJLIST:
			uint	OldNbObj;

			ObjList += 1;
			OldNbObj = Response->NbObj;
			ManageObjects(Buffer, Size - (*Buffer - Mark), Response);
			NbObjs += Response->NbObj - OldNbObj;
			Idx += (Response->NbObj - OldNbObj) + 1;
			goto ContinueDecode;
			break;
		default :
			break;
		}
		Idx += 1;
ContinueDecode:
		continue ;
	}
	return (NbObjs - ObjList);
}

int	DecodeExtObjects(uchar **Buffer, uint Size, ObjectDesc **Objs)
{
	int				family_table[] = {0x00, 0x04, 0x03, 0x05, 0x02, 0x06, 0x01};
	int				IpIdTable[0xFF] = {0};
    int				idx1, idx2, family, id, nb_obj, Ips;
	int				value;
	struct in_addr	IP;
	ObjectDesc		*Object;

	*Objs = NULL;

	data_cursor = *Buffer;
	data_cursor_last = *Buffer + Size;
	streambyte = 0x00;
	
    decode_data dd1, dd2;
        
    decoder.data = 0;
    decoder.bit = 0;
    decoder.max = 0;        
    
    family = id = nb_obj = value = Ips = 0;
    
    dd1.a = 0x07;
    dd1.b = 0x02;
    dd1.c = 0x01;
    dd1.lookup_table = lookup_table2;
    
    dd2.a = 0x10;
    dd2.b = 0x01;
    dd2.c = 0x00;
    dd2.lookup_table = lookup_table3;
    
    // initialization of the stream read
    streambyte=*data_cursor;
    data_cursor++;
    
    // initialization of the decoder
    decoder.data = (streambyte >> 1);
    decoder.bit = streambyte & 1;
    decoder.max = 1 << 7; // 1 byte + shr
    
    // loop over the 'streaming data'
    // streambyte holds the currently observed byte of the octet-stream
    while (
            (data_cursor<data_cursor_last) // while data left on stream
            || ( decoder.max > 1 << (7 + 2*8) ) // or enough bits already produced
            )
    {
        idx1 = getindex(lookup_table1);
		if (!idx1)
			goto EndRead;
        // now we try to do something with the index we just found
        
        // real decoding:
        // the d_index must be used as an index to some symbol table
    
        if (idx1 > 6)
            goto case_default;
        if (idx1 != 6)
        {
            idx2 = idx1 - 1;
            goto case_common;
        }
        switch (idx1) {
            case 6:
                // some special handling here
                idx2 = sub_getindex(0, dd1) + 5;
                goto case_common;
case_default:
            default:
                // here, d_index seem to be an index to a 'mutating' TYPE table
                // get an additional information from the stream out of another lookup_table
                idx2 = sub_getindex(0, dd1);
                if ((idx1 - 6))
                {
                   family = family_table[idx1 - 6];
                   memcpy(family_table + 1, family_table, (idx1 - 6) * 4);
                   family_table[0] = family;
                }
case_common:
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
               // some special handling here
               family = family_table[0];
               id += idx2;
                        
			   *Objs = (ObjectDesc *)realloc(*Objs, sizeof(ObjectDesc) * (nb_obj + 1));
			   Object = &((*Objs)[nb_obj]);
			   Object->Family = family;
			   Object->Id = id;

               switch (family)
               {
                   case OBJ_FAMILY_NBR:
                        value = sub_getindex(0, dd2);
						Object->Value.Nbr = value;
                        break;
				   case OBJ_FAMILY_NETADDR:
					    IpIdTable[Ips] = id;
						Ips++;
						goto NoUpdate;
						break;
				   case OBJ_FAMILY_INTLIST:
						int	NbInt, NbIdx;

						NbInt = sub_getindex(0, dd2);
						if (NbInt > 0x3FFFFFFF)
							goto EndRead;
						Object->Value.Memory.MsZ = NbInt;
						Object->Value.Memory.Memory = (uchar *)malloc(NbInt * sizeof(uint));
						for (NbIdx = 0; NbIdx < NbInt; NbIdx++)
							((uint *)Object->Value.Memory.Memory)[NbIdx] = sub_getindex(0, dd2);
                   default:
                        break;
               }
               nb_obj += 1;
NoUpdate:
            break;
        }
    }
EndRead:
	filldecoder();
	*Buffer = data_cursor_last - (Ips * 0x06) - 1;
	int	  IpBrowse = 0;
	while (Ips)
	{
		*Objs = (ObjectDesc *)realloc(*Objs, sizeof(ObjectDesc) * (nb_obj + 1));
		Object = &((*Objs)[nb_obj]);
		Object->Family = OBJ_FAMILY_NETADDR;
		Object->Id = IpIdTable[IpBrowse++];
		
		IP.S_un.S_addr = htonl(*(unsigned long *)*Buffer);
		ZeroMemory(Object->Value.Addr.ip, MAX_IP_LEN + 1);
		strcpy_s(Object->Value.Addr.ip, MAX_IP_LEN + 1, inet_ntoa(IP));
		*Buffer += 4;
		Object->Value.Addr.port = *(unsigned short *)(*Buffer);
		*Buffer += 2;
		
		nb_obj += 1;
		Ips--;
	}
	return nb_obj;
}