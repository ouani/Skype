#include "Objects.h"

unsigned char spec_chars[] = {
	0x2E, 0x2D, 0x2F, 0x5F, 0x21, 0x2B, 0x2C, 0x29, 0x3A, 0x28, 0x2A, 0x3F, 0x0D, 0x0A, 0x27, 0x26, 
	0x22, 0x3D, 0x3B, 0x7E, 0x40, 0x3E, 0x3C, 0x7C, 0x5E, 0x5D, 0x5B, 0x5C, 0x23, 0x60, 0x24, 0x25, 
	0x7B, 0x7D, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0B, 0x0C, 0x0E, 0x0F, 0x10, 
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x7F, 
	0x00, 0x00, 0x00, 0x00
};

unsigned char filling_chars[] = {
	0x00, 0x00, 0xD4, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3, 
	0xC1, 0x00, 0x00, 0x00, 0xC7, 0x00, 0xCB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDF, 0x00, 0x00, 
	0xCC, 0x00, 0x00, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x00, 
	0x00, 0xCB, 0x00, 0x00, 0x00, 0x00, 0xC4, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00, 0x00, 0xC2, 0x00, 0x00, 0x00, 0xC3, 0x00, 0x00, 
	0xC2, 0x00, 0xC9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0xCA, 0x00
};

unsigned char extd_chars[] = {
	0xD7, 0xC3, 0xD0, 0xC5, 0xE5, 0xC4, 0xE3, 0xD1, 0xE6, 0xE7, 0xEC, 0xE4, 
	0xE8, 0xEF, 0xE9, 0xD9, 0xD8, 0xEB, 0xEA, 0xE2, 0xC2, 0xE0, 0xED, 0xC6, 0xDB, 0xE1, 0xCE, 0xCF, 
	0xC0, 0xC1, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xDA, 0xDC, 
	0xDD, 0xDE, 0xDF, 0xEE, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 
	0xFC, 0xFD, 0xFE, 0xFF, 0x00, 0x00, 0x00, 0x00
};

unsigned char spec_extd_chars[] = {
	0x82, 0x99, 0xB8, 0xB3, 0xA9, 0x81, 0xBC, 0x9C, 
	0x85, 0x95, 0xA1, 0x9B, 0xA8, 0x84, 0xB0, 0x90, 0x80, 0xB6, 0x94, 0xA4, 0x91, 0xBA, 0x9E, 0x9A, 
	0xA0, 0xB5, 0xBD, 0xBE, 0xA7, 0x9D, 0x97, 0xA5, 0x9F, 0xAA, 0xB1, 0x83, 0x8C, 0x93, 0xB2, 0x98, 
	0xA6, 0xA2, 0xBB, 0x88, 0xAD, 0x96, 0x8F, 0xB4, 0xA3, 0x92, 0xBF, 0x87, 0xB7, 0x8B, 0x8D, 0xB9, 
	0x89, 0x8A, 0x8E, 0xAE, 0x86, 0xAC, 0xAB, 0xAF, 0x00, 0x00, 0x00, 0x00
};

unsigned char space_chars[] = {
	0x20, 0x00, 0x00, 0x00
};

unsigned char maj_voy_chars[] = {
	0x41, 0x45, 0x49, 0x4F, 
	0x55, 0x59, 0x00, 0x00
};

unsigned char maj_cons_chars[] = {
	0x53, 0x4D, 0x54, 0x42, 0x52, 0x4C, 0x4E, 0x50, 0x4B, 0x43, 0x44, 0x48, 
	0x47, 0x4A, 0x57, 0x46, 0x56, 0x5A, 0x58, 0x51, 0x00, 0x00, 0x00, 0x00
};
	
unsigned char chiffres_chars[] = {
	0x30, 0x32, 0x31, 0x36, 
	0x33, 0x34, 0x35, 0x37, 0x38, 0x39, 0x00, 0x00
};

unsigned char min_cons1_chars[] = {
	0x6E, 0x72, 0x6C, 0x73, 0x78, 0x00, 0x00, 0x00
};

unsigned char min_voy_chars[] = {
	0x65, 0x61, 0x69, 0x6F, 0x75, 0x79, 0x00, 0x00
};

unsigned char min_cons2_chars[] = {	
	0x74, 0x64, 0x6D, 0x68, 0x6B, 0x70, 0x63, 0x67, 
	0x77, 0x62, 0x7A, 0x66, 0x76, 0x6A, 0x71, 0x00
};

unsigned char null_chars[] = {
	0x00, 0x00, 0x00, 0x00
};

unsigned char *charsets[] = {
	null_chars, min_cons2_chars, min_voy_chars, min_cons1_chars, chiffres_chars, maj_cons_chars, maj_voy_chars, space_chars, spec_extd_chars,
	extd_chars, spec_chars, filling_chars
};

int lookup_table1[] = {
	0x000, 0x2A3, 0x37C, 0x67C, 0x6A3, 0x6AE, 0xA84, 0xB74, 0xDAD, 0xF5D, 0xFB2, 0xFD4, 0xFFF, 0x1000
};

int lookup_table2[] = {
	0x000, 0x123, 0x266, 0x2B4, 0x8A2, 0x9F5, 0xCFC, 0xF70, 0xFFF, 0x1000
};

int lookup_table3[] = {
	0x000, 0x14D, 0x34C, 0x42B, 0x4A3, 0x6CA, 0x953, 0x9C6, 0xA6C, 0xABB, 0xBAE, 0xC43, 0xC9B, 0xCDD, 0xD31, 0xD93,
	0xDB5, 0x1000
};

int lookup_table4[] = {
	0x000, 0x1000
};

int lookup_table5[] = {
	0x000, 0x636, 0x9C8, 0xAED, 0xBE5, 0xCA5, 0xF0E, 0xF7C, 0xF83, 0xF8A, 0xFC2, 0x1000
};

int lookup_table6[] = {
	0x000, 0x229, 0x3E3, 0x550, 0x6B9, 0x816, 0x969, 0xAB9, 0xBB7, 0xCAE, 0xD8A, 0xE42, 0xEF7, 0xF87, 0xFF1, 0x1000
};

int lookup_table7[] = {
	0x000, 0x1E1, 0x470, 0xC5C, 0xE79, 0xE88, 0xE8F, 0xE96, 0xF57, 0xF5E, 0xF87, 0x1000
};

int lookup_table8[] = {
	0x000, 0x452, 0x899, 0xB87, 0xE15, 0xF61, 0x1000, 0x000, 0x000, 0x4B8, 0x8CB, 0xC89, 0xFC1, 0x1000
};

int lookup_table9[] = {
	0x000, 0x21D, 0x66A, 0x87E, 0xE9F, 0xEAF, 0xEB6, 0xEBD, 0xF97, 0xF9E, 0xFBF, 0x1000
};

int lookup_table10[] = {
	0x000, 0x4B8, 0x8CB, 0xC89, 0xFC1, 0x1000
};

int lookup_table11[] = {
	0x000, 0x3A9, 0x76F, 0xCBA, 0xE7F, 0xE8E, 0xE95, 0xE9C, 0xF85, 0xF8C, 0xFB4, 0x1000
};

int lookup_table12[] = {
	0x000, 0x241, 0x42A, 0x5E2, 0x775, 0x901, 0xA88, 0xBFD, 0xD58, 0xEB2, 0x1000
};

int lookup_table13[] = {
	0x000, 0x1D4, 0x1DB, 0x1E2, 0x1E9, 0xE93, 0xE9A, 0xEA1, 0xF31, 0xF38, 0xF3F, 0x1000
};

int lookup_table14[] = {
	0x000, 0x1A0, 0x2FA, 0x420, 0x539, 0x63B, 0x739, 0x836, 0x928, 0xA07, 0xAE6, 0xBB7, 0xC86, 0xD43, 0xDF2, 0xEA1, 
	0xF2F, 0xF97, 0xFD8, 0xFF0, 0x1000
};

int lookup_table15[] = {
	0x000, 0xAB, 0x1E9, 0xB06, 0xC26, 0xC2D, 0xD68, 0xF05, 0xF4B, 0xF52, 0xFBD, 0x1000
};

int lookup_table16[] = {
	0x000, 0x5C8, 0x8DA, 0xBBD, 0xE2F, 0xF23, 0x1000
};

int lookup_table17[] = {
	0x000, 0x12E, 0x36D, 0x478, 0x898, 0x89F, 0xD91, 0xEC5, 0xF92, 0xF99, 0xFA9, 0x1000
};

int lookup_table18[] = {
	0x000, 0x1000
};

int lookup_table19[] = {
	0x000, 0x7, 0x3EA, 0x586, 0x6C7, 0x847, 0xD5F, 0xE37, 0xEC9, 0xED0, 0xF5F, 0x1000
};

int lookup_table20[] = {
	0x000, 0xEF, 0x1A5, 0x242, 0x2D4, 0x366, 0x3EE, 0x46A, 0x4DA, 0x54A, 0x5B3, 0x619, 0x67D, 0x6D6, 0x72D, 0x77D, 
	0x7CC, 0x819, 0x862, 0x8AA, 0x8F0, 0x935, 0x978, 0x9BA, 0x9F9, 0xA38, 0xA76, 0xAB3, 0xAF0, 0xB2C, 0xB63, 0xB99, 
	0xBCD, 0xC01, 0xC33, 0xC65, 0xC94, 0xCC3, 0xCF2, 0xD1E, 0xD49, 0xD73, 0xD9B, 0xDC2, 0xDE8, 0xE0D, 0xE31, 0xE53, 
	0xE73, 0xE93, 0xEB1, 0xECF, 0xEED, 0xF0B, 0xF28, 0xF44, 0xF5F, 0xF79, 0xF91, 0xFA6, 0xFBB, 0xFD0, 0xFE2, 0xFF1,
	0x1000
};

int lookup_table21[] = {
	0x000, 0x14D, 0x29D, 0x374, 0x526, 0x52D, 0x53A, 0x541, 0x649, 0x929, 0xFB1, 0x1000
};

int lookup_table22[] = {
	0x000, 0x233, 0x561, 0x755, 0x940, 0xA05, 0xABD, 0xB48, 0xBD0, 0xC40, 0xC8A, 0xCCB, 0xD0B, 0xD47, 0xD7F, 0xDB2, 
	0xDE2, 0xE05, 0xE19, 0xE2D, 0xE40, 0xE50, 0xE5C, 0xE66, 0xE70, 0xE7A, 0xE84, 0xE8E, 0xE98, 0xEA2, 0xEAC, 0xEB6, 
	0xEC0, 0xECA, 0xED4, 0xEDE, 0xEE8, 0xEF2, 0xEFC, 0xF06, 0xF10, 0xF1A, 0xF24, 0xF2E, 0xF38, 0xF42, 0xF4C, 0xF56, 
	0xF60, 0xF6A, 0xF74, 0xF7E, 0xF88, 0xF92, 0xF9C, 0xFA6, 0xFB0, 0xFBA, 0xFC4, 0xFCE, 0xFD8, 0xFE2, 0xFEC, 0xFF6,
	0x1000
};

int lookup_table23[] = {
	0x000, 0x7, 0xE, 0x15, 0x1C, 0x23, 0x2A, 0x31, 0x38, 0xFF2, 0xFF9, 0x1000
};

int lookup_table24[] = {
	0x000, 0x32F, 0x712, 0x82B, 0x904, 0x9C3, 0xA78, 0xB27, 0xBC0, 0xC42, 0xC9A, 0xCEA, 0xD36, 0xD7E, 0xDC5, 0xDEE, 
	0xE06, 0xE1B, 0xE30, 0xE3C, 0xE48, 0xE52, 0xE5C, 0xE66, 0xE70, 0xE7A, 0xE84, 0xE8E, 0xE98, 0xEA2, 0xEAC, 0xEB6, 
	0xEC0, 0xECA, 0xED4, 0xEDE, 0xEE8, 0xEF2, 0xEFC, 0xF06, 0xF10, 0xF1A, 0xF24, 0xF2E, 0xF38, 0xF42, 0xF4C, 0xF56, 
	0xF60, 0xF6A, 0xF74, 0xF7E, 0xF88, 0xF92, 0xF9C, 0xFA6, 0xFB0, 0xFBA, 0xFC4, 0xFCE, 0xFD8, 0xFE2, 0xFEC, 0xFF6,
	0x1000
};

int lookup_table25[] = {
	0x000, 0x15E, 0x41C, 0x4CE, 0x59C, 0x8C0, 0x985, 0x9B0, 0xB2C, 0xB33, 0xB58, 0x1000
};

int *lookups[] = {
	lookup_table4, lookup_table5, lookup_table6, lookup_table7, lookup_table8, lookup_table9, lookup_table10, lookup_table11,
	lookup_table12, lookup_table13, lookup_table14, lookup_table15, lookup_table16, lookup_table17, lookup_table18, lookup_table19,
	lookup_table20, lookup_table21, lookup_table22, lookup_table23, lookup_table24, lookup_table25
};

unsigned char	*data_cursor;
unsigned char	*data_cursor_last;
unsigned char	streambyte;

uchar			fid_table[0xA0 * 0x03] = {0};
uint			base_fid[] = {0x00, 0x04, 0x03, 0x05, 0x02, 0x06, 0x01};
int 			LvlPrev[0x03] = {0};

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

typedef	struct {
	int		type;
	int		id;
	int		size;
	int		objlinfid;
	uint	objlinfrank;
}			raw_coded;

queue<raw_coded>	raw_codedz;

raw_coded			Raw;

void	filldecoder()
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

int		getindex(int *lookup_table)
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

int		getindex2(int idx)
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

int		sub_getindex(int x, decode_data dd)
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

void	WriteObject(uchar **Buffer, ObjectDesc Object)
{
	int	IdxDown, IdxUp;

	Object.ObjListInfos.Id = -1;
	Object.ObjListInfos.Rank = 0;

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
	case OBJ_FAMILY_NETADDR:
		*(unsigned int *)(*Buffer) = inet_addr(Object.Value.Addr.ip);
		*Buffer += 4;
		*(unsigned short *)(*Buffer) = htons(Object.Value.Addr.port);
		*Buffer += 2;
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

ObjectDesc	*GetObjByID(SResponse Response, uint ID, uint ObjLID, uint ObjRank)
{
	ObjectDesc *Result = NULL;

	for (uint Idx = 0; Idx < Response.NbObj; Idx++)
	{
		if (Response.Objs[Idx].Id == ID)
		{
			if (ObjLID != -1)
			{
				if (Response.Objs[Idx].ObjListInfos.Id == ObjLID)
				{
					if (ObjRank != -1)
					{
						if (Response.Objs[Idx].ObjListInfos.Rank == ObjRank)
						{
							Result = (ObjectDesc *)malloc(sizeof(*Result));
							*Result = Response.Objs[Idx];
							break;
						}
					}
					else
					{
						Result = (ObjectDesc *)malloc(sizeof(*Result));
						*Result = Response.Objs[Idx];
						break;
					}
				}
			}
			else
			{
				Result = (ObjectDesc *)malloc(sizeof(*Result));
				*Result = Response.Objs[Idx];
				break;
			}
		}
	}

	return (Result);
}

void	DumpObj(ObjectDesc Object)
{
	int	Idx;

	printf("ID : 0x%x\n", Object.Id);
	printf("ObjListInfos : #%d(0x%x)/#%d(0x%x)\n", Object.ObjListInfos.Id, Object.ObjListInfos.Id, Object.ObjListInfos.Rank, Object.ObjListInfos.Rank);
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
	printf("\n");
}

uint	DefNbObjList(SResponse Response)
{
	uint	Max = 0;

	for (uint Idx = 0; Idx < Response.NbObj; Idx++)
	{
		if (Response.Objs[Idx].ObjListInfos.Rank > Max)
			Max = Response.Objs[Idx].ObjListInfos.Rank;
	}
	return Max;
}

int		DecodeRawObjects(uchar **Buffer, uint Size, SResponse *Response, ObjectDesc **Objs, int Suffix)
{
	int				NbObjs, lIdx, IdxUp, IdxDown;
	uint			Family, Id;
	uchar			*Str, *Mark;
	struct in_addr	IP;
	ObjectDesc		*Object;
	static int		Idx = 0;
	static int		Level = 0;
	static int		CurObjListId = -1;
	static uint		CurObjListRank = 0;
	uint			LocalObjListRank;

	LocalObjListRank = CurObjListRank;
	NbObjs = Family = Id = lIdx = 0;
	Mark = *Buffer;

	ReadValue(Buffer, &NbObjs);
	Level += 1;

	if (Level == 1)
		Idx += Suffix;

	while (lIdx < NbObjs)
	{
		Family = **Buffer;
		*Buffer += 1;
		ReadValue(Buffer, &Id);
		*Objs = (ObjectDesc *)realloc(*Objs, sizeof(ObjectDesc) * (Idx + 1));
		Object = &((*Objs)[Idx]);
		Object->Family = Family;
		Object->Id = Id;
		Object->ObjListInfos.Id = CurObjListId;
		Object->ObjListInfos.Rank = LocalObjListRank;

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
			IP.S_un.S_addr = *(unsigned long *)*Buffer;
			ZeroMemory(Object->Value.Addr.ip, MAX_IP_LEN + 1);
			strcpy_s(Object->Value.Addr.ip, MAX_IP_LEN + 1, inet_ntoa(IP));
			*Buffer += 4;
			Object->Value.Addr.port = htons(*(unsigned short *)(*Buffer));
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
			int		OldCurObjListId;

			OldCurObjListId = CurObjListId;
			CurObjListId = (int)Id;
			CurObjListRank += 1;
			OldNbObj = Response->NbObj;
			ManageObjects(Buffer, Size - (*Buffer - Mark), Response);
			CurObjListId = OldCurObjListId;
			//Suffix += Response->NbObj - OldNbObj;
			NbObjs -= 1;
			//Idx += (Response->NbObj - OldNbObj);
			goto ContinueDecode;
			break;
		default :
			break;
		}
		Idx += 1;
		lIdx += 1;
ContinueDecode:
		continue ;
	}

	Level -= 1;
	if (Level == 0)
	{
		Idx = 0;
		CurObjListId = -1;
		CurObjListRank = 0;
	}
	return (NbObjs);
}

int		DecodeExtObjects(uchar **Buffer, uint Size, SResponse *Response, ObjectDesc **Objs, int Suffix)
{
	uint			*family_table;
	int				IpIdTable[0xFF] = {0};
	int				idx0, idx1, idx2, family, id, nb_obj, Idx;
	int				value;
	struct in_addr	IP;
	uchar			*Mark;
	ObjectDesc		*Object;
	uchar			String[0xFFF];
	uchar			Character;
	int				x, a, y, i;
	static int		Init = 0;
	static int		RawSz = 0;
	static int		CurObjListId = -1;
	static uint		CurObjListRank = 0;
	uint			LocalObjListRank;

	LocalObjListRank = CurObjListRank;

	decode_data		dd1, dd2;

	Mark = *Buffer;
	data_cursor = *Buffer;
	data_cursor_last = *Buffer + Size;

	family = id = nb_obj = value = 0;

	dd1.a = 0x07;
	dd1.b = 0x02;
	dd1.c = 0x01;
	dd1.lookup_table = lookup_table2;

	dd2.a = 0x10;
	dd2.b = 0x01;
	dd2.c = 0x00;
	dd2.lookup_table = lookup_table3;

	if (Init == 0)
	{
		// initialization of the stream read
		streambyte=*data_cursor;
		data_cursor++;
		// initialization of the decoder
		decoder.data = (streambyte >> 1);
		decoder.bit = streambyte & 1;
		decoder.max = 1 << 7; // 1 byte + shr

		ZeroMemory(LvlPrev, sizeof(int) * 3);
		ZeroMemory(fid_table, (0xA0 * 3));
		for (uint fidx = 0; fidx < 3; fidx++)
			memcpy_s(fid_table + (0xA0 * fidx), (0xA0 * 3) - (0xA0 * fidx), base_fid, sizeof(base_fid));
	}
	Init += 1;

	family_table = (uint *)(fid_table + (0xA0 * (Init - 1)));
	// loop over the 'streaming data'
	// streambyte holds the currently observed byte of the octet-stream
	Idx = Suffix;
	idx0 = 0;
	if ((Init != 1) && (LvlPrev[Init - 1] != 0))
	{
		idx0 = sub_getindex(0, dd1);
		if (idx0 > LvlPrev[Init - 1])
			goto EndRead;
		LvlPrev[Init - 1] = 0;
	}
	while (
		(data_cursor<data_cursor_last) // while data left on stream
		|| ( decoder.max > 1 << (7 + 2*8) ) // or enough bits already produced
		)
	{
		if (idx0)
		{
			int chkidx = 0;

			family = family_table[(LvlPrev[Init - 1] * 2) + 8];
			idx0 -= 1;
			id = family_table[(LvlPrev[Init - 1] * 2) + 7];
			
			for (chkidx = 0; chkidx < 7; chkidx++)
			{
				if (family_table[chkidx] == family)
					break;
			}
			if (chkidx != 0)
			{
				memcpy(family_table + 1, family_table, chkidx * 4);
				family_table[0] = family;
			}							

			goto WriteObj;
		}
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
WriteObj:
		family_table[(LvlPrev[Init - 1] * 2) + 8] = family;
		family_table[(LvlPrev[Init - 1] * 2) + 7] = id;

		*Objs = (ObjectDesc *)realloc(*Objs, sizeof(ObjectDesc) * (Idx + 1));
		Object = &((*Objs)[Idx]);
		Object->Family = family;
		Object->Id = id;
		Object->ObjListInfos.Id = CurObjListId;
		Object->ObjListInfos.Rank = LocalObjListRank;

		switch (family)
		{
		case OBJ_FAMILY_NBR:
			value = sub_getindex(0, dd2);
			Object->Value.Nbr = value;
			break;
		case OBJ_FAMILY_TABLE:
			Raw.id = id;
			Raw.type = family;
			Raw.size = sub_getindex(0, dd2);
			Raw.objlinfid = CurObjListId;
			Raw.objlinfrank = LocalObjListRank;
			RawSz += Raw.size;
			raw_codedz.push(Raw);
			LvlPrev[Init - 1] += 1;
			goto NoUpdate;
			break;
		case OBJ_FAMILY_NETADDR:
			Raw.id = id;
			Raw.type = family;
			Raw.size = 0x06;
			Raw.objlinfid = CurObjListId;
			Raw.objlinfrank = LocalObjListRank;
			RawSz += Raw.size;
			raw_codedz.push(Raw);
			LvlPrev[Init - 1] += 1;
			goto NoUpdate;
			break;
		case OBJ_FAMILY_STRING:
			a = 0;
			i = 0;
			ZeroMemory(String, 0xFFF);
ReadLetter:
			Character = 0;
			x = getindex(lookups[a + 1]);
			y = 0;
			if (!(lookups[x * 2][1] == 0x1000))
				y = getindex(lookups[x * 2]);
			Character = charsets[x][y];
			if (Character == 0)
				goto NoLetter;
			String[i++] = Character;
			a = x * 2;
			goto ReadLetter;
NoLetter:
			Object->Value.Memory.MsZ = i + 1;
			Object->Value.Memory.Memory = (uchar *)malloc(Object->Value.Memory.MsZ);
			memcpy_s(Object->Value.Memory.Memory, Object->Value.Memory.MsZ, String, i + 1);
			break;
		case OBJ_FAMILY_BLOB:
			Raw.id = id;
			Raw.type = family;
			Raw.size = sub_getindex(0, dd2);
			RawSz += Raw.size;
			Raw.objlinfid = CurObjListId;
			Raw.objlinfrank = LocalObjListRank;
			raw_codedz.push(Raw);
			LvlPrev[Init - 1] += 1;
			goto NoUpdate;
			break;
		case OBJ_FAMILY_OBJLIST:
			uint	OldNbObj;
			int	OldCurObjListId;

			OldCurObjListId = CurObjListId;
			CurObjListId = (int)id;
			CurObjListRank += 1;
			OldNbObj = Response->NbObj;
			Response->NbObj += DecodeExtObjects(&data_cursor, Size - (data_cursor - Mark), Response, Objs, Idx);
			CurObjListId = OldCurObjListId;
			Suffix += Response->NbObj - OldNbObj;
			Idx += (Response->NbObj - OldNbObj);
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
		Idx += 1;
		LvlPrev[Init - 1] += 1;
NoUpdate:
		break;
		}
	}
	LvlPrev[Init - 1] -= 1;
EndRead:

	Init -= 1;
	if (Init == 0)
	{
		int IdxUp, IdxDown;

		filldecoder();
		*Buffer = data_cursor_last - RawSz;
		while (!raw_codedz.empty())
		{
			Raw = raw_codedz.front();

			*Objs = (ObjectDesc *)realloc(*Objs, sizeof(ObjectDesc) * (Idx + 1));
			Object = &((*Objs)[Idx]);
			Object->Family = Raw.type;
			Object->Id = Raw.id;
			Object->ObjListInfos.Id = Raw.objlinfid;
			Object->ObjListInfos.Rank = Raw.objlinfrank;

			switch(Raw.type)
			{
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
				Object->Value.Memory.MsZ = Raw.size;
				Object->Value.Memory.Memory = (uchar *)malloc(Object->Value.Memory.MsZ);
				memcpy_s(Object->Value.Memory.Memory, Object->Value.Memory.MsZ, *Buffer, Object->Value.Memory.MsZ);
				*Buffer += Object->Value.Memory.MsZ;
				break;
			}

			nb_obj += 1;
			Idx += 1;
			raw_codedz.pop();
		}
		RawSz = 0;
		LvlPrev[Init] = 0;
		CurObjListId = -1;
		CurObjListRank = 0;
	}
	return nb_obj;
}