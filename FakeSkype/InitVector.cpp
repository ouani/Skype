#include "InitVector.h"

unsigned int		Update(unsigned int iv)
{
	unsigned int	Update;

	Update = iv;
	__asm
	{
		pushad
		mov ecx, iv
		
		lea eax, dword ptr [ecx + ecx * 0x4]
		shl eax, 0x8
		sub eax, ecx
		lea eax, dword ptr [eax + eax * 0x8]
		lea ecx, dword ptr [ecx + eax * 0x2]
		lea eax, dword ptr [ecx + ecx * 0x2 + 0x4271]
		
		mov Update, eax
		popad
	}
	return (Update);
}

unsigned int		GenIV()
{
	unsigned int	SeedA, SeedB, InitialIV;

	SeedA = GetTickCount();
	SeedB = BytesRandom();
	InitialIV = SeedB ^ SeedA;
	InitialIV = Update(Update(Update(InitialIV)));
	return (InitialIV);
}
