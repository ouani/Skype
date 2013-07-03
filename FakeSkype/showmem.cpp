#include		<stdio.h>
#include		"Common.h"

void	        TSHOWMEM(CConsoleLogger ThreadConsole, uchar *str, int size)
{
	int           offset;
	int           g_offset;
	int           line;
	int           nbr_lines;
	unsigned char *ptr;

	ptr = str;
	g_offset = 0;
	nbr_lines = (size / 16);
	if ((size % 16) != 0)
		nbr_lines++;
	for (line = 0; line < nbr_lines; line++)
	{
		ThreadConsole.printf("0x%p:", ptr);
		for (offset = 0; offset < 16; offset++)
		{
			ThreadConsole.printf(" ");
			if (g_offset >= size)
				ThreadConsole.printf("  ");
			else
			{
				if (*ptr < 16)
					ThreadConsole.printf("0");
				ThreadConsole.printf("%x", *ptr);
				g_offset++;
			}
			ptr += 1;
		}
		ptr -= 16;
		ThreadConsole.printf("  ");
		for (offset = 0; offset < 16; offset++)
		{
			if (ptr > (str + size))
				break;
			if (((*ptr >= ' ') && (*ptr <= '~')) == 0)
				ThreadConsole.printf(".");
			else
				ThreadConsole.printf("%c", *ptr);
			ptr++;
		}
		ThreadConsole.printf("\n");
	}
}

/*void	        showmem(uchar *str, int size)
{
	int           offset;
	int           g_offset;
	int           line;
	int           nbr_lines;
	unsigned char *ptr;

	ptr = str;
	g_offset = 0;
	nbr_lines = (size / 16);
	if ((size % 16) != 0)
		nbr_lines++;
	for (line = 0; line < nbr_lines; line++)
	{
		printf("0x%p:", ptr);
		for (offset = 0; offset < 16; offset++)
		{
			printf(" ");
			if (g_offset >= size)
				printf("  ");
			else
			{
				if (*ptr < 16)
					printf("0");
				printf("%x", *ptr);
				g_offset++;
			}
			ptr += 1;
		}
		ptr -= 16;
		printf("  ");
		for (offset = 0; offset < 16; offset++)
		{
			if (ptr > (str + size))
				break;
			if (((*ptr >= ' ') && (*ptr <= '~')) == 0)
				printf(".");
			else
				printf("%c", *ptr);
			ptr++;
		}
		printf("\n");
	}
}

*/

void			showmem(uchar *Mem, uint Sz)
{
	unsigned int i, j;

	if ((Sz == 0) || (Mem == NULL))
	{
		cprintf(RED, "ShowMem Error..\n");
		return ;
	}
 
    printf("0x%04x: ", 0);
    for (i = 0; i < Sz; i++)
	{
		printf("%02x%c", Mem[i], ' ');
		if ((i % 16) == 15)
		{
			printf(" ");
			for (j = 0; j < 16; j++)
				printf("%c", isprint(Mem[i - 15 + j]) ? Mem[i - 15 + j] : '.');
			if (i < (Sz - 1))
				printf( "\n0x%04x: ", i + 1);
		}
	}
	if (i % 16)
	{
		printf( "%*s ", 3 * (16 - (i % 16)), "" );
		for (j = 0; j < i % 16; j++)
			printf( "%c", isprint(Mem[i - (i % 16) + j]) ? Mem[i - (i % 16) + j] : '.' );
	}
	printf( "\n" );
}