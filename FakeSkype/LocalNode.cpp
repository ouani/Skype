#include <windows.h>

#include "Common.h"
#include "LocalNode.h"

uchar	 NodeID[NODEID_SZ] = {0};
uint	 StartTime = 0;

void	 InitUpTime()
{
	StartTime = GetTickCount();
}

uint	 GetUpTime()
{
	return ((GetTickCount() - StartTime) / 1000);
}

void	 InitNodeId()
{
	uint Up, Down;

	Up = BytesRandom();
	Down = BytesRandom();

	// FIXME : To Salt With <ProductID, C:\ Volume Serial Number, DiskIdentifier>
	memcpy_s(NodeID, NODEID_SZ, (uchar *)&Up, sizeof(Up));
	memcpy_s(NodeID + 4, NODEID_SZ - 4, (uchar *)&Down, sizeof(Down));
	
	/*printf("NodeID : \n");
	showmem(NodeID, NODEID_SZ);
	printf("\n");*/

	//FIXED NODEID

	memcpy_s(NodeID, NODEID_SZ, "\x49\x63\xff\xee\xe0\x5c\x9d\xf8", NODEID_SZ);
}

uchar	 *GetNodeId()
{
	return (&NodeID[0]);
}

void	 InitListeningPort()
{
	//Listen On Port DEF_LPORT
}

uint	 GetListeningPort()
{
	return (DEF_LPORT);
}

void	 InitLocalNode()
{
	InitUpTime();
	InitNodeId();
	InitListeningPort();
}