#include "Connection.h"

void	Connection::Flush()
{
	Status = DISCONNECTED;

	ZeroMemory(RecvBuffer, 0xFFF);
	RecvBufferSz = 0;

	int ReUse = 1;
	Socket = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(Socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&ReUse, sizeof(ReUse));

	ZeroMemory((char *)&SendAddr, sizeof(SendAddr));
	SendAddr.sin_family = AF_INET;
	SendAddr.sin_port = htons(Port);
	SendAddr.sin_addr.s_addr = inet_addr(IPAddress.c_str());
}

int		Connection::_Send(uchar *Datas, uint Size)
{

}

Connection::Connection(string cIPAddress = "0.0.0.0", ushort cPort = 0)
{
	IPAddress = cIPAddress;
	Port = cPort;
	Port = 443;	//FORCE HTTPS METHOD

	Flush();
}

int	Connection::Connect()
{
	if (Status == CONNECTED)
		return (1);

	if (Status == ERROR)
		Reset();

	if (Status == DISCONNECTED)
	{
		if (connect(Socket, (struct sockaddr *)&SendAddr, sizeof(SendAddr)) < 0)
		{
			return (-1);
		}
	}
}

int	Connection::Send(uchar *Datas, uint Size)
{
	if (Status == CONNECTED)
	{

	}
	else
		return (-1);
}

CSTATUS	Connection::GetStatus()
{
	return (Status);
}

void	Connection::Reset()
{
	closesocket(Socket);

	Flush();
}
