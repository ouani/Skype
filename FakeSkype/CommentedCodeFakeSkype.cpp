#include "Common.h"

int			main(int argc, char* argv[])
{
	WORD	wVersionRequested;
	WSADATA wsaData;
	int		err, account;
	Host	Session_SN;
	char	*User, *Pass;

	account = 9;

	if (account == 0)
	{
		User = "oj.med"; 
		Pass = "canastas";
	}
	else if (account == 1)
	{
		User = "mysegfault"; 
		Pass = "epitech";
	}
	else if (account == 2)
	{
		User = "chien.lunatic"; 
		Pass = "canastas";
	}
	else if (account == 3)
	{
		User = "courausarah1";
		Pass = "ibounanta";
	}
	else if (account == 4)
	{
		User = "james.de.meza"; 
		Pass = "cognac48";
	}
	else if (account == 5)
	{
		User = "phet78"; 
		Pass = "phet1461";
	}
	else if (account == 6)
	{
		User = "anne.fleur1984"; 
		Pass = "petipengouin";
	}
	else if (account == 7)
	{
		User = "oj.med.perm"; 
		Pass = "canastas";
	}
	else if (account == 8)
	{
		User = "oj.prez"; 
		Pass = "canastas";
	}
	else if (account == 9)
	{
		User = "oj.one"; 
		Pass = "canastas";
	}
	else if (account == 10)
	{
		User = "oj.two"; 
		Pass = "canastas";
	}

	InitLocalNode();
	//system("PAUSE");

	wVersionRequested = MAKEWORD(2, 2);
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0)
	{
		printf("Unable to start WSA Lib\n");
		return (0xBADF00D);
	}
	
	InitKeyServer();

	HostScan(&Session_SN);
	PerformLogin(User, Pass);	

	//SendPresence(Session_SN, User);
	SendPresence(Session_SN, User);

	EventContacts(User, Pass);	
	
	//Auto-Search To Verify Presence Brodcast
	/*Contact	UserC;

	ZeroMemory(&UserC, sizeof(UserC));
	UserC.Locations = new list<CLocation>;
	UserC.DisplayName = (uchar *)User;
	UserC.InternalName = (uchar *)User;
	UserC.BuddyStatus = 0;
	UserC.AuthCert = NULL;
	UserC.OnLineStatus = -1;
	Contacts.push(UserC);*/

	SearchContactList(Session_SN, User);
	InitialPingOnLine(Session_SN, User);

	//PerformFireWallTest(Session_SN);
	//SubmitUpdatedProps(Session_SN);
	
	Listen2SN(Session_SN);

	EndKeyServer();
	
	WSACleanup();
	return 0;
}
