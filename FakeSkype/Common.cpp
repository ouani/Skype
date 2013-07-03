#include "Common.h"

uchar	HttpsHandShakeTemplate[] = {
	0x80, 0x46, 0x01, 0x03, 0x01, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x05, 0x00, 0x00, 
	0x04, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x09, 0x00, 0x00, 0x64, 0x00, 0x00, 0x62, 0x00, 0x00, 0x08, 
	0x00, 0x00, 0x03, 0x00, 0x00, 0x06, 0x01, 0x00, 0x80, 0x07, 0x00, 0xC0, 0x03, 0x00, 0x80, 0x06, 
	0x00, 0x40, 0x02, 0x00, 0x80, 0x04, 0x00, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

char	*SkypeModulus1536[] = {"c095de9e868dc9fe1de94ab5e38e8dbdcae7e6249ef147de503f3e1c76e65af06f7714872f3527ee16410170196e4b2277db206827505bc48b4b63159f8eb0d56d14de686e5f6840e32522f8b7dafc6b901b83495757f4269b59440bc7824d4543eae2b00b9d4d21b0b056ae53d6cc6c3a35a5b10e72710cad00db5a42903e277e361cd1761a074afe997cc4a2c77427854ea1176da481cadb981ee145711c7160c5b31f5194f64ec919bf57dc544656f39bad7bbdacb6e46f22c30173df2ea7",
							   "a8f223612f4f5fc81ef1ca5e310b0b21532a72df6c1af0fbec87304aec983aab5d74a14cc72e53ef7752a248c0e5abe09484b597692015e796350989c88b3cae140ca82ccd9914e540468cf0edb35dcba4c352890e7a9eafac550b3978627651ad0a804f385ef5f4093ac6ee66b23e1f8202c61c6c0375eeb713852397ced2e199492aa61a3eab163d4c2625c873e95cafd95b80dd2d8732c8e25638a2007acfa6c8f1ff31cc2bc4ca8f4446f51da404335a48c955aaa3a4b57250d7ba29700b",
							   "aa4bc22ba5b925573c48bf886efad103a37d697283a3d37b8bf5a3eb2d09a9ae73e6905fcb3c6af06e4170b7a1856c70eab972cd3a468a28d7a87ceaad2404126dd5843f8895a0cfd9b07085afe60b8ae391a703479846d800737ab02fca5ead5673f416d5fb4a95e1d27bb4b7ca5411e74e98623f563b1d3709d749b3ee6d87242a8da04f39fd61ea679acc8e28601dadcc4434918dc544cd365f7b897600b3fb62875f4517ae32601764ae8d28b924074e47ebc2bcaaa42d9d8feb82137787",
							   NULL
							  };

char	*SkypeModulus2048[] = {"b8506aeed8ed30fe1c0e6774874b59206a77329042a49be2403da47d50052441067f87bcd57e6579b83df0bade2beff5b5cd8d87e8b3edac5f57fabccd49695974e2b5e5f0287d6c19ecc31b4504a9f8be25da78fa4ef345f91d339b73cc2d70b3904e11ca570ce9b5dc4b08b3c44b74dc463587ea637ef4456e61462b72042fc2f4ad5510a9850c06dc9a7374412fcadda955bd9800f9754cb3b8cc62d0e98d8282180971055b457c06f351e61164fc5a9de9d83d1d1378964001380b5b99ee4c5c7d50ac2462a4b7ea34fd32d90bd8d4b46410263673f900d1c60470165df9f3cb48016ab8ca45ce6875a71d977915ca8251b50258748dbc37fe332edc2855",
							   "bfe2db4bdf48358d3ae7c7d260989e4c7c1d81e6d9bd62e3a34dcaaa55f16c8c976a8862bc2462ae1b4063fd3d0de97e8aee5b793e171e22136319ff3474667c47ed1c14a892a19644005401cef46b5a8bd9510b3c8eeff80755decd2932cdca9119d96c5e16f6603b24ccc062822ca250336915a77aeab693268e1e22b1209d22f65a54cf7bcc7a4f9677eab54df8c33b16755ce1cf907efae988df8a4b4fad0591d95617189cd5ae0ef0935b2b458d72c7cc3de19a6268af4b06a8ce324292ca01b6a3adf7d133101a1e6659b03e0a1e14f07f8a11f5ec945c1a6f1eff06e75764262749acd6c3bf59503d970b038f77018cb09eb924fc2045db9b3248d6d5",
							   "9f2a6038e8132c3545bc7c5fbe56903e08e83353b1defe7042b5c8457ba5a40254b2812a843be54993dafed5fa55a415be652e2ff533483a1ab3907c5603df47a59311973c2b4c39cf942a58f12149ce0437b341aa58add6dc2ab27800f1f529975506c10925e5254ff0766ed276b194d36c783a7d426672e32e7d6881c91e167ccbb38f4f9ee703d621712b7de384c6c97fe5cf557c839d47ebf1c45db2ec554b4aebf203d00896e9b202e564251f6fc623f6810208ffd1497c4de673d87d693febc17ec5157aa5aa8a0055976fd4817b6ccef76d4525741820d72ef89c2558971189c5e42cdeb271590f6bb0e2bede43a28003f54298be689a39791ec8a919",
							   "bf137933ab269e3bacbea76da16f6ff06748028e79efe20aa696368fc88f6abca4571790f3d67ea4b6f382850f8f27a2ee4c044be541083d74ecbb30142070a7bc2746ff01fb243c4ec2a5fba296c3fb9c357429b4d511741bd2bf97034d29fe4fbd9013df87b725941e9696635fd53caf2f56b7b3609c51b8448256c4fb6078dde89f06d54c8bb4e2f6fbfb6ee42e698649e32e74dc542c94c2be3f9833ef22f988f9aa9c4fa5267b8aaf455ef06c693a36ca4447763e865086070713328e2f835649e1a15d78eaa6f90f9b5a6fac3f2eb3e24979bdacc4843956ef44c186f5007278c7d6cc1ceaefd8c56121ffa39c8d75873ae5a853b7cd1002885b49b209",
							   "d7edafe450023e3a4b0f7f1925196943ce1defd4d158cc868a29973bbedb9b90d203331b01c9752f254d7c922f8b5bdba2d25bd5955b887f26532afda73e37527f1265925ddbb6f1ed5efd660b1cad6ecb94628e1c90311a320db1a758ec36e3df926df48ebc1c099714dfe5e7541eec3ce96dd7d6f8b55288c081646c51a6b77f5c1ef1025b7862ee9d5e7d491293471ae7159daa40ccd7db2753071c11264aa5cc861d5fedc8fed6f2503b0a68a17d78cdfe3f698bd8af21ac1152f2dcef7c515bd9c9e4934cd9c9977ade4c77fbcd184111332f2737847b5ee713b6568d55c14618ae1e4ce088431709d9ad8fae987887ac829c3f7968bee8d1cfd347e341",
							   "d52af9c4194936e76ca66fd276533926d073b261c8de4cba4ea8f758dcce63e1c391220085ac94492926fde61ac0ca4b7b1acdd90a4d601b242cd2f890d8f826ab0c269bf1d23f497f2c236f1f57c01b881b88616eab2aa2028d533bb449b579063fcd287fba64ab0d64f4c1f38845d22017be45b7942348b494b1dd73982719be5ee37384b9feb41473e8bf71c8c4edab7a486907879e6a797baa2d7d9462fc24a7ad6a00598646064beb19f27513bee559f0316a398eaa5d5e618a41fc0d16ee1c6cf17e84bf7571227fe98a29d205c0ffd5546bed9f87e22e49ebee6d58e908e268d258d7520589f2b730d72639bb751ac4fb4d39125bb5b205bacfb423df",
							   "a4deafb40a982a87c989fe919b888dfe185113b17106b3241e7d166177b322b790131ddebae8d878bd8ae7e2e39794cab70988778cb13d121528e260eedabb3df35a320a02b7e68b63d4cd143d0ef93ab565d2163e467b77ae4644e9850e922fcdc61c58020e236a70557188e8ff2c332ff9e4f3d984042a2c802917ba9bcdf9277b4de3bf7055423bcac61332f2983d3fd9074dcb610e4c8d751bb38d4c20b470a8314d44790462e62c3b45a77cc290aab52b0a237fccd7513b5e8fd50ec4e79dac5047191417ffd68ebfa023f275a0fff93531cdda7b6287d34e41e89227c2942b6aeca11956fdb566f65be7f1c456b1b07b731cb78698b08478f5e7c856cb",
							   "a903c6079aac211634af60c85955889da69a552a2e994ef9395a53fc258c78c6308961d7bf3e87dd85ebb55087ffa151433514901e5b8e79458209864e82d839de8793002e15528d979a4b853a47a7d74e463ebdc321827308559c68a81f6de72660625f577ac42fc0addd31ad8697155de21d977bd9874ce65a6232cad0c08a21b9a2a3d4d14923115ff0d9b5f09e645f4d3a6c45ca1838a8f7a519b2d82fd82282678260d934bc8d42314ac6c703189ad734b2e9c8d285a50447fda2d01bd26452e63ce290ca1f88b1237abdd942372a384902ab3495a37bfd68c45d46008d134984f06f9114d411bd560fe48ec3a16a3f4ff0127ca52928f3261ddbb76b9d",
							   "b4792d7289d6aaba727b338d6ed91f7fa34f9d9abca23795bff72f7f38f4c27b416149489891c2b615d0b5db19a09d6462d26ee12526f93f4bd129655ecc890727f8a6ec71c17a82b02f68afe8dab6e40620236753784d4a279159dc613b2eebc1bbf9fa65b8ca1d13ded28ea575c591738772369ca4049329d10c06c194e92e13394f8b53c890235b922f18b24ccc71d59065aa6e45889da11d33feee17bd994c456d7635238f431403badb45b9ea907e4385ae2ef178dd5154c77895e9a8f60eef3c3969b356a0c11e6d3d4d0563c1e76d8268117f0eb4c160b3b941e77518a6361d17241f28c7f84ee0e378a831782e9dc688584a0ef9b383835e202bd67f",
							   NULL
							  };

char	*SkypeModulus4096[] = {"c3ac2b9912720fd9d5d121570bb8acb6c5b9b5ad4af08b75a68728860759a256f1c4357a329ac61528e968b7b41cae0f7c61784e0e72e465828fbb4e92931a2e14856d4a9600045df661cca37ccd6b993c93fcf62c0eab46882460df70b6f866293bd6d8fe35bcbd9c63ca4909c30652933d2b1943e67633af7ad0599ac8a61b914e2b97d9b1736683f1457695842951fff68e36fc170a54ddbb6b4f7d0361f5a6c36ad2837281aa9359460e6e15aa84d0e17ba9f1a9de3c88cc9233e371a6f18e48892e570679be601ddc134669967e2c550895ed97e49189b7164997eb266540b6b19d259188ddb9224ee846d1d2ca4e86eba4be39a7b1662f7e230b9d8a8f2553f3394a8b6f0668c3372bbba713064543b8f932ca34b3eb44bd8533191550b06960553a0e69386770569c1bc087d21976ef570f6634a5dd127407af32f39a56f5e72aed3590fa4722dc0a55e475b2d1ab39b2f0904168f97a16f4762d6804f7164feecc1a57823a3786c53bcdd73a7086ecd56142af052b86dec233ef8abeab437436c6c1c6ce231aa93bdf669f25c1c30b12df932df4b9662f90b1e1aaeca77a6c773dcb28669cf1852b8c14615e52905ccf3beac1546f499778dd01fc060876afe3f5f97de6d3cccae7a686222c17699f5968c453fd6f692e8254961018f5986d98c01c357d624d3d6c44e3b4ca344de00b2d8bf3939c2758b057bd4985",
							   "ba7463f3b6ccfd1327750915654e4823a5594b656cb9114b17146425bf5d720c9d94ca0bd2ca74ee8ac1af7940950ceebd161b1a631e4a6c98015a056d7af2decc2fc582a0b04ccb5eebb06a438816fbc594de942f9a90fb5c89bdcf215f0ddd59afba36b03538f5ef348dd96366900419c488263dbc547f26ffb54e9fb8faa5a9fed038bc2bd3b14a6b4ffaa5e01e84a029df338e47b267e15976508abb83b4bf88c523b5af7ba597fc4f4b07da84cd4eafb06cd9dee246854bb82be2620981e0c1491d0ed9ad67810cbf1ee7ad7d89a4c66ecb24f10d1c57e7a6947566a8a9739b2ca0af160761cddb4bf279ff6668a46c6c38a365dfeac5ba0f130418fe6234ae0642bff18c9a3422b0ef0f64373f7414ccf80cfd5440b3752de911542cdc10a25899ef7ff7ef32e8d6626caf5d8887d593a7323d663d5c1cd4885b48f3adfa529c42c9177519a2c283db8b68791dd8020cf2fb047fcf58d4605d3891074598eadf1b9c8da1a88b7fd7635d419c16ad109ed288f461d64325ae4929298c204e877515417645057bca10c6ceb3de4bd63441f2e2e2b03bad33781bf4e242f30da3e2407736668ced9193e022b75ab4f65d7201999fa317e9ad30a80080797279bfebd89614827c323979ec5141a25c15bf800f337907fe50b0cdb9eb07b9665958cc9373188dd58eb6571f1f41c4aa7b6357138557a37d122ab6c3f7cd2de9",
							   NULL
							  };

uchar	KeyDescTable[] = {
							0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
							0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 
							0x01, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 
							0x02, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 
							0x00, 0x08, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 
							0x05, 0x00, 0x00, 0x00, 0x05, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
							0x06, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07, 0x10, 0x00, 0x00, 
							0x00, 0x08, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 
							0x01, 0x00, 0x00, 0x00, 0x01, 0x20, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 
							0x00, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x80, 
							0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
							0xFF, 0xFF, 0xFF, 0xFF
						};

unsigned char	RecvBuffer[0xFFFF];
int				RecvBufferSz;
queue<RecvDesc>	RecvDQueue;

uint			SuperWait = 0;
uint			Blocking = 0;
uint			NoWait = 0;

char	*Bin2HexStr(uchar *Bin, uint Size)
{
	char *Result;
	uint	 Idx;

	Result = (char *)malloc((Size * 2) + 1);
	ZeroMemory(Result, (Size * 2) + 1);
	for (Idx = 0; Idx < Size; Idx++)
	{
		char	Tmp[4] = {0};
		uchar	X = Bin[Idx];

		_snprintf_s(Tmp, 4, 2, "%02x", X);
		strcat_s(Result, (Size * 2) + 1, Tmp);
	}
	return (Result);
}

uchar	*MemDup(uchar *Mem, uint Size)
{
	uchar	*Res;

	Res = (uchar *)malloc(Size);
	memcpy_s(Res, Size, Mem, Size);
	
	return (Res);
}

void	MemReverse(uchar *Mem, uint Size)
{
	uint	Idx = 0;
	uchar	Tmp;

	while (Idx < Size / 2)
	{
		Tmp = Mem[Idx];
		Mem[Idx] = Mem[Size - 1 - Idx];
		Mem[Size - 1 - Idx] = Tmp;
		Idx++;
	}
}

char	*KeySelect(uint KeyDesc)
{
	char	*Key;
	uchar	*KeyDescTableEx;

	Key = *SkypeModulus1536;
	KeyDescTableEx = KeyDescTable;
	__asm
	{
		pushad

		mov eax, dword ptr [KeyDescTable + 0x04]
		mov edx, 0x1000
		mov edi, KeyDesc
		cmp eax, edx
		mov ebx, KeyDescTableEx
		ja  SelectEnd
KeySelectL:
		mov eax, dword ptr [ebx + 0x08]
		cmp eax, -1
		jnb	SelectEnd
		mov ecx, dword ptr [ebx + 0x04]
		cmp ecx, 0x600
		je  Key1536
		cmp ecx, 0x800
		je	Key2048
		cmp ecx, edx
		jne	SelectEnd
		mov ecx, eax
		shl ecx, 0x0A
		lea esi, dword ptr [SkypeModulus4096 + eax + ecx]
		jmp Validate
Key2048:
		mov ecx, eax
		shl ecx, 0x09
		lea esi, dword ptr [SkypeModulus2048 + eax + ecx]
		jmp Validate
Key1536:
		lea ecx, [eax + eax * 0x02]
		shl ecx, 0x07
		lea esi, dword ptr [SkypeModulus1536 + eax + ecx]
Validate:
		cmp dword ptr [ebx], edi
		je  KeyOK
		mov eax, dword ptr [ebx + 0x10]
		add ebx, 0x0C
		cmp eax, edx
		jbe KeySelectL
KeyOK:
		mov eax, dword ptr [esi]
		mov Key, eax
SelectEnd:
		popad
	}

	return (Key);
}

void	 ReadValue(uchar **BufferAddr, void *Value)
{
	__asm
	{
		pushad

		mov edi, Value
		xor esi, esi
		mov dword ptr [edi], 0x00
		mov ebx, BufferAddr
ReadAgain:
		mov eax, dword ptr [ebx]
		mov ecx, esi
		add esi, 0x07
		mov dl, byte ptr [eax]
		inc eax
		mov dword ptr [ebx], eax
		mov al, dl
		and eax, 0x7F
		shl eax, cl
		mov ecx, dword ptr [edi]
		or ecx, eax
		test dl, 0x80
		mov dword ptr [edi], ecx
		je ReadEnd
		jmp ReadAgain
ReadEnd:

		popad
	}
}

void	 ReadValueW(uchar **BufferAddr, void *Value)
{
	__asm
	{
		pushad

		mov edi, Value
		xor esi, esi
		mov word ptr [edi], 0x00
		mov ebx, BufferAddr
ReadAgain:
		mov eax, dword ptr [ebx]
		mov ecx, esi
		add esi, 0x07
		mov dl, byte ptr [eax]
		inc eax
		mov dword ptr [ebx], eax
		mov al, dl
		and eax, 0x7F
		shl eax, cl
		mov ecx, dword ptr [edi]
		or ecx, eax
		test dl, 0x80
		mov dword ptr [edi], ecx
		je ReadEnd
		jmp ReadAgain
ReadEnd:

		popad
	}
}

void	 WriteValue(uchar **BufferAddr, uint Value)
{
	__asm
	{
		pushad

		mov ecx, Value
		mov eax, BufferAddr
		cmp ecx, 0x7F
		jbe JustWrite
WriteAgain:
		mov esi, dword ptr [eax]
		mov dl, cl
		or  dl, 0x80
		mov byte ptr [esi], dl
		mov edx, dword ptr [eax]
		shr ecx, 0x07
		inc edx
		cmp ecx, 0x7F
		mov dword ptr [eax], edx
		ja  WriteAgain
JustWrite:
		mov edx, dword ptr [eax]
		mov byte ptr [edx], cl
		mov ecx, dword ptr [eax]
		inc ecx
		mov dword ptr [eax], ecx

		popad
	}
}

int		GetWrittenSz(uint Value)
{
	uchar	Buffer[0x0F] = {0};
	uchar	*Browser = Buffer;
	uchar	*Mark = Browser;

	WriteValue(&Browser, Value);
	return ((int)(Browser - Mark));
}

void	cprintf(WORD Color, char *format, ...)
{
	va_list	ap;

	va_start(ap, format);
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO Previous;

	GetConsoleScreenBufferInfo(hConsole, &Previous);
	SetConsoleTextAttribute(hConsole, Color);
	
	vprintf(format, ap);

	SetConsoleTextAttribute(hConsole, Previous.wAttributes);
	va_end(ap);
}

/* FIXME : SHOULD UNCIPHER TO KEEP STREAM UP TO DATE */
void	FlushSocket(SOCKET Socket, Host CurHost)
{
	fd_set			m_TCPSockets;
	int				SelRes = 0;
	int				Res = -1;
	timeval			Wait = {0, 0};
	uchar			Buffer[0x1000] = {0};
	

	RecvBufferSz = 0xFFFF;
	ZeroMemory(RecvBuffer, 0xFFFF);

	Res = -1;
	FD_ZERO(&m_TCPSockets);
	FD_SET(Socket, &m_TCPSockets);
		
	RecvBufferSz = 0;
	while ((SelRes = select(FD_SETSIZE, &m_TCPSockets, NULL, NULL, &Wait)))
	{	
		Res = recv(Socket, (char *)&(Buffer[0]), sizeof(Buffer), 0);
		if (Res == 0)
		{
			printf("Connection reset by peer !\n");
			return ;
		}
		else if (Res == -1)
		{
			printf("Socket Error\n");
			return ;
		}
		else
		{
			printf("%d Bytes Flushed..\n", Res);
			memcpy_s(RecvBuffer + RecvBufferSz, 0xFFFF - RecvBufferSz, Buffer, Res);
			RecvBufferSz += Res;
		}

		FD_ZERO(&m_TCPSockets);
		FD_SET(Socket, &m_TCPSockets);
	}
	
	if ((Res == -1) || (Res == 0))
		return ;
	return ;
}

int		SendPacket(SOCKET Socket, Host CurHost, uchar *Packet, uint Size)
{
	sockaddr_in		Sender, ReplyTo;
	fd_set			m_UDPSockets;
	timeval			Wait = {0, 300000};
	int				SelRes = 0;
	int				Res = -1;
	uchar			Buffer[0x1000];
	int				RptSz;
	
	RecvBufferSz = 0xFFFF;
	RptSz = sizeof(struct sockaddr_in);

	ZeroMemory(RecvBuffer, 0xFFFF);
	ZeroMemory((char *)&Sender, sizeof(Sender));
	Sender.sin_family = AF_INET;
	Sender.sin_port = htons(CurHost.port);
	Sender.sin_addr.s_addr = inet_addr(CurHost.ip);

	Res = sendto(Socket, (const char *)Packet, Size, 0, (SOCKADDR *)&Sender, sizeof(Sender));
	printf("%d Bytes sent..\n", Res);

	if ((Res == -1) || (Res == 0))
		return (0);
		
	Res = -1;
	FD_ZERO(&m_UDPSockets);
	FD_SET(Socket, &m_UDPSockets);

	RecvBufferSz = 0;
	while ((SelRes = select(FD_SETSIZE, &m_UDPSockets, NULL, NULL, &Wait)))
	{	
		RptSz = sizeof(struct sockaddr_in);
		Res = recvfrom(Socket, (char *)&Buffer[0], sizeof(Buffer), 0, (SOCKADDR *)&ReplyTo, &RptSz);
		if (Res == 0)
		{
			printf("Connection reset by peer !\n");
			return (0);
		}
		else if (Res == -1)
		{
			printf("Socket Error\n");
			return (0);
		}
		else
		{
			printf("%d Bytes in response..\n", Res);
			memcpy_s(RecvBuffer + RecvBufferSz, 0xFFFF - RecvBufferSz, Buffer, Res);
			RecvBufferSz += Res;
		}

		FD_ZERO(&m_UDPSockets);
		FD_SET(Socket, &m_UDPSockets);
	}

	if ((Res == -1) || (Res == 0))
		return (0);
	return (1);
}

int		SendPacketTCP(SOCKET Socket, Host CurHost, uchar *Packet, uint Size, ushort CustomPort, int *Connected)
{
	sockaddr_in		Sender;
	fd_set			m_TCPSockets;
	timeval			Wait = {1, 0};
	int				SelRes = 0;
	int				Res = -1;
	uchar			Buffer[0x1000];
	

	RecvBufferSz = 0xFFFF;
	ZeroMemory(RecvBuffer, 0xFFFF);

	if (SuperWait)
		Wait.tv_sec = (SuperWait == 1) ? 10 : 5;

	if (!(*Connected))
	{
		ZeroMemory((char *)&Sender, sizeof(Sender));
		Sender.sin_family = AF_INET;
		Sender.sin_port = htons((CustomPort == -1) ? CurHost.port : CustomPort);
		Sender.sin_addr.s_addr = inet_addr(CurHost.ip);

		if (connect(Socket, (struct sockaddr *)&Sender, sizeof(Sender)) < 0)
		{
			printf("Connection refused..\n");
			return (0);
		}
		*Connected = 1;
	}

	Res = send(Socket, (const char *)Packet, Size, 0);
	printf("%d Bytes sent..\n", Res);

	if ((Res == -1) || (Res == 0))
		return (0);

	if (NoWait)
	{
		NoWait = 0;
		return (1);
	}
	Res = -1;
	FD_ZERO(&m_TCPSockets);
	FD_SET(Socket, &m_TCPSockets);
		
	RecvBufferSz = 0;
	while ((SelRes = select(FD_SETSIZE, &m_TCPSockets, NULL, NULL, (Blocking) ? NULL : &Wait)))
	{	
		Res = recv(Socket, (char *)&(Buffer[0]), sizeof(Buffer), 0);
		if (Res == 0)
		{
			printf("Connection reset by peer !\n");
			return (0);
		}
		else if (Res == -1)
		{
			printf("Socket Error\n");
			return (0);
		}
		else
		{
			printf("%d Bytes in response..\n", Res);
			memcpy_s(RecvBuffer + RecvBufferSz, 0xFFFF - RecvBufferSz, Buffer, Res);
			RecvBufferSz += Res;
		}

		FD_ZERO(&m_TCPSockets);
		FD_SET(Socket, &m_TCPSockets);

		if (SuperWait)
		{
			if (SuperWait == 2)
				break;
			Wait.tv_sec = 1;
			Wait.tv_usec = 0;
		}
		/*else
		{
			Wait.tv_sec = 0;
			Wait.tv_usec = 750000;
		}*/
		Blocking = 0;
	}
	
	SuperWait = 0;

	if ((Res == -1) || (Res == 0))
		return (0);
	return (1);
}

int		TSENDPACKETTCP(CConsoleLogger ThreadConsole, SOCKET Socket, Host CurHost, uchar *Packet, uint Size, ushort CustomPort, int *Connected)
{
	sockaddr_in		Sender;
	fd_set			m_TCPSockets;
	timeval			Wait = {1, 0};
	int				SelRes = 0;
	int				Res = -1;
	uchar			Buffer[0x1000];
	

	RecvBufferSz = 0xFFFF;
	ZeroMemory(RecvBuffer, 0xFFFF);

	if (SuperWait)
		Wait.tv_sec = (SuperWait == 1) ? 10 : 5;

	if (!(*Connected))
	{
		ZeroMemory((char *)&Sender, sizeof(Sender));
		Sender.sin_family = AF_INET;
		Sender.sin_port = htons((CustomPort == -1) ? CurHost.port : CustomPort);
		Sender.sin_addr.s_addr = inet_addr(CurHost.ip);

		if (connect(Socket, (struct sockaddr *)&Sender, sizeof(Sender)) < 0)
		{
			ThreadConsole.printf("Connection refused..\n");
			return (0);
		}
		*Connected = 1;
	}

	Res = send(Socket, (const char *)Packet, Size, 0);
	ThreadConsole.printf("%d Bytes sent..\n", Res);

	if ((Res == -1) || (Res == 0))
		return (0);

	if (NoWait)
	{
		NoWait = 0;
		return (1);
	}
	Res = -1;
	FD_ZERO(&m_TCPSockets);
	FD_SET(Socket, &m_TCPSockets);
		
	RecvBufferSz = 0;
	while ((SelRes = select(FD_SETSIZE, &m_TCPSockets, NULL, NULL, (Blocking) ? NULL : &Wait)))
	{	
		Res = recv(Socket, (char *)&(Buffer[0]), sizeof(Buffer), 0);
		if (Res == 0)
		{
			ThreadConsole.printf("Connection reset by peer !\n");
			return (0);
		}
		else if (Res == -1)
		{
			ThreadConsole.printf("Socket Error\n");
			return (0);
		}
		else
		{
			ThreadConsole.printf("%d Bytes in response..\n", Res);
			memcpy_s(RecvBuffer + RecvBufferSz, 0xFFFF - RecvBufferSz, Buffer, Res);
			RecvBufferSz += Res;
		}

		FD_ZERO(&m_TCPSockets);
		FD_SET(Socket, &m_TCPSockets);

		if (SuperWait)
		{
			if (SuperWait == 2)
				break;
			Wait.tv_sec = 1;
			Wait.tv_usec = 0;
		}
		/*else
		{
			Wait.tv_sec = 0;
			Wait.tv_usec = 750000;
		}*/
		Blocking = 0;
	}
	
	SuperWait = 0;

	if ((Res == -1) || (Res == 0))
		return (0);
	return (1);
}

int		SendPacketTCPEx(SOCKET Socket, Host CurHost, uchar *Packet, uint Size, ushort CustomPort, int *Connected)
{
	sockaddr_in		Sender;
	fd_set			m_TCPSockets;
	timeval			Wait = {0, 1000000};
	int				SelRes = 0;
	int				Res = -1;
	RecvDesc		*RecvD;

	while (!RecvDQueue.empty())
		RecvDQueue.pop();

	if (!(*Connected))
	{
		ZeroMemory((char *)&Sender, sizeof(Sender));
		Sender.sin_family = AF_INET;
		Sender.sin_port = htons((CustomPort == -1) ? CurHost.port : CustomPort);
		Sender.sin_addr.s_addr = inet_addr(CurHost.ip);

		if (connect(Socket, (struct sockaddr *)&Sender, sizeof(Sender)) < 0)
		{
			printf("Connection refused..\n");
			return (0);
		}
		*Connected = 1;
	}

	Res = send(Socket, (const char *)Packet, Size, 0);
	printf("%d Bytes sent..\n", Res);

	if ((Res == -1) || (Res == 0))
		return (0);

	Res = -1;
	FD_ZERO(&m_TCPSockets);
	FD_SET(Socket, &m_TCPSockets);
		
	while ((SelRes = select(FD_SETSIZE, &m_TCPSockets, NULL, NULL, &Wait)))
	{	
		RecvD = (RecvDesc *)malloc(sizeof(RecvDesc));
		Res = recv(Socket, (char *)&(RecvD->RecvBuf[0]), sizeof(RecvD->RecvBuf), 0);
		if (Res == 0)
		{
			printf("Connection reset by peer !\n");
			return (0);
		}
		else
		{
			printf("%d Bytes in response..\n", Res);
			RecvD->RecvSz = Res;
		}

		RecvDQueue.push(*RecvD);

		FD_ZERO(&m_TCPSockets);
		FD_SET(Socket, &m_TCPSockets);
	}
	
	if ((Res == -1) || (Res == 0))
		return (0);
	return (1);
}

void	Listen2SN(Host SN)
{
	fd_set			m_TCPSockets;
	int				SelRes = 0;
	int				Res = -1;
	uchar			Title[MAX_PATH] = {0};
	uchar			Buffer[0x1000] = {0};
	
	_snprintf_s((char *)Title, MAX_PATH, MAX_PATH, "FakeSkype - Logged User : %s (Waiting For Queries)..", GLoginD.User);
	SetConsoleTitle((LPCSTR)Title);

	SendACK(LastPID, SN.socket, SN, HTTPS_PORT, &(SN.Connected), &Keys);
	printf("Listennig To SuperNode..\n");
	RecvBufferSz = 0xFFFF;
	ZeroMemory(RecvBuffer, 0xFFFF);

	Res = -1;
	FD_ZERO(&m_TCPSockets);
	FD_SET(SN.socket, &m_TCPSockets);
		
	RecvBufferSz = 0;
	while ((SelRes = select(FD_SETSIZE, &m_TCPSockets, NULL, NULL, NULL)))
	{	
		Res = recv(SN.socket, (char *)&(Buffer[0]), sizeof(Buffer), 0);
		if (Res == 0)
		{
			printf("Connection reset by peer !\n");
			return ;
		}
		else if (Res == -1)
		{
			printf("Socket Error\n");
			return ;
		}
		else
		{
			printf("%d Bytes received from SN..\n", Res);
			
			CipherTCP(&(Keys.RecvStream), Buffer, Res);
			
			showmem(Buffer, Res);
			printf("\n\n");

			if (Res > 4)
				HandleQuery(SN, Buffer, Res);

			/*uchar		*Browser;
			SResponse	Response;
			
			Browser = Buffer;

			while (Res)
			{
				ZeroMemory(&Response, sizeof(Response));
				TCPResponseManager(&Browser, (uint *)&Res, &Response, 0);

				for (uint Idx = 0; Idx < Response.NbObj; Idx++)
				{
					DumpObj(Response.Objs[Idx]);
				}
			}*/
			
			//memcpy_s(RecvBuffer + RecvBufferSz, 0xFFFF - RecvBufferSz, Buffer, Res);
			//RecvBufferSz += Res;
		}

		ZeroMemory(Buffer, 0x1000);
		FD_ZERO(&m_TCPSockets);
		FD_SET(SN.socket, &m_TCPSockets);
	}
	
	if ((Res == -1) || (Res == 0))
		return ;
	return ;
}

void	SendACK(ushort PacketID, SOCKET Socket, Host CurHost, ushort CustomPort, int *Connected, TCPKeyPair *HKeys)
{
	uchar	Buffer[0x04] = {0};
	ushort	RPacketID = htons(PacketID);

	Buffer[0] = 0x07;
	Buffer[1] = 0x01;
	Buffer[2] = *(uchar *)&RPacketID;
	Buffer[3] = *((uchar *)&RPacketID + 1);

	printf("Sending ACK of packet 0x%x\n", PacketID);
	//showmem(Buffer, sizeof(Buffer));

	CipherTCP(&(HKeys->SendStream), Buffer, 3);
	CipherTCP(&(HKeys->SendStream), Buffer + 3, sizeof(Buffer) - 3);

	NoWait = 1;
	SendPacketTCP(Socket, CurHost, Buffer, sizeof(Buffer), HTTPS_PORT, Connected);

	printf("\n");
}

void	LocationBlob2Location(uchar	*Location, CLocation *ContactLocation, uint BlobSz)
{
	int				IdxUp, IdxDown;
	uchar			NodeID[8];
	struct in_addr	IP;

	IdxUp = 0;
	IdxDown = sizeof(ContactLocation->NodeID) - 1;

	ZeroMemory(NodeID, sizeof(NodeID));
	*(unsigned int *)NodeID = *(unsigned int *)(Location + 4);
	*(unsigned int *)(NodeID + 4) = *(unsigned int *)Location;

	while (IdxDown >= 0)
		ContactLocation->NodeID[IdxUp++] = NodeID[IdxDown--];
	Location += sizeof(ContactLocation->NodeID);

	ContactLocation->UnkN = *Location;
	Location += 1;

	IP.S_un.S_addr = *(unsigned long *)Location;
	ZeroMemory(ContactLocation->PVAddr.ip, MAX_IP_LEN + 1);
	strcpy_s(ContactLocation->PVAddr.ip, MAX_IP_LEN + 1, inet_ntoa(IP));
	Location += 4;
	ContactLocation->PVAddr.port = htons(*(unsigned short *)(Location));
	Location += 2;

	if (BlobSz == 0x15)
	{
		IP.S_un.S_addr = *(unsigned long *)Location;
		ZeroMemory(ContactLocation->SNAddr.ip, MAX_IP_LEN + 1);
		strcpy_s(ContactLocation->SNAddr.ip, MAX_IP_LEN + 1, inet_ntoa(IP));
		Location += 4;
		ContactLocation->SNAddr.port = htons(*(unsigned short *)(Location));
		Location += 2;
	}
}

void	DumpLocation(CLocation *Location)
{
	printf("0x%08x%08x-%d-%s:%d", *(uint *)Location->NodeID, *(uint *)(Location->NodeID + 4), Location->UnkN, Location->PVAddr.ip, Location->PVAddr.port);
	if (Location->SNAddr.port)
		printf("-%s:%d", Location->SNAddr.ip, Location->SNAddr.port);
	printf("\n");
}

void			DumpTCPPacketObjs(uchar *Datas, uint DSize)
{
	uchar		*Buffer;
	uint		Size, Idx;
	SResponse	Response;

	Buffer = Datas;
	Size = DSize;

	while (Size > 0)
	{
		Response.Objs = NULL;
		Response.NbObj = 0;
		TCPResponseManager(&Buffer, (uint *)&Size, &Response);
		for (Idx = 0; Idx < Response.NbObj; Idx++)
		{
			DumpObj(Response.Objs[Idx]);
		}
		printf("\n");
	}
}
