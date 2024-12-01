#include<WinSock2.h>
#include<iostream>
#include <WS2tcpip.h>
#include <Iphlpapi.h>
#include<thread>
#include<mutex>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

#include"Connect_msg.h"

using namespace std;
#pragma comment(lib,"ws2_32.lib")     //链接库文件
#pragma comment(lib,"iphlpapi.lib")     //链接库文件

//字节数组转换为十六进制字符串
std::string bytesToHexString(const unsigned char* bytes, size_t length) {
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (size_t i = 0; i < length; ++i) {
		ss << std::setw(2) << static_cast<unsigned>(bytes[i]);
		if (i < length - 1) {
			ss << '-';
		}
	}
	return ss.str();
}
string auto_ip()
{
	WSADATA wsaData;
	int iResult;

	// 初始化Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		std::cerr << "WSAStartup failed: " << iResult << std::endl;
		return NULL;
	}

	// 获取主机名
	char hostname[256];
	iResult = gethostname(hostname, sizeof(hostname));
	if (iResult != 0) {
		std::cerr << "gethostname failed: " << iResult << std::endl;
		WSACleanup();
		return NULL;
	}

	// 获取主机信息
	struct addrinfo hints, * res;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; // IPv4
	hints.ai_socktype = SOCK_STREAM;

	iResult = getaddrinfo(hostname, NULL, &hints, &res);
	if (iResult != 0) {
		std::cerr << "getaddrinfo failed: " << iResult << std::endl;
		WSACleanup();
		return NULL;
	}

	// 输出IPv4地址
	struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
	char ipstr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, INET_ADDRSTRLEN);
	std::cout << "IPv4 Address: " << ipstr << std::endl;

	// 释放内存
	freeaddrinfo(res);
	WSACleanup();
	return ipstr;
}
string auto_outLet()
{
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	unsigned long stSize = sizeof(IP_ADAPTER_INFO);
	int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);

	if (ERROR_BUFFER_OVERFLOW == nRel) {
		delete pIpAdapterInfo;
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	}

	if (ERROR_SUCCESS == nRel) {
		while (pIpAdapterInfo) {
			std::cout << "网卡名称: " << pIpAdapterInfo->AdapterName << std::endl;
			std::cout << "网卡描述: " << pIpAdapterInfo->Description << std::endl;
			if(pIpAdapterInfo->CurrentIpAddress != NULL) std::cout << "ipv4地址: " << pIpAdapterInfo->CurrentIpAddress->IpAddress.String << std::endl;
			//printf("ipv4地址: %s\n", pIpAdapterInfo->CurrentIpAddress->IpAddress.String);
			std::cout << "物理地址: " << bytesToHexString(pIpAdapterInfo->Address, pIpAdapterInfo->AddressLength) << std::endl;
			std::cout << "网卡类型: ";
			switch (pIpAdapterInfo->Type) {
			case MIB_IF_TYPE_OTHER:
				std::cout << "OTHER" << std::endl;
				break;
			case MIB_IF_TYPE_ETHERNET:
				std::cout << "ETHERNET" << std::endl;
				break;
			case MIB_IF_TYPE_TOKENRING:
				std::cout << "TOKENRING" << std::endl;
				break;
			case MIB_IF_TYPE_FDDI:
				std::cout << "FDDI" << std::endl;
				break;
			case MIB_IF_TYPE_PPP:
				std::cout << "PPP" << std::endl;
				break;
			case MIB_IF_TYPE_LOOPBACK:
				std::cout << "LOOPBACK" << std::endl;
				break;
			}
			pIpAdapterInfo = pIpAdapterInfo->Next;
		}
	}

	if (pIpAdapterInfo) {
		delete pIpAdapterInfo;
	}
	return "fa";
}
string auto_wifi()
{
	string ipv4 = "000.000.00.00";
	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	ULONG outBufLen = sizeof(IP_ADAPTER_ADDRESSES);
	int result = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen);
	if (result == ERROR_BUFFER_OVERFLOW) {
		pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
		result = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen);
	}
	if (result == ERROR_SUCCESS) {
		PIP_ADAPTER_ADDRESSES pAdapter = pAddresses;
		while (pAdapter) {
			if (pAdapter->IfType == IF_TYPE_IEEE80211) { // 检查是否为无线适配器
				PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress;
				while (pUnicast) {
					if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) { // 检查是否为IPv4地址
						struct sockaddr_in* pAddr = (struct sockaddr_in*)pUnicast->Address.lpSockaddr;
						printf("无线适配器IPv4地址: %s\n", inet_ntoa(pAddr->sin_addr));
						ipv4 = inet_ntoa(pAddr->sin_addr);
					}
					pUnicast = pUnicast->Next;
				}
			}
			pAdapter = pAdapter->Next;
		}
	}
	free(pAddresses);

	return ipv4;
}

Connect_msg* connect_msg = NULL;
std::mutex mux;
std::unique_lock<std::mutex> loc(mux);
bool is_used = true;
int index = 0;//当前为第几个连接的客户端

/// <summary>
///	开启线程进行通讯
/// </summary>
/// <param name="soc"></param>

//记录连接断开的id
vector<int> snap_id;
//根据关键字查找前缀
bool findKey(std::string key, std::string buf_rec, std::string &msg)
{
	std::stringstream f(buf_rec);
	std::string sg;
	std::getline(f, sg);
	f >> sg;
	if (sg == key)
	{
		f >> sg;
		msg = sg;
		return true;
	}
	return false;
}
void ServerCom(SOCKET& soc, int d) {
	char buf_rec[1024];
	char buf_send[1024];
	std::string msg;
	int id = d;
	Connect_msg* con = NULL;
	std::cout << "开始连接：" << id << std::endl;

	while (is_used) {
		int res = recv(soc, buf_rec, sizeof(buf_rec), 0);
		if (res > 0)
		{
			if (buf_rec[0] != '\0')
			{
				cout << buf_rec << endl;
			}
			std::stringstream f(buf_rec);
			std::string sg;
			if(con == NULL)
			{
				
				f >> sg;
				if (sg == "connect_id:")
				{
					f >> sg;
					if (stoi(sg) == id) cout << id << "不允许与自己连接，请重试" << endl;
					else con = connect_msg->connect(id, stoi(sg));
					cout << sg << endl;
				}
				else
				{
					con = connect_msg->get(id);
				}
			}
			else
			{
				if (buf_rec[0] != '\0')
				{
					f >> sg;
					con->send(id, buf_rec);
				}
				if (con->recv(id) != "\0")
				{
					send(soc, con->recv(id).c_str(), sizeof(con->recv(id)), 0);//会出现空格以后都不见的BUG：sizeof(con->recv(id).c_str())
					cout << con->recv(id) << endl;
					con->del_msg(id);
				}
			}
		}
		else {
			std::cout << "已断开连接：" << id << std::endl;
			snap_id.push_back(id);
			if (con != NULL) delete(con);
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
			//index--;
			return;
		}
	}
}
//创建 socket 对象

int main(int argc, char* argv[]) 
{
	connect_msg = new Connect_msg;

	//① 初始化动态链接库 ws2_32.dll，分配资源
	WORD wVersionRequested = MAKEWORD(2, 2);//指定支持的 windows套接字规范的版本
	WSADATA wsadata;
	int init_res = WSAStartup(wVersionRequested, &wsadata);
	if (init_res != 0)
	{
		std::cout << "WSA Start Failed" << std::endl;
		return -1;
	}
	else {
		std::cout << "WSA Start success" << std::endl;
	}

	//②创建 socket 服务端
	SOCKET SocketServer;//声明一个 Socket 套接字对象
	constexpr int max_listen = 20;//设置最大连接数
	SOCKET socket_client[max_listen];//创建一个客户端组
	std::thread server_th[max_listen];
	
	SocketServer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (SocketServer != INVALID_SOCKET)//判断是否创建成功
	{
		//③绑定对应地址信息
		//设置地址端口号机器地址族
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;//一般与使用 socket() 函数创建 socket 对象时使用的地址族一样
		addr.sin_port = htons(80);//设置端口号
		inet_pton(AF_INET, auto_wifi().c_str(), &(addr.sin_addr));  //本地连接2的地址：192.168.137.1 或 hnkd的地址：192.168.84.96
		int addr_len = sizeof(addr);//地址信息的长度
		int res = bind(SocketServer, (sockaddr*)&addr, addr_len);
		if (res == 0)//返回 0 则代表绑定成功
		{
			std::cout << "bind success" << std::endl;
			//④将套接字设置成被动监听状态，并且为其指定可访问的服务端个数
			listen(SocketServer, max_listen);
			while (true) {
				//创建一个线程
				sockaddr_in addr_client;
				int addr_client_len = sizeof(addr_client);
				//⑤ 使用 accept 等待连接客户端， addr_client 获取客户端 ip,端口
				//这里可以优化下，使用多线程，在实际情况下避免堵塞
				SOCKET socketClient = accept(SocketServer, (sockaddr*)&addr_client, &addr_client_len);
				if (index < max_listen && socketClient != INVALID_SOCKET)//判断接收是否正确，而且没超出最大个数
				{
					int h_id;
					if(!snap_id.empty())
					{
						h_id = snap_id[snap_id.size()-1];
					}
					else
					{
						h_id = index++;
					}
					if (server_th[h_id].joinable()) {
						server_th[h_id].join();
					}
					//发送消息回去，通知一下已经连接成功
					socket_client[h_id] = std::move(socketClient);//没有问题，且能连接成功将其传给数组
					//char buf[] = "service: connect success and you're sb!";
					char buf_send[100];
					string msg = "id: " + to_string(h_id);
					int send_len = sizeof(msg.c_str());
					memcpy(buf_send, msg.c_str(), sizeof(buf_send)); //不可缺少，否则乱码
					send(socket_client[h_id], buf_send, sizeof(buf_send), 0);
					std::cout << "accept" << std::endl;
					//开启一个线程
					server_th[h_id] = std::thread(ServerCom, std::ref(socket_client[h_id]), h_id);
				}
			}
		}
		else {
			std::cout << "bind Failed" << std::endl;
		}
	}
	else {
		std::cout << "socket create Failed" << std::endl;
	}

	loc.lock();
	is_used = false;//关闭线程使用
	loc.unlock();
	for (size_t i = 0; i < index; i++)
	{
		if (server_th[i].joinable())
		{
			server_th[i].join();
		}
	}

	//当不在使用时，关闭 socket 服务端和释放动态链接库 ws2-32.dll 分配的资源
	closesocket(SocketServer);
	WSACleanup();//释放动态链接库 ws2_32.dll 初始化时多分配的空间
	return 0;
}
