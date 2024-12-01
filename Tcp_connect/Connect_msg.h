#pragma once
#include<vector>
#include<string>
using namespace std;

class Connect_msg
{
private:
	static vector<int> m_connect, b_connect;
	static vector<Connect_msg*> connect_msg_s;

	char buf_a[1024] = "\0";
	char buf_b[1024] = "\0";
	int a, b;
	Connect_msg(int aa, int bb) :a(aa), b(bb)
	{

	}
public:
	int id;
	Connect_msg()
	{

	}
	~Connect_msg()
	{
		if (connect_msg_s[id])
		{
			connect_msg_s.erase(connect_msg_s.begin() + id);
			m_connect.erase(m_connect.begin() + id);
			b_connect.erase(b_connect.begin() + id);
		}
	}

	Connect_msg* connect(int aa, int bb)
	{
		Connect_msg* msg;
		m_connect.push_back(aa);
		b_connect.push_back(bb);
		msg = new Connect_msg(aa,bb);
		msg->id = connect_msg_s.size();
		connect_msg_s.push_back(msg);
		return msg;
	}
	Connect_msg* get(int id)
	{
		for (int i = 0; i < connect_msg_s.size(); i++)
		{
			if (connect_msg_s[i]->a == id || connect_msg_s[i]->b == id)
			{
				return connect_msg_s[i];
			}
		}
		return NULL;
	}
	void send(int id, string msg)
	{
		if(id == a)	memcpy(buf_a, msg.c_str(), sizeof(buf_a));
		else if (id == b) memcpy(buf_b, msg.c_str(), sizeof(buf_b));
	}
	string recv(int id)
	{
		char limit[1024] = "\0";

		if (id == a)
		{
			memcpy(limit, buf_b, sizeof(limit));
			return limit;
		}
		else if (id == b)
		{
			memcpy(limit, buf_a, sizeof(limit));
			return limit;
		}
		return "\0";
	}
	void del_msg(int id)
	{
		if (id == a)
		{
			memcpy(buf_b, "\0", sizeof(buf_b));
		}
		else if (id == b)
		{
			memcpy(buf_a, "\0", sizeof(buf_a));
		}
	}
};

