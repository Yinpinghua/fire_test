#ifndef ip_port_filter_h__
#define ip_port_filter_h__

#include <windows.h>
#include <fwpmu.h>
#include <string>
#include <vector>
#include <algorithm>
#include <functional>
#include <unordered_map>

enum class defense_type
{
	block = 0, //禁用
	permit = 1, //允许
};

enum class data_direction
{
	dir_out = 0, //数据包流出
	dir_in = 1,  //数据包流入
};

enum class filter_msg
{
	icmp_protocol =0,
	ip_protocol   =1,
	tcp_protocol  =2,
	udp_protocol  =3,
};

struct filter_info
{
	std::string source_ip; //源IP
	std::string dest_ip; //目的IP
	std::string source_port; //源端口
	std::string dest_port; //目的IP
	data_direction dir; //数据包的方向
	defense_type defens_type; //过滤动作
};

class ip_port_filter
{
	using Func = std::function<uint64_t(const filter_info&)>;
public:
	static ip_port_filter& instance() {
		static ip_port_filter ins;
		return ins;
	}

	~ip_port_filter();
	uint64_t filter(const int msg_id,const filter_info& info);
	//成功:true,失败:false
	bool delte_rule(const uint64_t rule_id);
	//情况所有规则
	bool clear_all_rule();
private:
	ip_port_filter();
	bool init();
	int inet4_pton(const char* cp, uint32_t& ap);
	void clear_res();
	void regedit_msg_func(int msg_id, const Func& func);
	//成功返回规则id,失败返回0 (tcp和UDP包括禁ping都启作用,不需要传入端口)
	uint64_t block_ip(const filter_info& info);
	//成功返回规则id,失败返回0 (端口视情况传入)
	uint64_t block_tcp(const filter_info& info);
	uint64_t block_udp(const filter_info& info);
	//成功返回规则id,失败返回0 (不需要传入端口)
	uint64_t block_icmp(const filter_info& info);
private:
	ip_port_filter(const ip_port_filter&) = delete;
	ip_port_filter& operator=(const ip_port_filter&) = delete;
	ip_port_filter(ip_port_filter&&) = delete;
	ip_port_filter& operator=(ip_port_filter&&) = delete;
private:
	bool init_falg_ = false;
	FWPM_SUBLAYER0    fwp_sub_layer_;
	HANDLE engine_ = nullptr;
	GUID sub_layer_guid_ = { 0 };
	std::unordered_map<int,Func>msgs_;
	std::vector<uint64_t>rules_;
};

#endif // ip_port_filter_h__
