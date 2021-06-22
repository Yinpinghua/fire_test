//#include<windows.h>  
//#include<dbghelp.h>  
//#pragma comment(lib,"dbghelp.lib")  
//// 创建dump文件  
//void createdumpfile(lpcwstr lpstrdumpfilepathname, exception_pointers* pexception)
//{
//	handle hdumpfile = createfile(lpstrdumpfilepathname, generic_write, 0, null, create_always, file_attribute_normal, null);
//	// dump信息  
//	minidump_exception_information dumpinfo;
//	dumpinfo.exceptionpointers = pexception;
//	dumpinfo.threadid = getcurrentthreadid();
//	dumpinfo.clientpointers = true;
//	// 写入dump文件内容  
//	minidumpwritedump(getcurrentprocess(), getcurrentprocessid(), hdumpfile, minidumpnormal, &dumpinfo, null, null);
//	closehandle(hdumpfile);
//}
//// 处理unhandled exception的回调函数  
//long applicationcrashhandler(exception_pointers* pexception)
//{
//	createdumpfile(l"test.dmp", pexception);
//	return exception_execute_handler;
//}
//
//void fun(int* p)
//{
//	p[0] = 0;
//}
//int main(int argc, char* argv[])
//{
//	//注册异常处理函数  
//	setunhandledexceptionfilter((lptop_level_exception_filter)applicationcrashhandler);
//	fun(nullptr);
//	return 0;
//}

#include "ip_port_filter.h"
//#include "app_socket.h"
#include <iostream>

int main()
{
	//http_client client;
	//client.connect("w.yoyoyoyoo.com", "8111");
	//client.request("/api/web/node/server/authorize/new",request_mod::get);
	//int result = client.request_result();
	//std::string str1 = client.reason();
	//std::string str = client.request_data();
	//std::cout << str << std::endl;
	filter_info info;
	info.source_ip = "192.168.5.83";
	info.dest_ip = "";
	info.dir = data_direction::dir_in;
	info.defens_type = defense_type::block;
	uint64_t rule_id = ip_port_filter::instance().filter(static_cast<int>(filter_msg::ip_protocol), info);
	ip_port_filter::instance().delte_rule(rule_id);


	//filter_info info;
	//info.source_ip = "192.168.5.83";
	//info.dest_ip = "192.168.5.212";
	//info.dest_port = "10808";
	//info.dir = data_direction::dir_in;
	//info.defens_type = defense_type::block;
	//uint64_t rule_id = ip_port_filter::instance().filter(static_cast<int>(filter_msg::tcp_protocol), info);
	//ip_port_filter::instance().delte_rule(rule_id);


	//filter_info info;
	//info.source_ip = "192.168.5.212";
	//info.dest_ip = "192.168.5.212";
	//info.dest_port = "4444";
	//info.dir = data_direction::dir_in;
	//info.defens_type = defense_type::block;
	//uint64_t rule_id = ip_port_filter::instance().filter(static_cast<int>(filter_msg::udp_protocol), info);
	//ip_port_filter::instance().delte_rule(rule_id);

	//暂时不知道怎么测试 
	//filter_info info;
	//info.source_ip = "192.168.5.83";
	//info.dest_ip = "192.168.5.212";
	//info.dir = data_direction::dir_in;
	//info.defens_type = defense_type::block;
	//uint64_t rule_id = ip_port_filter::instance().filter(static_cast<int>(filter_msg::icmp_protocol), info);
	//ip_port_filter::instance().delte_rule(rule_id);

	return 0;
}
