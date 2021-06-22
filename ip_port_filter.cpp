#include "ip_port_filter.h"
#define MEM_FN1(func,class_type,ptr) std::bind(&class_type::func,ptr,std::placeholders::_1)

wchar_t filter_display_name[] = { L"filter display name PFirewall" };

#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Ws2_32.lib")


ip_port_filter::~ip_port_filter()
{
	clear_all_rule();
	clear_res();
}

uint64_t ip_port_filter::filter(const int msg_id,const filter_info& info)
{
	auto iter_find = msgs_.find(msg_id);
	if (iter_find == msgs_.end()){
		return 0;
	}

	return iter_find->second(info);
}

uint64_t ip_port_filter::block_ip(const filter_info& info)
{
	if (!init_falg_) {
		init_falg_ = init();
	}

	if (!init_falg_){
		return 0;
	}

	if (info.dest_ip.empty() && info.source_ip.empty()){
		return 0;
	}

	FWPM_FILTER0            fwp_filter;
	FWPM_FILTER_CONDITION0  fwp_conditions[4] = { 0 };
	RtlZeroMemory(&fwp_filter, sizeof(FWPM_FILTER0));
	int index = 0;
	fwp_filter.subLayerKey = fwp_sub_layer_.subLayerKey;
	(info.dir == data_direction::dir_in) ? (fwp_filter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4) :
		(fwp_filter.layerKey = FWPM_LAYER_OUTBOUND_IPPACKET_V4);

	(info.defens_type == defense_type::block) ? (fwp_filter.action.type = FWP_ACTION_BLOCK) :
		(fwp_filter.action.type = FWP_ACTION_PERMIT);

	fwp_filter.weight.type = FWP_EMPTY;
	fwp_filter.displayData.name = filter_display_name;

	if (!info.dest_ip.empty()){
		(info.dir == data_direction::dir_in) ? (fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS) : 
			(fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS);

		fwp_conditions[index].matchType = FWP_MATCH_EQUAL;
		fwp_conditions[index].conditionValue.type = FWP_UINT32;
		uint32_t ip_value = 0;
		inet4_pton(info.dest_ip.c_str(), ip_value);
		fwp_conditions[index].conditionValue.uint32 = ip_value;
		++index;
	}

	if (!info.source_ip.empty()){
		(info.dir == data_direction::dir_in) ? (fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS) : 
			(fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS);

		fwp_conditions[index].matchType = FWP_MATCH_EQUAL;
		fwp_conditions[index].conditionValue.type = FWP_UINT32;
		uint32_t ip_value = 0;
		inet4_pton(info.source_ip.c_str(), ip_value);
		fwp_conditions[index].conditionValue.uint32 = ip_value;
		++index;
	}

	fwp_filter.numFilterConditions = index;
	fwp_filter.filterCondition = fwp_conditions;
	unsigned long result = ERROR_SUCCESS;
	result = FwpmTransactionBegin0(engine_, NULL);
	if (result != ERROR_SUCCESS){
		return 0;
	}

	uint64_t rule_id =0;
	result = FwpmFilterAdd0(engine_, &fwp_filter, NULL, &rule_id);
	if (result != ERROR_SUCCESS){
		return 0;
	}

	result = FwpmTransactionCommit0(engine_);
	if (result != ERROR_SUCCESS){
		FwpmTransactionAbort0(engine_);
		return 0;
	}

	rules_.emplace_back(rule_id);
	return rule_id;
}

uint64_t ip_port_filter::block_tcp(const filter_info& info)
{
	if (!init_falg_) {
		init_falg_ = init();
	}

	if (!init_falg_) {
		return 0;
	}

	FWPM_FILTER0            fwp_filter;
	FWPM_FILTER_CONDITION0  fwp_conditions[4] = { 0 };
	RtlZeroMemory(&fwp_filter, sizeof(FWPM_FILTER0));
	int index = 0;
	fwp_filter.subLayerKey = fwp_sub_layer_.subLayerKey;
	(info.dir == data_direction::dir_in) ? (fwp_filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4) :
		(fwp_filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4);

	(info.defens_type == defense_type::block) ? (fwp_filter.action.type = FWP_ACTION_BLOCK) :
		(fwp_filter.action.type = FWP_ACTION_PERMIT);

	fwp_filter.weight.type = FWP_EMPTY;
	fwp_filter.displayData.name = filter_display_name;

	if (!info.dest_ip.empty()) {
		(info.dir == data_direction::dir_in) ? (fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS) :
			(fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS);

		fwp_conditions[index].matchType = FWP_MATCH_EQUAL;
		fwp_conditions[index].conditionValue.type = FWP_UINT32;
		uint32_t ip_value = 0;
		inet4_pton(info.dest_ip.c_str(), ip_value);
		fwp_conditions[index].conditionValue.uint32 = ip_value;
		++index;
	}

	if (!info.source_ip.empty()) {
		(info.dir == data_direction::dir_in) ? (fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS) :
			(fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS);

		fwp_conditions[index].matchType = FWP_MATCH_EQUAL;
		fwp_conditions[index].conditionValue.type = FWP_UINT32;
		uint32_t ip_value = 0;
		inet4_pton(info.source_ip.c_str(), ip_value);
		fwp_conditions[index].conditionValue.uint32 = ip_value;
		++index;
	}

	if (!info.dest_port.empty()) {
		(info.dir == data_direction::dir_in) ? (fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT) :
			(fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT);
		fwp_conditions[index].matchType = FWP_MATCH_EQUAL;
		fwp_conditions[index].conditionValue.type = FWP_UINT16;
		fwp_conditions[index].conditionValue.uint16 = std::atoi(info.dest_port.c_str());
		++index;
	}

	if (!info.source_port.empty()) {
		(info.dir == data_direction::dir_in) ? (fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT) :
			(fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT);
		fwp_conditions[index].matchType = FWP_MATCH_EQUAL;
		fwp_conditions[index].conditionValue.type = FWP_UINT16;
		fwp_conditions[index].conditionValue.uint32 = std::atoi(info.source_port.c_str());
		++index;
	}

	fwp_filter.numFilterConditions = index;
	fwp_filter.filterCondition = fwp_conditions;
	unsigned long result = ERROR_SUCCESS;
	result = FwpmTransactionBegin0(engine_, NULL);
	if (result != ERROR_SUCCESS) {
		return 0;
	}

	uint64_t rule_id = 0;
	result = FwpmFilterAdd0(engine_, &fwp_filter, NULL, &rule_id);
	if (result != ERROR_SUCCESS) {
		return 0;
	}

	result = FwpmTransactionCommit0(engine_);
	if (result != ERROR_SUCCESS) {
		FwpmTransactionAbort0(engine_);
		return 0;
	}

	rules_.emplace_back(rule_id);
	return rule_id;
}

uint64_t ip_port_filter::block_udp(const filter_info& info)
{
	if (!init_falg_) {
		init_falg_ = init();
	}

	if (!init_falg_) {
		return 0;
	}

	FWPM_FILTER0            fwp_filter;
	FWPM_FILTER_CONDITION0  fwp_conditions[4] = { 0 };
	RtlZeroMemory(&fwp_filter, sizeof(FWPM_FILTER0));
	int index = 0;
	fwp_filter.subLayerKey = fwp_sub_layer_.subLayerKey;
	fwp_filter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V4;

	(info.defens_type == defense_type::block) ? (fwp_filter.action.type = FWP_ACTION_BLOCK) :
		(fwp_filter.action.type = FWP_ACTION_PERMIT);

	fwp_filter.weight.type = FWP_EMPTY;
	fwp_filter.displayData.name = filter_display_name;

	if (!info.dest_ip.empty()) {
		(info.dir == data_direction::dir_in) ? (fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS) :
			(fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS);

		fwp_conditions[index].matchType = FWP_MATCH_EQUAL;
		fwp_conditions[index].conditionValue.type = FWP_UINT32;
		uint32_t ip_value = 0;
		inet4_pton(info.dest_ip.c_str(), ip_value);
		fwp_conditions[index].conditionValue.uint32 = ip_value;
		++index;
	}

	if (!info.source_ip.empty()) {
		(info.dir == data_direction::dir_in) ? (fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS) :
			(fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS);

		fwp_conditions[index].matchType = FWP_MATCH_EQUAL;
		fwp_conditions[index].conditionValue.type = FWP_UINT32;
		uint32_t ip_value = 0;
		inet4_pton(info.source_ip.c_str(), ip_value);
		fwp_conditions[index].conditionValue.uint32 = ip_value;
		++index;
	}

	if (!info.dest_port.empty()) {
		(info.dir == data_direction::dir_in) ? (fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT) :
			(fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT);
		fwp_conditions[index].matchType = FWP_MATCH_EQUAL;
		fwp_conditions[index].conditionValue.type = FWP_UINT16;
		fwp_conditions[index].conditionValue.uint16 = std::atoi(info.dest_port.c_str());
		++index;
	}

	if (!info.source_port.empty()) {
		(info.dir == data_direction::dir_in) ? (fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT) :
			(fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT);
		fwp_conditions[index].matchType = FWP_MATCH_EQUAL;
		fwp_conditions[index].conditionValue.type = FWP_UINT16;
		fwp_conditions[index].conditionValue.uint32 = std::atoi(info.source_port.c_str());
		++index;
	}

	fwp_filter.numFilterConditions = index;
	fwp_filter.filterCondition = fwp_conditions;
	unsigned long result = ERROR_SUCCESS;
	result = FwpmTransactionBegin0(engine_, NULL);
	if (result != ERROR_SUCCESS) {
		return 0;
	}

	uint64_t rule_id = 0;
	result = FwpmFilterAdd0(engine_, &fwp_filter, NULL, &rule_id);
	if (result != ERROR_SUCCESS) {
		return 0;
	}

	result = FwpmTransactionCommit0(engine_);
	if (result != ERROR_SUCCESS) {
		FwpmTransactionAbort0(engine_);
		return 0;
	}

	rules_.emplace_back(rule_id);
	return rule_id;
}

uint64_t ip_port_filter::block_icmp(const filter_info& info)
{
	if (!init_falg_) {
		init_falg_ = init();
	}

	if (!init_falg_) {
		return 0;
	}

	if (info.dest_ip.empty() && info.source_ip.empty()) {
		return 0;
	}

	FWPM_FILTER0            fwp_filter;
	FWPM_FILTER_CONDITION0  fwp_conditions[4] = { 0 };
	RtlZeroMemory(&fwp_filter, sizeof(FWPM_FILTER0));
	int index = 0;
	fwp_filter.subLayerKey = fwp_sub_layer_.subLayerKey;

	(info.dir == data_direction::dir_in) ? (fwp_filter.layerKey = FWPM_LAYER_INBOUND_ICMP_ERROR_V4) :
		(fwp_filter.layerKey = FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4);

	(info.defens_type == defense_type::block) ? (fwp_filter.action.type = FWP_ACTION_BLOCK) :
		(fwp_filter.action.type = FWP_ACTION_PERMIT);

	fwp_filter.weight.type = FWP_EMPTY;
	fwp_filter.displayData.name = filter_display_name;

	if (!info.dest_ip.empty()) {
		(info.dir == data_direction::dir_in) ? (fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS) :
			(fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS);

		fwp_conditions[index].matchType = FWP_MATCH_EQUAL;
		fwp_conditions[index].conditionValue.type = FWP_UINT32;
		uint32_t ip_value = 0;
		inet4_pton(info.dest_ip.c_str(), ip_value);
		fwp_conditions[index].conditionValue.uint32 = ip_value;
		++index;
	}

	if (!info.source_ip.empty()) {
		(info.dir == data_direction::dir_in) ? (fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS) :
			(fwp_conditions[index].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS);

		fwp_conditions[index].matchType = FWP_MATCH_EQUAL;
		fwp_conditions[index].conditionValue.type = FWP_UINT32;
		uint32_t ip_value = 0;
		inet4_pton(info.source_ip.c_str(), ip_value);
		fwp_conditions[index].conditionValue.uint32 = ip_value;
		++index;
	}

	fwp_filter.numFilterConditions = index;
	fwp_filter.filterCondition = fwp_conditions;
	unsigned long result = ERROR_SUCCESS;
	result = FwpmTransactionBegin0(engine_, NULL);
	if (result != ERROR_SUCCESS) {
		return 0;
	}

	uint64_t rule_id = 0;
	result = FwpmFilterAdd0(engine_, &fwp_filter, NULL, &rule_id);
	if (result != ERROR_SUCCESS) {
		return 0;
	}

	result = FwpmTransactionCommit0(engine_);
	if (result != ERROR_SUCCESS) {
		FwpmTransactionAbort0(engine_);
		return 0;
	}

	rules_.emplace_back(rule_id);
	return rule_id;
}

ip_port_filter::ip_port_filter()
{
	regedit_msg_func(static_cast<int>(filter_msg::ip_protocol),
		MEM_FN1(block_ip,ip_port_filter,this));

	regedit_msg_func(static_cast<int>(filter_msg::tcp_protocol),
		MEM_FN1(block_tcp, ip_port_filter, this));

	regedit_msg_func(static_cast<int>(filter_msg::udp_protocol),
		MEM_FN1(block_udp, ip_port_filter, this));

	regedit_msg_func(static_cast<int>(filter_msg::icmp_protocol),
		MEM_FN1(block_icmp, ip_port_filter, this));
}

bool ip_port_filter::delte_rule(const uint64_t rule_id)
{
	auto iter_find = std::find_if(rules_.begin(), rules_.end(), 
		[rule_id](const uint64_t value) {return value == rule_id;});

	if ( iter_find == rules_.end()){
		return false;
	}

	unsigned long result = ERROR_SUCCESS;
	result = FwpmFilterDeleteById0(engine_, rule_id);
	if (result != ERROR_SUCCESS){
		FwpmEngineClose0(engine_);
		return false;
	}

	rules_.erase(iter_find);

	if (rules_.size() ==0){
		clear_res();
	}

	return true;
}

bool ip_port_filter::clear_all_rule()
{
	auto iter_beg = rules_.begin();
	for (;iter_beg != rules_.end();++iter_beg){
		unsigned long result = ERROR_SUCCESS;
		result = FwpmFilterDeleteById0(engine_,*iter_beg);
		if (result != ERROR_SUCCESS) {
			FwpmEngineClose0(engine_);
			break;
		}
	}

	clear_res();
	return true;
}

bool ip_port_filter::init()
{
	memset(&fwp_sub_layer_, 0, sizeof(fwp_sub_layer_));
	RPC_STATUS rpc_status = RPC_S_OK;
	rpc_status = UuidCreate(&fwp_sub_layer_.subLayerKey);
	if (rpc_status != RPC_S_OK){
		return false;
	}

	wchar_t sub_name[] = { L"MyFilterSublayer" };
	wchar_t description[] = { L"My filter sublayer" };
	fwp_sub_layer_.displayData.name = sub_name;
	fwp_sub_layer_.displayData.description = description;
	fwp_sub_layer_.flags = 0;
	fwp_sub_layer_.weight = 0x100;

	unsigned long result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine_);
	if (result != ERROR_SUCCESS){
		return false;
	}

	result = FwpmSubLayerAdd0(engine_, &fwp_sub_layer_, NULL);
	if (result != ERROR_SUCCESS){
		FwpmEngineClose0(engine_);
		return false;
	}

	sub_layer_guid_ = fwp_sub_layer_.subLayerKey;
	return true;
}

int ip_port_filter::inet4_pton(const char* cp, uint32_t& ap)
{
	uint32_t acc = 0;
	uint32_t  dots = 0;
	uint32_t  addr = 0;
	uint32_t index = 0;

	do {
		char cc = *cp;
		if (cc >= '0' && cc <= '9') {
			acc = acc * 10 + (cc - '0');
		}
		else if (cc == '.' || cc == '\0') {
			if (++dots > 3 && cc == '.') {
				return 0;
			}
			/* Fall through */

			if (acc > 255) {
				return 0;
			}

			//addr += (acc << (index * 8));//各平台统一
			//从左往右，低位放
			addr = addr << 8 | acc; // 这句是精华,每次将当前值左移八位加上后面的值
			++index;
			acc = 0;
		}
	} while (*cp++);

	// Normalize the address 
	if (dots < 3) {
		addr <<= 8 * (3 - dots);
	}

	ap = addr;
	return 1;
}

void ip_port_filter::clear_res()
{
	if (engine_ == nullptr){
		init_falg_ = false;
		return;
	}

	FwpmSubLayerDeleteByKey0(engine_,&sub_layer_guid_);
	init_falg_ = false;
	FwpmEngineClose0(engine_);
	engine_ = nullptr;
}

void ip_port_filter::regedit_msg_func(int msg_id, const Func& func)
{
	auto iter_find = msgs_.find(msg_id);
	if (iter_find != msgs_.end()) {
		return;
	}

	msgs_.emplace(msg_id, func);
}
