#include "app_socket.h"

#ifdef _DEBUG
#pragma comment(lib, "crypt32")
#pragma comment(lib, "libssl64MTd.lib")
#pragma comment(lib, "libcrypto64MTd.lib")
#else
#pragma comment(lib, "crypt32")
#pragma comment(lib, "libssl64MT.lib")
#pragma comment(lib, "libcrypto64MT.lib")
#endif

template class app_socket<Http>;
template class app_socket<Https>;

template<typename T>
app_socket<T>::app_socket()
	:resolver_(ioc_)
	,ctx_(boost::asio::ssl::context::tlsv12_client)
	,http_stream_(ioc_)
	,https_stream_(ioc_,ctx_)
{

}

template<typename T>
app_socket<T>::~app_socket()
{
	close();
}

template<typename T>
bool app_socket<T>::connect(const std::string& host, const std::string& port)
{
	if constexpr (is_http) {
		return http_connect(host,port);
	}else {
		return https_connect(host, port);
	}
}

template<typename T>
bool app_socket<T>::request(const std::string& target, request_mod mod)
{
	http::request<http::string_body> req;
	if (mod == request_mod::get) {
		req.method(http::verb::get);
	}else if (mod == request_mod::post) {
		req.method(http::verb::post);
	}else {
		return false;
	}

	req.target(target);
	req.version(11);
	req.set(http::field::host, host_);
	boost::system::error_code ec;
	http::write(socket(), req, ec);
	if (ec) {
		return false;
	}

	res_.emplace();
	boost::beast::flat_buffer buffer;
	http::read(socket(), buffer, *res_, ec);
	if (ec) {
		return false;
	}

	return true;
}

template<typename T>
int app_socket<T>::request_result()
{
	return res_->base().result_int();
}

template<typename T>
std::string app_socket<T>::request_data()
{
	std::string body = res_->body();
	return std::move(body);
}

template<typename T>
void app_socket<T>::close()
{
	if constexpr (is_http) {
		close_http_socket();
	}else {
		close_https_socket();
	}
}

template<typename T>
auto& app_socket<T>::socket()
{
	if constexpr (is_http) {
		return http_stream_;
	}else {
		return https_stream_;
	}
}

template<typename T>
bool app_socket<T>::http_connect(const std::string& host, const std::string& port)
{
	boost::system::error_code ec;
	const auto  results = resolver_.resolve(host, port, ec);
	if (ec) {
		return false;
	}

	boost::beast::get_lowest_layer(http_stream_).expires_after(std::chrono::seconds(3));
	boost::beast::get_lowest_layer(http_stream_).connect(results, ec);
	if (ec) {
		return false;
	}

	boost::beast::get_lowest_layer(http_stream_).expires_never();

	host_ = host;
	return true;
}

template<typename T>
bool app_socket<T>::https_connect(const std::string& host, const std::string& port)
{
	boost::system::error_code ec;
	const auto  results = resolver_.resolve(host, port, ec);
	if (ec) {
		return false;
	}

	boost::beast::get_lowest_layer(https_stream_).expires_after(std::chrono::seconds(3));
	boost::beast::get_lowest_layer(https_stream_).connect(results, ec);
	if (ec) {
		return false;
	}

	boost::beast::get_lowest_layer(https_stream_).expires_never();
	boost::beast::get_lowest_layer(https_stream_).expires_after(std::chrono::seconds(10));
	https_stream_.handshake(boost::asio::ssl::stream_base::client, ec);
	if (ec) {
		return false;
	}

	boost::beast::get_lowest_layer(https_stream_).expires_never();
	host_ = host;
	return true;
}

template<typename T>
void app_socket<T>::close_http_socket()
{
	using tcp = boost::asio::ip::tcp;

	boost::system::error_code ec;
	http_stream_.socket().shutdown(tcp::socket::shutdown_both, ec);
}

template<typename T>
void app_socket<T>::close_https_socket()
{
	boost::system::error_code ec;
	https_stream_.shutdown(ec);
}

template<typename T>
std::string app_socket<T>::reason()
{
	return res_->base().reason().to_string();
}
