#ifndef http_socket_h__
#define http_socket_h__

#include <string>
#include <boost/asio.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

namespace http = boost::beast::http;

enum class request_mod
{
	get  = 0,
	post = 1,
};

struct Http  {};
struct Https {};

template<typename T>
class app_socket
{
public:
	app_socket();
	~app_socket();
	bool connect(const std::string& host, const std::string& port);
	bool request(const std::string& target, request_mod mod);
	int  request_result();
	std::string request_data();
	std::string reason();
private:
	void close();
	auto& socket();
	bool http_connect(const std::string& host, const std::string& port);
	bool https_connect(const std::string& host, const std::string& port);
	void close_http_socket();
	void close_https_socket();
private:
	static constexpr bool is_http = 
		std::is_same<T,Http>::value;
	std::string host_;
	boost::asio::io_context ioc_;
	boost::asio::ip::tcp::resolver resolver_;
	boost::asio::ssl::context ctx_;
	boost::beast::ssl_stream<boost::beast::tcp_stream> https_stream_;
	boost::beast::tcp_stream http_stream_;
	boost::optional<http::response<http::string_body>>res_;
};

using http_client  = app_socket<Http>;
using https_client = app_socket<Https>;
#endif // http_socket_h__
