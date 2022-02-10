
#include "httplib.h"
#include <limits>

#ifdef _WIN32
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

using socket_t = SOCKET;

#else
using socket_t = int;
#define INVALID_SOCKET (-1)
#endif

static std::atomic<socket_t> svr_sock_= INVALID_SOCKET; /* 改动：svr_sock 从类成员变量变成全局变量，尚未充分评估带来的负面影响 */

namespace httplib {

int close_socket(socket_t sock) {
#ifdef _WIN32
	return closesocket(sock);
#else
	return close(sock);
#endif
}

int select_read(socket_t sock, time_t sec, time_t usec) {
#ifdef CPPHTTPLIB_USE_POLL
	struct pollfd pfd_read;
	pfd_read.fd = sock;
	pfd_read.events = POLLIN;

	auto timeout = static_cast<int>(sec * 1000 + usec / 1000);

	return poll(&pfd_read, 1, timeout);
#else
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(sock, &fds);

	timeval tv;
	tv.tv_sec = static_cast<long>(sec);
	tv.tv_usec = static_cast<long>(usec);

	return select(static_cast<int>(sock + 1), &fds, nullptr, nullptr, &tv);
#endif
}

int select_write(socket_t sock, time_t sec, time_t usec) {
#ifdef CPPHTTPLIB_USE_POLL
	struct pollfd pfd_read;
	pfd_read.fd = sock;
	pfd_read.events = POLLOUT;

	auto timeout = static_cast<int>(sec * 1000 + usec / 1000);

	return poll(&pfd_read, 1, timeout);
#else
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(sock, &fds);

	timeval tv;
	tv.tv_sec = static_cast<long>(sec);
	tv.tv_usec = static_cast<long>(usec);

	return select(static_cast<int>(sock + 1), nullptr, &fds, nullptr, &tv);
#endif
}

bool wait_until_socket_is_ready(socket_t sock, time_t sec, time_t usec) {
#ifdef CPPHTTPLIB_USE_POLL
	struct pollfd pfd_read;
	pfd_read.fd = sock;
	pfd_read.events = POLLIN | POLLOUT;

	auto timeout = static_cast<int>(sec * 1000 + usec / 1000);

	if (poll(&pfd_read, 1, timeout) > 0 &&
		pfd_read.revents & (POLLIN | POLLOUT)) {
		int error = 0;
		socklen_t len = sizeof(error);
		return getsockopt(sock, SOL_SOCKET, SO_ERROR,
			reinterpret_cast<char *>(&error), &len) >= 0 &&
			!error;
	}
	return false;
#else
	fd_set fdsr;
	FD_ZERO(&fdsr);
	FD_SET(sock, &fdsr);

	auto fdsw = fdsr;
	auto fdse = fdsr;

	timeval tv;
	tv.tv_sec = static_cast<long>(sec);
	tv.tv_usec = static_cast<long>(usec);

	if (select(static_cast<int>(sock + 1), &fdsr, &fdsw, &fdse, &tv) > 0 &&
		(FD_ISSET(sock, &fdsr) || FD_ISSET(sock, &fdsw))) {
		int error = 0;
		socklen_t len = sizeof(error);
		return getsockopt(sock, SOL_SOCKET, SO_ERROR,
			reinterpret_cast<char *>(&error), &len) >= 0 &&
			!error;
	}
	return false;
#endif
}
class Stream {
public:
	virtual ~Stream() = default;

	virtual bool is_readable() const = 0;
	virtual bool is_writable() const = 0;

	virtual int read(char *ptr, size_t size) = 0;
	virtual int write(const char *ptr, size_t size) = 0;
	virtual std::string get_remote_addr() const = 0;

	template <typename... Args>
	int write_format(const char *fmt, const Args &... args);
	int write(const char *ptr);
	int write(const std::string &s);
};

class SocketStream : public Stream {
public:
	SocketStream(socket_t sock, time_t read_timeout_sec,
		time_t read_timeout_usec);
	~SocketStream() override;

	bool is_readable() const override;
	bool is_writable() const override;
	int read(char *ptr, size_t size) override;
	int write(const char *ptr, size_t size) override;
	std::string get_remote_addr() const override;

private:
	socket_t sock_;
	time_t read_timeout_sec_;
	time_t read_timeout_usec_;
};

class BufferStream : public Stream {
public:
	BufferStream() = default;
	~BufferStream() override = default;

	bool is_readable() const override;
	bool is_writable() const override;
	int read(char *ptr, size_t size) override;
	int write(const char *ptr, size_t size) override;
	std::string get_remote_addr() const override;

	const std::string &get_buffer() const;

private:
	std::string buffer;
	int position = 0;
};

template <typename T>
bool process_socket(bool is_client_request, socket_t sock,
	size_t keep_alive_max_count, time_t read_timeout_sec,
	time_t read_timeout_usec, T callback) {
	assert(keep_alive_max_count > 0);

	auto ret = false;

	if (keep_alive_max_count > 1) {
		auto count = keep_alive_max_count;
		while (count > 0 &&
			(is_client_request ||
				select_read(sock, CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND,
					CPPHTTPLIB_KEEPALIVE_TIMEOUT_USECOND) > 0)) {
			SocketStream strm(sock, read_timeout_sec, read_timeout_usec);
			auto last_connection = count == 1;
			auto connection_close = false;

			ret = callback(strm, last_connection, connection_close);
			if (!ret || connection_close) { break; }

			count--;
		}
	}
	else { // keep_alive_max_count  is 0 or 1
		SocketStream strm(sock, read_timeout_sec, read_timeout_usec);
		auto dummy_connection_close = false;
		ret = callback(strm, true, dummy_connection_close);
	}

	return ret;
}



int shutdown_socket(socket_t sock) {
#ifdef _WIN32
	return shutdown(sock, SD_BOTH);
#else
	return shutdown(sock, SHUT_RDWR);
#endif
}

template <typename Fn>
socket_t create_socket(const char *host, int port, Fn fn,
	int socket_flags = 0) {
#ifdef _WIN32
#define SO_SYNCHRONOUS_NONALERT 0x20
#define SO_OPENTYPE 0x7008

	int opt = SO_SYNCHRONOUS_NONALERT;
	setsockopt(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, (char *)&opt,
		sizeof(opt));
#endif

	// Get address info
	struct addrinfo hints;
	struct addrinfo *result;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = socket_flags;
	hints.ai_protocol = 0;

	auto service = std::to_string(port);

	if (getaddrinfo(host, service.c_str(), &hints, &result)) {
		return INVALID_SOCKET;
	}

	for (auto rp = result; rp; rp = rp->ai_next) {
		// Create a socket
#ifdef _WIN32
		auto sock = WSASocketW(rp->ai_family, rp->ai_socktype, rp->ai_protocol,
			nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
		/**
		 * Since the WSA_FLAG_NO_HANDLE_INHERIT is only supported on Windows 7 SP1
		 * and above the socket creation fails on older Windows Systems.
		 *
		 * Let's try to create a socket the old way in this case.
		 *
		 * Reference:
		 * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa
		 *
		 * WSA_FLAG_NO_HANDLE_INHERIT:
		 * This flag is supported on Windows 7 with SP1, Windows Server 2008 R2 with
		 * SP1, and later
		 *
		 */
		if (sock == INVALID_SOCKET) {
			sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		}
#else
		auto sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
#endif
		if (sock == INVALID_SOCKET) { continue; }

#ifndef _WIN32
		if (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1) { continue; }
#endif

		// Make 'reuse address' option available
		int yes = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&yes),
			sizeof(yes));
#ifdef SO_REUSEPORT
		setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<char *>(&yes),
			sizeof(yes));
#endif

		// bind or connect
		if (fn(sock, *rp)) {
			freeaddrinfo(result);
			return sock;
		}

		close_socket(sock);
	}

	freeaddrinfo(result);
	return INVALID_SOCKET;
}

void set_nonblocking(socket_t sock, bool nonblocking) {
#ifdef _WIN32
	auto flags = nonblocking ? 1UL : 0UL;
	ioctlsocket(sock, FIONBIO, &flags);
#else
	auto flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL,
		nonblocking ? (flags | O_NONBLOCK) : (flags & (~O_NONBLOCK)));
#endif
}

bool is_connection_error() {
#ifdef _WIN32
	return WSAGetLastError() != WSAEWOULDBLOCK;
#else
	return errno != EINPROGRESS;
#endif
}

bool bind_ip_address(socket_t sock, const char *host) {
	struct addrinfo hints;
	struct addrinfo *result;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;

	if (getaddrinfo(host, "0", &hints, &result)) { return false; }

	auto ret = false;
	for (auto rp = result; rp; rp = rp->ai_next) {
		const auto &ai = *rp;
		if (!::bind(sock, ai.ai_addr, static_cast<int>(ai.ai_addrlen))) {
			ret = true;
			break;
		}
	}

	freeaddrinfo(result);
	return ret;
}

std::string if2ip(const std::string &ifn) {
#ifndef _WIN32
	struct ifaddrs *ifap;
	getifaddrs(&ifap);
	for (auto ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr && ifn == ifa->ifa_name) {
			if (ifa->ifa_addr->sa_family == AF_INET) {
				auto sa = reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr);
				char buf[INET_ADDRSTRLEN];
				if (inet_ntop(AF_INET, &sa->sin_addr, buf, INET_ADDRSTRLEN)) {
					freeifaddrs(ifap);
					return std::string(buf, INET_ADDRSTRLEN);
				}
			}
		}
	}
	freeifaddrs(ifap);
#endif
	return std::string();
}





std::string file_extension(const std::string &path) {
	std::smatch m;
	static auto re = std::regex("\\.([a-zA-Z0-9]+)$");
	if (std::regex_search(path, m, re)) { return m[1].str(); }
	return std::string();
}

const char *
find_content_type(const std::string &path,
	const std::map<std::string, std::string> &user_data) {
	auto ext = file_extension(path);

	auto it = user_data.find(ext);
	if (it != user_data.end()) { return it->second.c_str(); }

	if (ext == "txt") {
		return "text/plain";
	}
	else if (ext == "html" || ext == "htm") {
		return "text/html";
	}
	else if (ext == "css") {
		return "text/css";
	}
	else if (ext == "jpeg" || ext == "jpg") {
		return "image/jpg";
	}
	else if (ext == "png") {
		return "image/png";
	}
	else if (ext == "gif") {
		return "image/gif";
	}
	else if (ext == "svg") {
		return "image/svg+xml";
	}
	else if (ext == "ico") {
		return "image/x-icon";
	}
	else if (ext == "json") {
		return "application/json";
	}
	else if (ext == "pdf") {
		return "application/pdf";
	}
	else if (ext == "js") {
		return "application/javascript";
	}
	else if (ext == "wasm") {
		return "application/wasm";
	}
	else if (ext == "xml") {
		return "application/xml";
	}
	else if (ext == "xhtml") {
		return "application/xhtml+xml";
	}
	return nullptr;
}

const char *status_message(int status) {
	switch (status) {
	case 100: return "Continue";
	case 200: return "OK";
	case 202: return "Accepted";
	case 204: return "No Content";
	case 206: return "Partial Content";
	case 301: return "Moved Permanently";
	case 302: return "Found";
	case 303: return "See Other";
	case 304: return "Not Modified";
	case 400: return "Bad Request";
	case 401: return "Unauthorized";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 413: return "Payload Too Large";
	case 414: return "Request-URI Too Long";
	case 415: return "Unsupported Media Type";
	case 416: return "Range Not Satisfiable";
	case 417: return "Expectation Failed";
	case 503: return "Service Unavailable";

	default:
	case 500: return "Internal Server Error";
	}
}

class stream_line_reader {
public:
	stream_line_reader(Stream &strm, char *fixed_buffer, size_t fixed_buffer_size)
		: strm_(strm), fixed_buffer_(fixed_buffer),
		fixed_buffer_size_(fixed_buffer_size) {}

	const char *ptr() const {
		if (glowable_buffer_.empty()) {
			return fixed_buffer_;
		}
		else {
			return glowable_buffer_.data();
		}
	}

	size_t size() const {
		if (glowable_buffer_.empty()) {
			return fixed_buffer_used_size_;
		}
		else {
			return glowable_buffer_.size();
		}
	}

	bool end_with_crlf() const {
		auto end = ptr() + size();
		return size() >= 2 && end[-2] == '\r' && end[-1] == '\n';
	}

	bool getline() {
		fixed_buffer_used_size_ = 0;
		glowable_buffer_.clear();

		for (size_t i = 0;; i++) {
			char byte;
			auto n = strm_.read(&byte, 1);

			if (n < 0) {
				return false;
			}
			else if (n == 0) {
				if (i == 0) {
					return false;
				}
				else {
					break;
				}
			}

			append(byte);

			if (byte == '\n') { break; }
		}

		return true;
	}

private:
	void append(char c) {
		if (fixed_buffer_used_size_ < fixed_buffer_size_ - 1) {
			fixed_buffer_[fixed_buffer_used_size_++] = c;
			fixed_buffer_[fixed_buffer_used_size_] = '\0';
		}
		else {
			if (glowable_buffer_.empty()) {
				assert(fixed_buffer_[fixed_buffer_used_size_] == '\0');
				glowable_buffer_.assign(fixed_buffer_, fixed_buffer_used_size_);
			}
			glowable_buffer_ += c;
		}
	}

	Stream &strm_;
	char *fixed_buffer_;
	const size_t fixed_buffer_size_;
	size_t fixed_buffer_used_size_ = 0;
	std::string glowable_buffer_;
};

bool read_headers(Stream &strm, Headers &headers) {
	const auto bufsiz = 2048;
	char buf[bufsiz];
	stream_line_reader line_reader(strm, buf, bufsiz);

	for (;;) {
		if (!line_reader.getline()) { return false; }

		// Check if the line ends with CRLF.
		if (line_reader.end_with_crlf()) {
			// Blank line indicates end of headers.
			if (line_reader.size() == 2) { break; }
		}
		else {
			continue; // Skip invalid line.
		}

		// Skip trailing spaces and tabs.
		auto end = line_reader.ptr() + line_reader.size() - 2;
		while (line_reader.ptr() < end && (end[-1] == ' ' || end[-1] == '\t')) {
			end--;
		}

		// Horizontal tab and ' ' are considered whitespace and are ignored when on
		// the left or right side of the header value:
		//  - https://stackoverflow.com/questions/50179659/
		//  - https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html
		static const std::regex re(R"((.+?):[\t ]*(.+))");

		std::cmatch m;
		if (std::regex_match(line_reader.ptr(), end, m, re)) {
			auto key = std::string(m[1]);
			auto val = std::string(m[2]);
			headers.emplace(key, val);
		}
	}

	return true;
}

bool read_content_with_length(Stream &strm, uint64_t len,
	Progress progress, ContentReceiver out) {
	char buf[CPPHTTPLIB_RECV_BUFSIZ];

	uint64_t r = 0;
	while (r < len) {
		auto read_len = static_cast<size_t>(len - r);
		auto n = strm.read(buf, std::min(read_len, CPPHTTPLIB_RECV_BUFSIZ));
		if (n <= 0) { return false; }

		if (!out(buf, n)) { return false; }

		r += n;

		if (progress) {
			if (!progress(r, len)) { return false; }
		}
	}

	return true;
}

void skip_content_with_length(Stream &strm, uint64_t len) {
	char buf[CPPHTTPLIB_RECV_BUFSIZ];
	uint64_t r = 0;
	while (r < len) {
		auto read_len = static_cast<size_t>(len - r);
		auto n = strm.read(buf, std::min(read_len, CPPHTTPLIB_RECV_BUFSIZ));
		if (n <= 0) { return; }
		r += n;
	}
}

bool read_content_without_length(Stream &strm, ContentReceiver out) {
	char buf[CPPHTTPLIB_RECV_BUFSIZ];
	for (;;) {
		auto n = strm.read(buf, CPPHTTPLIB_RECV_BUFSIZ);
		if (n < 0) {
			return false;
		}
		else if (n == 0) {
			return true;
		}
		if (!out(buf, n)) { return false; }
	}

	return true;
}

bool read_content_chunked(Stream &strm, ContentReceiver out) {
	const auto bufsiz = 16;
	char buf[bufsiz];

	stream_line_reader line_reader(strm, buf, bufsiz);

	if (!line_reader.getline()) { return false; }

	auto chunk_len = std::stoi(line_reader.ptr(), 0, 16);

	while (chunk_len > 0) {
		if (!read_content_with_length(strm, chunk_len, nullptr, out)) {
			return false;
		}

		if (!line_reader.getline()) { return false; }

		if (strcmp(line_reader.ptr(), "\r\n")) { break; }

		if (!line_reader.getline()) { return false; }

		chunk_len = std::stoi(line_reader.ptr(), 0, 16);
	}

	if (chunk_len == 0) {
		// Reader terminator after chunks
		if (!line_reader.getline() || strcmp(line_reader.ptr(), "\r\n"))
			return false;
	}

	return true;
}

std::string make_content_range_header_field(size_t offset, size_t length,
	size_t content_length) {
	std::string field = "bytes ";
	field += std::to_string(offset);
	field += "-";
	field += std::to_string(offset + length - 1);
	field += "/";
	field += std::to_string(content_length);
	return field;
}

template <typename SToken, typename CToken, typename Content>
bool process_multipart_ranges_data(const Request &req, Response &res,
	const std::string &boundary,
	const std::string &content_type,
	SToken stoken, CToken ctoken,
	Content content) {
	for (size_t i = 0; i < req.ranges.size(); i++) {
		ctoken("--");
		stoken(boundary);
		ctoken("\r\n");
		if (!content_type.empty()) {
			ctoken("Content-Type: ");
			stoken(content_type);
			ctoken("\r\n");
		}

		auto offsets = detail::get_range_offset_and_length(req, res.body.size(), i);
		auto offset = offsets.first;
		auto length = offsets.second;

		ctoken("Content-Range: ");
		stoken(make_content_range_header_field(offset, length, res.body.size()));
		ctoken("\r\n");
		ctoken("\r\n");
		if (!content(offset, length)) { return false; }
		ctoken("\r\n");
	}

	ctoken("--");
	stoken(boundary);
	ctoken("--\r\n");

	return true;
}
std::string make_multipart_ranges_data(const Request &req, Response &res,
	const std::string &boundary,
	const std::string &content_type) {
	std::string data;

	process_multipart_ranges_data(
		req, res, boundary, content_type,
		[&](const std::string &token) { data += token; },
		[&](const char *token) { data += token; },
		[&](size_t offset, size_t length) {
		data += res.body.substr(offset, length);
		return true;
	});

	return data;
}

size_t
get_multipart_ranges_data_length(const Request &req, Response &res,
	const std::string &boundary,
	const std::string &content_type) {
	size_t data_length = 0;

	process_multipart_ranges_data(
		req, res, boundary, content_type,
		[&](const std::string &token) { data_length += token.size(); },
		[&](const char *token) { data_length += strlen(token); },
		[&](size_t /*offset*/, size_t length) {
		data_length += length;
		return true;
	});

	return data_length;
}

ssize_t write_content(Stream &strm, ContentProvider content_provider,
	size_t offset, size_t length) {
	size_t begin_offset = offset;
	size_t end_offset = offset + length;
	while (offset < end_offset) {
		ssize_t written_length = 0;

		DataSink data_sink;
		data_sink.write = [&](const char *d, size_t l) {
			offset += l;
			written_length = strm.write(d, l);
		};
		data_sink.done = [&](void) { written_length = -1; };
		data_sink.is_writable = [&](void) { return strm.is_writable(); };

		content_provider(offset, end_offset - offset, data_sink);
		if (written_length < 0) { return written_length; }
	}
	return static_cast<ssize_t>(offset - begin_offset);
}

bool write_multipart_ranges_data(Stream &strm, const Request &req,
	Response &res,
	const std::string &boundary,
	const std::string &content_type) {
	return process_multipart_ranges_data(
		req, res, boundary, content_type,
		[&](const std::string &token) { strm.write(token); },
		[&](const char *token) { strm.write(token); },
		[&](size_t offset, size_t length) {
		return write_content(strm, res.content_provider, offset, length) >= 0;
	});
}

int Stream::write(const char *ptr) { return write(ptr, strlen(ptr)); }

int Stream::write(const std::string &s) {
	return write(s.data(), s.size());
}

template <typename... Args>
int Stream::write_format(const char *fmt, const Args &... args) {
	std::array<char, 2048> buf;

#if defined(_MSC_VER) && _MSC_VER < 1900
	auto n = _snprintf_s(buf, bufsiz, buf.size() - 1, fmt, args...);
#else
	auto n = snprintf(buf.data(), buf.size() - 1, fmt, args...);
#endif
	if (n <= 0) { return n; }

	if (n >= static_cast<int>(buf.size()) - 1) {
		std::vector<char> glowable_buf(buf.size());

		while (n >= static_cast<int>(glowable_buf.size() - 1)) {
			glowable_buf.resize(glowable_buf.size() * 2);
#if defined(_MSC_VER) && _MSC_VER < 1900
			n = _snprintf_s(&glowable_buf[0], glowable_buf.size(),
				glowable_buf.size() - 1, fmt, args...);
#else
			n = snprintf(&glowable_buf[0], glowable_buf.size() - 1, fmt, args...);
#endif
		}
		return write(&glowable_buf[0], n);
	}
	else {
		return write(buf.data(), n);
	}
}

namespace detail {

	std::pair<size_t, size_t>
		get_range_offset_and_length(const Request &req, size_t content_length,
			size_t index) {
		auto r = req.ranges[index];

		if (r.first == -1 && r.second == -1) {
			return std::make_pair(0, content_length);
		}

		if (r.first == -1) {
			r.first = content_length - r.second;
			r.second = content_length - 1;
		}

		if (r.second == -1) { r.second = content_length - 1; }

		return std::make_pair(r.first, r.second - r.first + 1);
	}

	std::pair<size_t, size_t>
		get_range_offset_and_length(const Request &req, const Response &res,
			size_t index) {
		auto r = req.ranges[index];

		if (r.second == -1) { r.second = res.content_length - 1; }

		return std::make_pair(r.first, r.second - r.first + 1);
	}
	
	std::string get_remote_addr(socket_t sock) {
		struct sockaddr_storage addr;
		socklen_t len = sizeof(addr);

		if (!getpeername(sock, reinterpret_cast<struct sockaddr *>(&addr), &len)) {
			std::array<char, NI_MAXHOST> ipstr{};

			if (!getnameinfo(reinterpret_cast<struct sockaddr *>(&addr), len,
				ipstr.data(), ipstr.size(), nullptr, 0, NI_NUMERICHOST)) {
				return ipstr.data();
			}
		}

		return std::string();
	}
}// namespace detail

//namespace detail {

	// Socket stream implementation
	SocketStream::SocketStream(socket_t sock, time_t read_timeout_sec,
		time_t read_timeout_usec)
		: sock_(sock), read_timeout_sec_(read_timeout_sec),
		read_timeout_usec_(read_timeout_usec) {}

	SocketStream::~SocketStream() {}

	bool SocketStream::is_readable() const {
		return select_read(sock_, read_timeout_sec_, read_timeout_usec_) > 0;
	}

	bool SocketStream::is_writable() const {
		return select_write(sock_, 0, 0) > 0;
	}

	int SocketStream::read(char *ptr, size_t size) {
		if (is_readable()) { return recv(sock_, ptr, static_cast<int>(size), 0); }
		return -1;
	}

	int SocketStream::write(const char *ptr, size_t size) {
		if (is_writable()) { return send(sock_, ptr, static_cast<int>(size), 0); }
		return -1;
	}

	std::string SocketStream::get_remote_addr() const {
		return detail::get_remote_addr(sock_);
	}

	// Buffer stream implementation
	bool BufferStream::is_readable() const { return true; }

	bool BufferStream::is_writable() const { return true; }

	int BufferStream::read(char *ptr, size_t size) {
#if defined(_MSC_VER) && _MSC_VER < 1900
		int len_read = static_cast<int>(buffer._Copy_s(ptr, size, size, position));
#else
		int len_read = static_cast<int>(buffer.copy(ptr, size, position));
#endif
		position += len_read;
		return len_read;
	}

	int BufferStream::write(const char *ptr, size_t size) {
		buffer.append(ptr, size);
		return static_cast<int>(size);
	}

	std::string BufferStream::get_remote_addr() const { return ""; }

	const std::string &BufferStream::get_buffer() const { return buffer; }

//} // namespace detail

// HTTP server implementation
Server::Server()
	: keep_alive_max_count_(CPPHTTPLIB_KEEPALIVE_MAX_COUNT),
	read_timeout_sec_(CPPHTTPLIB_READ_TIMEOUT_SECOND),
	read_timeout_usec_(CPPHTTPLIB_READ_TIMEOUT_USECOND),
	payload_max_length_(CPPHTTPLIB_PAYLOAD_MAX_LENGTH), is_running_(false)
	/*,svr_sock_(INVALID_SOCKET)*/ {
#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
	new_task_queue = [] { return new ThreadPool(CPPHTTPLIB_THREAD_POOL_COUNT); };
}

Server::~Server() {}

Server &Server::Get(const char *pattern, Handler handler) {
	get_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
	return *this;
}

Server &Server::Post(const char *pattern, Handler handler) {
	post_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
	return *this;
}

Server &Server::Post(const char *pattern,
	HandlerWithContentReader handler) {
	post_handlers_for_content_reader_.push_back(
		std::make_pair(std::regex(pattern), handler));
	return *this;
}

Server &Server::Put(const char *pattern, Handler handler) {
	put_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
	return *this;
}

Server &Server::Put(const char *pattern,
	HandlerWithContentReader handler) {
	put_handlers_for_content_reader_.push_back(
		std::make_pair(std::regex(pattern), handler));
	return *this;
}

Server &Server::Patch(const char *pattern, Handler handler) {
	patch_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
	return *this;
}

Server &Server::Patch(const char *pattern,
	HandlerWithContentReader handler) {
	patch_handlers_for_content_reader_.push_back(
		std::make_pair(std::regex(pattern), handler));
	return *this;
}

Server &Server::Delete(const char *pattern, Handler handler) {
	delete_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
	return *this;
}

Server &Server::Options(const char *pattern, Handler handler) {
	options_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
	return *this;
}

bool Server::set_base_dir(const char *dir, const char *mount_point) {
	return set_mount_point(mount_point, dir);
}

bool Server::set_mount_point(const char *mount_point, const char *dir) {
	if (detail::is_dir(dir)) {
		std::string mnt = mount_point ? mount_point : "/";
		if (!mnt.empty() && mnt[0] == '/') {
			base_dirs_.emplace_back(mnt, dir);
			return true;
		}
	}
	return false;
}

bool Server::remove_mount_point(const char *mount_point) {
	for (auto it = base_dirs_.begin(); it != base_dirs_.end(); ++it) {
		if (it->first == mount_point) {
			base_dirs_.erase(it);
			return true;
		}
	}
	return false;
}

void Server::set_file_extension_and_mimetype_mapping(const char *ext,
	const char *mime) {
	file_extension_and_mimetype_map_[ext] = mime;
}

void Server::set_file_request_handler(Handler handler) {
	file_request_handler_ = std::move(handler);
}

void Server::set_error_handler(Handler handler) {
	error_handler_ = std::move(handler);
}

void Server::set_logger(Logger logger) { logger_ = std::move(logger); }

void
Server::set_expect_100_continue_handler(Expect100ContinueHandler handler) {
	expect_100_continue_handler_ = std::move(handler);
}

void Server::set_keep_alive_max_count(size_t count) {
	keep_alive_max_count_ = count;
}

void Server::set_read_timeout(time_t sec, time_t usec) {
	read_timeout_sec_ = sec;
	read_timeout_usec_ = usec;
}

void Server::set_payload_max_length(size_t length) {
	payload_max_length_ = length;
}

bool Server::bind_to_port(const char *host, int port, int socket_flags) {
	if (bind_internal(host, port, socket_flags) < 0) return false;
	return true;
}
int Server::bind_to_any_port(const char *host, int socket_flags) {
	return bind_internal(host, 0, socket_flags);
}

bool Server::listen_after_bind() { return listen_internal(); }

bool Server::listen(const char *host, int port, int socket_flags) {
	return bind_to_port(host, port, socket_flags) && listen_internal();
}

bool Server::is_running() const { return is_running_; }

void Server::stop() {
	if (is_running_) {
		assert(svr_sock_ != INVALID_SOCKET);
		std::atomic<socket_t> sock(svr_sock_.exchange(INVALID_SOCKET));
		shutdown_socket(sock);
		close_socket(sock);
	}
}

bool Server::parse_request_line(const char *s, Request &req) {
	const static std::regex re(
		"(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|PRI) "
		"(([^?]+)(?:\\?(.*?))?) (HTTP/1\\.[01])\r\n");

	std::cmatch m;
	if (std::regex_match(s, m, re)) {
		req.version = std::string(m[5]);
		req.method = std::string(m[1]);
		req.target = std::string(m[2]);
		req.path = detail::decode_url(m[3]);

		// Parse query text
		auto len = std::distance(m[4].first, m[4].second);
		if (len > 0) { detail::parse_query_text(m[4], req.params); }

		return true;
	}

	return false;
}

template <typename T>
int write_headers(Stream &strm, const T &info, const Headers &headers) {
	auto write_len = 0;
	for (const auto &x : info.headers) {
		auto len =
			strm.write_format("%s: %s\r\n", x.first.c_str(), x.second.c_str());
		if (len < 0) { return len; }
		write_len += len;
	}
	for (const auto &x : headers) {
		auto len =
			strm.write_format("%s: %s\r\n", x.first.c_str(), x.second.c_str());
		if (len < 0) { return len; }
		write_len += len;
	}
	auto len = strm.write("\r\n");
	if (len < 0) { return len; }
	write_len += len;
	return write_len;
}
#if 1
bool Server::write_response(Stream &strm, bool last_connection,
	const Request &req, Response &res) {
	assert(res.status != -1);

	if (400 <= res.status && error_handler_) { error_handler_(req, res); }

	// Response line
	if (!strm.write_format("HTTP/1.1 %d %s\r\n", res.status,
		status_message(res.status))) {
		return false;
	}

	// Headers
	if (last_connection || req.get_header_value("Connection") == "close") {
		res.set_header("Connection", "close");
	}

	if (!last_connection && req.get_header_value("Connection") == "Keep-Alive") {
		res.set_header("Connection", "Keep-Alive");
	}

	if (!res.has_header("Content-Type") &&
		(!res.body.empty() || res.content_length > 0)) {
		res.set_header("Content-Type", "text/plain");
	}

	if (!res.has_header("Accept-Ranges") && req.method == "HEAD") {
		res.set_header("Accept-Ranges", "bytes");
	}

	std::string content_type;
	std::string boundary;

	if (req.ranges.size() > 1) {
		boundary = detail::make_multipart_data_boundary();

		auto it = res.headers.find("Content-Type");
		if (it != res.headers.end()) {
			content_type = it->second;
			res.headers.erase(it);
		}

		res.headers.emplace("Content-Type",
			"multipart/byteranges; boundary=" + boundary);
	}

	if (res.body.empty()) {
		if (res.content_length > 0) {
			size_t length = 0;
			if (req.ranges.empty()) {
				length = res.content_length;
			}
			else if (req.ranges.size() == 1) {
				auto offsets =
					detail::get_range_offset_and_length(req, res.content_length, 0);
				auto offset = offsets.first;
				length = offsets.second;
				auto content_range = make_content_range_header_field(
					offset, length, res.content_length);
				res.set_header("Content-Range", content_range);
			}
			else {
				length = get_multipart_ranges_data_length(req, res, boundary,
					content_type);
			}
			res.set_header("Content-Length", std::to_string(length));
		}
		else {
			if (res.content_provider) {
				res.set_header("Transfer-Encoding", "chunked");
			}
			else {
				res.set_header("Content-Length", "0");
			}
		}
	}
	else {
		if (req.ranges.empty()) {
			;
		}
		else if (req.ranges.size() == 1) {
			auto offsets =
				detail::get_range_offset_and_length(req, res.body.size(), 0);
			auto offset = offsets.first;
			auto length = offsets.second;
			auto content_range = make_content_range_header_field(
				offset, length, res.body.size());
			res.set_header("Content-Range", content_range);
			res.body = res.body.substr(offset, length);
		}
		else {
			res.body =
				make_multipart_ranges_data(req, res, boundary, content_type);
		}

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
		// TODO: 'Accept-Encoding' has gzip, not gzip;q=0
		const auto &encodings = req.get_header_value("Accept-Encoding");
		if (encodings.find("gzip") != std::string::npos &&
			detail::can_compress(res.get_header_value("Content-Type"))) {
			if (detail::compress(res.body)) {
				res.set_header("Content-Encoding", "gzip");
			}
		}
#endif

		auto length = std::to_string(res.body.size());
		res.set_header("Content-Length", length);
	}

	if (!write_headers(strm, res, Headers())) { return false; }

	// Body
	if (req.method != "HEAD") {
		if (!res.body.empty()) {
			if (!strm.write(res.body)) { return false; }
		}
		else if (res.content_provider) {
			if (!write_content_with_provider(strm, req, res, boundary,
				content_type)) {
				return false;
			}
		}
	}

	// Log
	if (logger_) { logger_(req, res); }

	return true;
}
#endif

std::string from_i_to_hex(size_t n) {
	const char *charset = "0123456789abcdef";
	std::string ret;
	do {
		ret = charset[n & 15] + ret;
		n >>= 4;
	} while (n > 0);
	return ret;
}

template <typename T>
ssize_t write_content_chunked(Stream &strm,
	ContentProvider content_provider,
	T is_shutting_down) {
	size_t offset = 0;
	auto data_available = true;
	ssize_t total_written_length = 0;
	while (data_available && !is_shutting_down()) {
		ssize_t written_length = 0;

		DataSink data_sink;
		data_sink.write = [&](const char *d, size_t l) {
			data_available = l > 0;
			offset += l;

			// Emit chunked response header and footer for each chunk
			auto chunk = from_i_to_hex(l) + "\r\n" + std::string(d, l) + "\r\n";
			written_length = strm.write(chunk);
		};
		data_sink.done = [&](void) {
			data_available = false;
			written_length = strm.write("0\r\n\r\n");
		};
		data_sink.is_writable = [&](void) { return strm.is_writable(); };

		content_provider(offset, 0, data_sink);

		if (written_length < 0) { return written_length; }
		total_written_length += written_length;
	}
	return total_written_length;
}

bool
Server::write_content_with_provider(Stream &strm, const Request &req,
	Response &res, const std::string &boundary,
	const std::string &content_type) {
	if (res.content_length) {
		if (req.ranges.empty()) {
			if (write_content(strm, res.content_provider, 0,
				res.content_length) < 0) {
				return false;
			}
		}
		else if (req.ranges.size() == 1) {
			auto offsets =
				detail::get_range_offset_and_length(req, res.content_length, 0);
			auto offset = offsets.first;
			auto length = offsets.second;
			if (write_content(strm, res.content_provider, offset, length) <
				0) {
				return false;
			}
		}
		else {
			if (!write_multipart_ranges_data(strm, req, res, boundary,
				content_type)) {
				return false;
			}
		}
	}
	else {
		auto is_shutting_down = [this]() {
			return /*this->*/svr_sock_ == INVALID_SOCKET;
		};
		if (write_content_chunked(strm, res.content_provider,
			is_shutting_down) < 0) {
			return false;
		}
	}
	return true;
}

bool Server::read_content(Stream &strm, bool last_connection,
	Request &req, Response &res) {
	MultipartFormDataMap::iterator cur;
	auto ret =
		read_content_core(strm, last_connection, req, res,
			// Regular
			[&](const char *buf, size_t n) {
		if (req.body.size() + n > req.body.max_size()) {
			return false;
		}
		req.body.append(buf, n);
		return true;
	},
			// Multipart
		[&](const MultipartFormData &file) {
		cur = req.files.emplace(file.name, file);
		return true;
	},
		[&](const char *buf, size_t n) {
		auto &content = cur->second.content;
		if (content.size() + n > content.max_size()) {
			return false;
		}
		content.append(buf, n);
		return true;
	});

	const auto &content_type = req.get_header_value("Content-Type");
	if (!content_type.find("application/x-www-form-urlencoded")) {
		detail::parse_query_text(req.body, req.params);
	}

	return ret;
}

bool Server::read_content_with_content_receiver(
	Stream &strm, bool last_connection, Request &req, Response &res,
	ContentReceiver receiver, MultipartContentHeader multipart_header,
	ContentReceiver multipart_receiver) {
	return read_content_core(strm, last_connection, req, res, receiver,
		multipart_header, multipart_receiver);
}
namespace detail {



	socket_t create_client_socket(const char *host, int port,
		time_t timeout_sec,
		const std::string &intf) {
		return create_socket(
			host, port, [&](socket_t sock, struct addrinfo &ai) -> bool {
			if (!intf.empty()) {
				auto ip = if2ip(intf);
				if (ip.empty()) { ip = intf; }
				if (!bind_ip_address(sock, ip.c_str())) { return false; }
			}

			set_nonblocking(sock, true);

			auto ret = ::connect(sock, ai.ai_addr, static_cast<int>(ai.ai_addrlen));
			if (ret < 0) {
				if (is_connection_error() ||
					!wait_until_socket_is_ready(sock, timeout_sec, 0)) {
					close_socket(sock);
					return false;
				}
			}

			set_nonblocking(sock, false);
			return true;
		});
	}

	template <typename T>
	bool process_and_close_socket(bool is_client_request, socket_t sock,
		size_t keep_alive_max_count,
		time_t read_timeout_sec,
		time_t read_timeout_usec, T callback) {
		auto ret = process_socket(is_client_request, sock, keep_alive_max_count,
			read_timeout_sec, read_timeout_usec, callback);
		close_socket(sock);
		return ret;
	}

	template <typename T>
	bool read_content(Stream &strm, T &x, size_t payload_max_length, int &status,
		Progress progress, ContentReceiver receiver) {

		ContentReceiver out = [&](const char *buf, size_t n) {
			return receiver(buf, n);
		};

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
		decompressor decompressor;

		if (!decompressor.is_valid()) {
			status = 500;
			return false;
		}

		if (x.get_header_value("Content-Encoding") == "gzip") {
			out = [&](const char *buf, size_t n) {
				return decompressor.decompress(
					buf, n, [&](const char *buf, size_t n) { return receiver(buf, n); });
			};
		}
#else
		if (x.get_header_value("Content-Encoding") == "gzip") {
			status = 415;
			return false;
		}
#endif

		auto ret = true;
		auto exceed_payload_max_length = false;

		if (is_chunked_transfer_encoding(x.headers)) {
			ret = read_content_chunked(strm, out);
		}
		else if (!has_header(x.headers, "Content-Length")) {
			ret = read_content_without_length(strm, out);
		}
		else {
			auto len = get_header_value_uint64(x.headers, "Content-Length", 0);
			if (len > payload_max_length) {
				exceed_payload_max_length = true;
				skip_content_with_length(strm, len);
				ret = false;
			}
			else if (len > 0) {
				ret = read_content_with_length(strm, len, progress, out);
			}
		}

		if (!ret) { status = exceed_payload_max_length ? 413 : 400; }

		return ret;
	}

#ifdef _WIN32
	class WSInit {
	public:
		WSInit() {
			WSADATA wsaData;
			WSAStartup(0x0002, &wsaData);
		}

		~WSInit() { WSACleanup(); }
	};

	static WSInit wsinit_;
#endif
} // namespace detail

bool Server::read_content_core(Stream &strm, bool last_connection,
	Request &req, Response &res,
	ContentReceiver receiver,
	MultipartContentHeader mulitpart_header,
	ContentReceiver multipart_receiver) {
	detail::MultipartFormDataParser multipart_form_data_parser;
	ContentReceiver out;

	if (req.is_multipart_form_data()) {
		const auto &content_type = req.get_header_value("Content-Type");
		std::string boundary;
		if (!detail::parse_multipart_boundary(content_type, boundary)) {
			res.status = 400;
			return write_response(strm, last_connection, req, res);
		}

		multipart_form_data_parser.set_boundary(boundary);
		out = [&](const char *buf, size_t n) {
			return multipart_form_data_parser.parse(buf, n, multipart_receiver,
				mulitpart_header);
		};
	}
	else {
		out = receiver;
	}

	if (!detail::read_content(strm, req, payload_max_length_, res.status,
		Progress(), out)) {
		return write_response(strm, last_connection, req, res);
	}

	if (req.is_multipart_form_data()) {
		if (!multipart_form_data_parser.is_valid()) {
			res.status = 400;
			return write_response(strm, last_connection, req, res);
		}
	}

	return true;
}

bool Server::handle_file_request(Request &req, Response &res,
	bool head) {
	for (const auto &kv : base_dirs_) {
		const auto &mount_point = kv.first;
		const auto &base_dir = kv.second;

		// Prefix match
		if (!req.path.find(mount_point)) {
			std::string sub_path = "/" + req.path.substr(mount_point.size());
			if (detail::is_valid_path(sub_path)) {
				auto path = base_dir + sub_path;
				if (path.back() == '/') { path += "index.html"; }

				if (detail::is_file(path)) {
					detail::read_file(path, res.body);
					auto type =
						find_content_type(path, file_extension_and_mimetype_map_);
					if (type) { res.set_header("Content-Type", type); }
					res.status = 200;
					if (!head && file_request_handler_) {
						file_request_handler_(req, res);
					}
					return true;
				}
			}
		}
	}
	return false;
}

socket_t /*Server::*/create_server_socket(const char *host, int port,
	int socket_flags) /*const*/ {
	return create_socket(
		host, port,
		[](socket_t sock, struct addrinfo &ai) -> bool {
		if (::bind(sock, ai.ai_addr, static_cast<int>(ai.ai_addrlen))) {
			return false;
		}
		if (::listen(sock, 5)) { // Listen through 5 channels
			return false;
		}
		return true;
	},
		socket_flags);
}

int Server::bind_internal(const char *host, int port, int socket_flags) {
	if (!is_valid()) { return -1; }

	svr_sock_ = create_server_socket(host, port, socket_flags);
	if (svr_sock_ == INVALID_SOCKET) { return -1; }

	if (port == 0) {
		struct sockaddr_storage address;
		socklen_t len = sizeof(address);
		if (getsockname(svr_sock_, reinterpret_cast<struct sockaddr *>(&address),
			&len) == -1) {
			return -1;
		}
		if (address.ss_family == AF_INET) {
			return ntohs(reinterpret_cast<struct sockaddr_in *>(&address)->sin_port);
		}
		else if (address.ss_family == AF_INET6) {
			return ntohs(
				reinterpret_cast<struct sockaddr_in6 *>(&address)->sin6_port);
		}
		else {
			return -1;
		}
	}
	else {
		return port;
	}
}

bool Server::listen_internal() {
	auto ret = true;
	is_running_ = true;

	{
		std::unique_ptr<TaskQueue> task_queue(new_task_queue());

		for (;;) {
			if (svr_sock_ == INVALID_SOCKET) {
				// The server socket was closed by 'stop' method.
				break;
			}

			auto val = select_read(svr_sock_, 0, 100000);

			if (val == 0) { // Timeout
				continue;
			}

			socket_t sock = accept(svr_sock_, nullptr, nullptr);

			if (sock == INVALID_SOCKET) {
				if (errno == EMFILE) {
					// The per-process limit of open file descriptors has been reached.
					// Try to accept new connections after a short sleep.
					std::this_thread::sleep_for(std::chrono::milliseconds(1));
					continue;
				}
				if (svr_sock_ != INVALID_SOCKET) {
					close_socket(svr_sock_);
					ret = false;
				}
				else {
					; // The server socket was closed by user.
				}
				break;
			}

			task_queue->enqueue([=]() 
			{ 
				//process_and_close_socket(sock); 
				detail::process_and_close_socket(
				false, sock, keep_alive_max_count_, read_timeout_sec_, read_timeout_usec_,
				[this](Stream &strm, bool last_connection, bool &connection_close) {
				return process_request(strm, last_connection, connection_close,
				nullptr);
	});
			});
		}

		task_queue->shutdown();
	}

	is_running_ = false;
	return ret;
}

bool Server::routing(Request &req, Response &res, Stream &strm,
	bool last_connection) {
	// File handler
	bool is_head_request = req.method == "HEAD";
	if ((req.method == "GET" || is_head_request) &&
		handle_file_request(req, res, is_head_request)) {
		return true;
	}

	if (detail::expect_content(req)) {
		// Content reader handler
		{
			ContentReader reader(
				[&](ContentReceiver receiver) {
				return read_content_with_content_receiver(
					strm, last_connection, req, res, receiver, nullptr, nullptr);
			},
				[&](MultipartContentHeader header, ContentReceiver receiver) {
				return read_content_with_content_receiver(
					strm, last_connection, req, res, nullptr, header, receiver);
			});

			if (req.method == "POST") {
				if (dispatch_request_for_content_reader(
					req, res, reader, post_handlers_for_content_reader_)) {
					return true;
				}
			}
			else if (req.method == "PUT") {
				if (dispatch_request_for_content_reader(
					req, res, reader, put_handlers_for_content_reader_)) {
					return true;
				}
			}
			else if (req.method == "PATCH") {
				if (dispatch_request_for_content_reader(
					req, res, reader, patch_handlers_for_content_reader_)) {
					return true;
				}
			}
		}

		// Read content into `req.body`
		if (!read_content(strm, last_connection, req, res)) { return false; }
	}

	// Regular handler
	if (req.method == "GET" || req.method == "HEAD") {
		return dispatch_request(req, res, get_handlers_);
	}
	else if (req.method == "POST") {
		return dispatch_request(req, res, post_handlers_);
	}
	else if (req.method == "PUT") {
		return dispatch_request(req, res, put_handlers_);
	}
	else if (req.method == "DELETE") {
		return dispatch_request(req, res, delete_handlers_);
	}
	else if (req.method == "OPTIONS") {
		return dispatch_request(req, res, options_handlers_);
	}
	else if (req.method == "PATCH") {
		return dispatch_request(req, res, patch_handlers_);
	}

	res.status = 400;
	return false;
}

bool Server::dispatch_request(Request &req, Response &res,
	Handlers &handlers) {
	for (const auto &x : handlers) {
		const auto &pattern = x.first;
		const auto &handler = x.second;

		if (std::regex_match(req.path, req.matches, pattern)) {
			handler(req, res);
			return true;
		}
	}
	return false;
}

bool Server::dispatch_request_for_content_reader(
	Request &req, Response &res, ContentReader content_reader,
	HandlersForContentReader &handlers) {
	for (const auto &x : handlers) {
		const auto &pattern = x.first;
		const auto &handler = x.second;

		if (std::regex_match(req.path, req.matches, pattern)) {
			handler(req, res, content_reader);
			return true;
		}
	}
	return false;
}

bool
Server::process_request(Stream &strm, bool last_connection,
	bool &connection_close,
	const std::function<void(Request &)> &setup_request) {
	std::array<char, 2048> buf{};

	stream_line_reader line_reader(strm, buf.data(), buf.size());

	// Connection has been closed on client
	if (!line_reader.getline()) { return false; }

	Request req;
	Response res;

	res.version = "HTTP/1.1";

	// Check if the request URI doesn't exceed the limit
	if (line_reader.size() > CPPHTTPLIB_REQUEST_URI_MAX_LENGTH) {
		Headers dummy;
		read_headers(strm, dummy);
		res.status = 414;
		return write_response(strm, last_connection, req, res);
	}

	// Request line and headers
	if (!parse_request_line(line_reader.ptr(), req) ||
		!read_headers(strm, req.headers)) {
		res.status = 400;
		return write_response(strm, last_connection, req, res);
	}

	if (req.get_header_value("Connection") == "close") {
		connection_close = true;
	}

	if (req.version == "HTTP/1.0" &&
		req.get_header_value("Connection") != "Keep-Alive") {
		connection_close = true;
	}

#if 0
	req.set_header("REMOTE_ADDR", strm.get_remote_addr());
#endif

	req.set_header("Cache-Control", "no-cache");

	if (req.has_header("Range")) {
		const auto &range_header_value = req.get_header_value("Range");
		if (!detail::parse_range_header(range_header_value, req.ranges)) {
			// TODO: error
		}
	}

	if (setup_request) { setup_request(req); }

	if (req.get_header_value("Expect") == "100-continue") {
		auto status = 100;
		if (expect_100_continue_handler_) {
			status = expect_100_continue_handler_(req, res);
		}
		switch (status) {
		case 100:
		case 417:
			strm.write_format("HTTP/1.1 %d %s\r\n\r\n", status,
				status_message(status));
			break;
		default: return write_response(strm, last_connection, req, res);
		}
	}

	// Rounting
	if (routing(req, res, strm, last_connection)) {
		if (res.status == -1) { res.status = req.ranges.empty() ? 200 : 206; }
	}
	else {
		if (res.status == -1) { res.status = 404; }
	}

	return write_response(strm, last_connection, req, res);
}

bool Server::is_valid() const { return true; }

#if 0 /* 放弃该接口，类成员函数的参数或返回值不能包含socket_t类型 */
inline bool Server::process_and_close_socket(socket_t sock) {
	return detail::process_and_close_socket(
		false, sock, keep_alive_max_count_, read_timeout_sec_, read_timeout_usec_,
		[this](Stream &strm, bool last_connection, bool &connection_close) {
		return process_request(strm, last_connection, connection_close,
			nullptr);
	});
}
#endif

// HTTP client implementation
Client::Client(const std::string &host, int port,
	const std::string &client_cert_path,
	const std::string &client_key_path)
	: host_(host), port_(port),
	host_and_port_(host_ + ":" + std::to_string(port_)),
	client_cert_path_(client_cert_path), client_key_path_(client_key_path) {}

Client::~Client() {}

bool Client::is_valid() const { return true; }

#if 0 /* 放弃该接口，类成员函数参数或返回值不能含有socket_t类型 */
inline socket_t Client::create_client_socket() const {
	if (!proxy_host_.empty()) {
		return detail::create_client_socket(proxy_host_.c_str(), proxy_port_,
			timeout_sec_, interface_);
	}
	return detail::create_client_socket(host_.c_str(), port_, timeout_sec_,
		interface_);
}
#endif

bool Client::read_response_line(Stream &strm, Response &res) {
	std::array<char, 2048> buf;

	stream_line_reader line_reader(strm, buf.data(), buf.size());

	if (!line_reader.getline()) { return false; }

	const static std::regex re("(HTTP/1\\.[01]) (\\d+?) .*\r\n");

	std::cmatch m;
	if (std::regex_match(line_reader.ptr(), m, re)) {
		res.version = std::string(m[1]);
		res.status = std::stoi(std::string(m[2]));
	}

	return true;
}

bool Client::send(const Request &req, Response &res) {

	socket_t sock;

	if (!proxy_host_.empty()) {
		sock = detail::create_client_socket(proxy_host_.c_str(), proxy_port_,
			timeout_sec_, interface_);
	}
	else
	{
		sock = detail::create_client_socket(host_.c_str(), port_, timeout_sec_,
			interface_);
	}

	//auto sock = create_client_socket();

	if (sock == INVALID_SOCKET) { return false; }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
	if (is_ssl() && !proxy_host_.empty()) {
		bool error;
		if (!connect(sock, res, error)) { return error; }
	}
#endif

	//return process_and_close_socket(
	//	sock, 1, [&](Stream &strm, bool last_connection, bool &connection_close) {
	//	return handle_request(strm, req, res, last_connection,
	//		connection_close);
	//});

	size_t request_count = 1;
	request_count = std::min(request_count, keep_alive_max_count_);
	return detail::process_and_close_socket(true, sock, request_count,
		read_timeout_sec_, read_timeout_usec_, [&](Stream &strm, bool last_connection, bool &connection_close) {
			return handle_request(strm, req, res, last_connection,
				connection_close);
		});
}

bool Client::send(const std::vector<Request> &requests,
	std::vector<Response> &responses) {
	size_t i = 0;
	while (i < requests.size()) {

		socket_t sock;

		if (!proxy_host_.empty()) {
			sock = detail::create_client_socket(proxy_host_.c_str(), proxy_port_,
				timeout_sec_, interface_);
		}
		else
		{
			sock = detail::create_client_socket(host_.c_str(), port_, timeout_sec_,
				interface_);
		}

		//auto sock = create_client_socket();

		if (sock == INVALID_SOCKET) { return false; }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
		if (is_ssl() && !proxy_host_.empty()) {
			Response res;
			bool error;
			if (!connect(sock, res, error)) { return false; }
		}
#endif

		size_t request_count = requests.size() - i;
		request_count = std::min(request_count, keep_alive_max_count_);

		if (detail::process_and_close_socket(true, sock, request_count,
			read_timeout_sec_, read_timeout_usec_,
			[&](Stream &strm, bool last_connection,
				bool &connection_close) -> bool {
			auto &req = requests[i++];
			auto res = Response();
			auto ret = handle_request(strm, req, res,
				last_connection,
				connection_close);
			if (ret) {
				responses.emplace_back(std::move(res));
			}
			return ret;
		})) {
			return false;
		}

		//if (!process_and_close_socket(sock, requests.size() - i,
		//	[&](Stream &strm, bool last_connection,
		//		bool &connection_close) -> bool {
		//	auto &req = requests[i++];
		//	auto res = Response();
		//	auto ret = handle_request(strm, req, res,
		//		last_connection,
		//		connection_close);
		//	if (ret) {
		//		responses.emplace_back(std::move(res));
		//	}
		//	return ret;
		//})) {
		//	return false;
		//}
	}

	return true;
}

bool Client::handle_request(Stream &strm, const Request &req,
	Response &res, bool last_connection,
	bool &connection_close) {
	if (req.path.empty()) { return false; }

	bool ret;

	if (!is_ssl() && !proxy_host_.empty()) {
		auto req2 = req;
		req2.path = "http://" + host_and_port_ + req.path;
		ret = process_request(strm, req2, res, last_connection, connection_close);
	}
	else {
		ret = process_request(strm, req, res, last_connection, connection_close);
	}

	if (!ret) { return false; }

	if (300 < res.status && res.status < 400 && follow_location_) {
		ret = redirect(req, res);
	}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
	if (res.status == 401 || res.status == 407) {
		auto is_proxy = res.status == 407;
		const auto &username =
			is_proxy ? proxy_digest_auth_username_ : digest_auth_username_;
		const auto &password =
			is_proxy ? proxy_digest_auth_password_ : digest_auth_password_;

		if (!username.empty() && !password.empty()) {
			std::map<std::string, std::string> auth;
			if (parse_www_authenticate(res, auth, is_proxy)) {
				Request new_req = req;
				auto key = is_proxy ? "Proxy-Authorization" : "WWW-Authorization";
				new_req.headers.erase(key);
				new_req.headers.insert(make_digest_authentication_header(
					req, auth, 1, random_string(10), username, password, is_proxy));

				Response new_res;

				ret = send(new_req, new_res);
				if (ret) { res = new_res; }
			}
		}
	}
#endif

	return ret;
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
inline bool Client::connect(socket_t sock, Response &res, bool &error) {
	error = true;
	Response res2;

	if (!detail::process_socket(
		true, sock, 1, read_timeout_sec_, read_timeout_usec_,
		[&](Stream &strm, bool /*last_connection*/, bool &connection_close) {
		Request req2;
		req2.method = "CONNECT";
		req2.path = host_and_port_;
		return process_request(strm, req2, res2, false, connection_close);
	})) {
		detail::close_socket(sock);
		error = false;
		return false;
	}

	if (res2.status == 407) {
		if (!proxy_digest_auth_username_.empty() &&
			!proxy_digest_auth_password_.empty()) {
			std::map<std::string, std::string> auth;
			if (parse_www_authenticate(res2, auth, true)) {
				Response res3;
				if (!detail::process_socket(
					true, sock, 1, read_timeout_sec_, read_timeout_usec_,
					[&](Stream &strm, bool /*last_connection*/,
						bool &connection_close) {
					Request req3;
					req3.method = "CONNECT";
					req3.path = host_and_port_;
					req3.headers.insert(make_digest_authentication_header(
						req3, auth, 1, random_string(10),
						proxy_digest_auth_username_, proxy_digest_auth_password_,
						true));
					return process_request(strm, req3, res3, false,
						connection_close);
				})) {
					detail::close_socket(sock);
					error = false;
					return false;
				}
			}
		}
		else {
			res = res2;
			return false;
		}
	}

	return true;
}
#endif

bool Client::redirect(const Request &req, Response &res) {
	if (req.redirect_count == 0) { return false; }

	auto location = res.get_header_value("location");
	if (location.empty()) { return false; }

	const static std::regex re(
		R"(^(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*(?:\?[^#]*)?)(?:#.*)?)");

	std::smatch m;
	if (!regex_match(location, m, re)) { return false; }

	auto scheme = is_ssl() ? "https" : "http";

	auto next_scheme = m[1].str();
	auto next_host = m[2].str();
	auto next_path = m[3].str();
	if (next_scheme.empty()) { next_scheme = scheme; }
	if (next_scheme.empty()) { next_scheme = scheme; }
	if (next_host.empty()) { next_host = host_; }
	if (next_path.empty()) { next_path = "/"; }

	if (next_scheme == scheme && next_host == host_) {
		return detail::redirect(*this, req, res, next_path);
	}
	else {
		if (next_scheme == "https") {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
			SSLClient cli(next_host.c_str());
			cli.copy_settings(*this);
			return detail::redirect(cli, req, res, next_path);
#else
			return false;
#endif
		}
		else {
			Client cli(next_host.c_str());
			cli.copy_settings(*this);
			return detail::redirect(cli, req, res, next_path);
		}
	}
}

bool Client::write_request(Stream &strm, const Request &req,
	bool last_connection) {
	BufferStream bstrm;

	// Request line
	const auto &path = detail::encode_url(req.path);

	bstrm.write_format("%s %s HTTP/1.1\r\n", req.method.c_str(), path.c_str());

	// Additonal headers
	Headers headers;
	if (last_connection) { headers.emplace("Connection", "close"); }

	if (!req.has_header("Host")) {
		if (is_ssl()) {
			if (port_ == 443) {
				headers.emplace("Host", host_);
			}
			else {
				headers.emplace("Host", host_and_port_);
			}
		}
		else {
			if (port_ == 80) {
				headers.emplace("Host", host_);
			}
			else {
				headers.emplace("Host", host_and_port_);
			}
		}
	}

#if	0
	if (!req.has_header("Accept")) { headers.emplace("Accept", "*/*"); }
#endif

	if (!req.has_header("User-Agent")) {
		headers.emplace("User-Agent", "(4G)(CTDCN_ZY/YAN1)(EC01;v1.00;YLJ)");
	}

	if (req.body.empty()) {
		if (req.content_provider) {
			auto length = std::to_string(req.content_length);
			headers.emplace("Content-Length", length);
		}
		else {
			headers.emplace("Content-Length", "0");
		}
	}
	else {
		if (!req.has_header("Content-Type")) {
			headers.emplace("Content-Type", "text/plain");
		}

		if (!req.has_header("Content-Length")) {
			auto length = std::to_string(req.body.size());
			headers.emplace("Content-Length", length);
		}
	}

	if (!basic_auth_username_.empty() && !basic_auth_password_.empty()) {
		headers.insert(make_basic_authentication_header(
			basic_auth_username_, basic_auth_password_, false));
	}

	if (!proxy_basic_auth_username_.empty() &&
		!proxy_basic_auth_password_.empty()) {
		headers.insert(make_basic_authentication_header(
			proxy_basic_auth_username_, proxy_basic_auth_password_, true));
	}

	write_headers(bstrm, req, headers);

	// Flush buffer
	auto &data = bstrm.get_buffer();
	strm.write(data.data(), data.size());

	// Body
	if (req.body.empty()) {
		if (req.content_provider) {
			size_t offset = 0;
			size_t end_offset = req.content_length;

			DataSink data_sink;
			data_sink.write = [&](const char *d, size_t l) {
				auto written_length = strm.write(d, l);
				offset += written_length;
			};
			data_sink.is_writable = [&](void) { return strm.is_writable(); };

			while (offset < end_offset) {
				req.content_provider(offset, end_offset - offset, data_sink);
			}
		}
	}
	else {
		strm.write(req.body);
	}

	return true;
}

std::shared_ptr<Response> Client::send_with_content_provider(
	const char *method, const char *path, const Headers &headers,
	const std::string &body, size_t content_length,
	ContentProvider content_provider, const char *content_type) {
	Request req;
	req.method = method;
	req.headers = headers;
	req.path = path;

	req.headers.emplace("Content-Type", content_type);

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
	if (compress_) {
		if (content_provider) {
			size_t offset = 0;

			DataSink data_sink;
			data_sink.write = [&](const char *data, size_t data_len) {
				req.body.append(data, data_len);
				offset += data_len;
			};
			data_sink.is_writable = [&](void) { return true; };

			while (offset < content_length) {
				content_provider(offset, content_length - offset, data_sink);
			}
		}
		else {
			req.body = body;
		}

		if (!detail::compress(req.body)) { return nullptr; }
		req.headers.emplace("Content-Encoding", "gzip");
	}
	else
#endif
	{
		if (content_provider) {
			req.content_length = content_length;
			req.content_provider = content_provider;
		}
		else {
			req.body = body;
		}
	}

	auto res = std::make_shared<Response>();

	return send(req, *res) ? res : nullptr;
}

bool Client::process_request(Stream &strm, const Request &req,
	Response &res, bool last_connection,
	bool &connection_close) {
	// Send request
	if (!write_request(strm, req, last_connection)) { return false; }

	// Receive response and headers
	if (!read_response_line(strm, res) ||
		!read_headers(strm, res.headers)) {
		return false;
	}

	if (res.get_header_value("Connection") == "close" ||
		res.version == "HTTP/1.0") {
		connection_close = true;
	}

	if (req.response_handler) {
		if (!req.response_handler(res)) { return false; }
	}

	// Body
	if (req.method != "HEAD" && req.method != "CONNECT") {
		ContentReceiver out = [&](const char *buf, size_t n) {
			if (res.body.size() + n > res.body.max_size()) { return false; }
			res.body.append(buf, n);
			return true;
		};

		if (req.content_receiver) {
			out = [&](const char *buf, size_t n) {
				return req.content_receiver(buf, n);
			};
		}

		int dummy_status;
		if (!detail::read_content(strm, res, std::numeric_limits<size_t>::max(),
			dummy_status, req.progress, out)) {
			return false;
		}
	}

	// Log
	if (logger_) { logger_(req, res); }

	return true;
}
#if 0 /* 放弃该接口，类成员函数的参数或返回值不能包含socket_t类型 */
inline bool Client::process_and_close_socket(
	socket_t sock, size_t request_count,
	std::function<bool(Stream &strm, bool last_connection,
		bool &connection_close)>
	callback) {
	request_count = std::min(request_count, keep_alive_max_count_);
	return detail::process_and_close_socket(true, sock, request_count,
		read_timeout_sec_, read_timeout_usec_,
		callback);
}
#endif

bool Client::is_ssl() const { return false; }

std::shared_ptr<Response> Client::Get(const char *path) {
	return Get(path, Headers(), Progress());
}

std::shared_ptr<Response> Client::Get(const char *path,
	Progress progress) {
	return Get(path, Headers(), std::move(progress));
}

std::shared_ptr<Response> Client::Get(const char *path,
	const Headers &headers) {
	return Get(path, headers, Progress());
}

std::shared_ptr<Response>
Client::Get(const char *path, const Headers &headers, Progress progress) {
	Request req;
	req.method = "GET";
	req.path = path;
	req.headers = headers;
	req.progress = std::move(progress);

	auto res = std::make_shared<Response>();
	return send(req, *res) ? res : nullptr;
}

std::shared_ptr<Response> Client::Get(const char *path,
	ContentReceiver content_receiver) {
	return Get(path, Headers(), nullptr, std::move(content_receiver), Progress());
}

std::shared_ptr<Response> Client::Get(const char *path,
	ContentReceiver content_receiver,
	Progress progress) {
	return Get(path, Headers(), nullptr, std::move(content_receiver),
		std::move(progress));
}

std::shared_ptr<Response> Client::Get(const char *path,
	const Headers &headers,
	ContentReceiver content_receiver) {
	return Get(path, headers, nullptr, std::move(content_receiver), Progress());
}

std::shared_ptr<Response> Client::Get(const char *path,
	const Headers &headers,
	ContentReceiver content_receiver,
	Progress progress) {
	return Get(path, headers, nullptr, std::move(content_receiver),
		std::move(progress));
}

std::shared_ptr<Response> Client::Get(const char *path,
	const Headers &headers,
	ResponseHandler response_handler,
	ContentReceiver content_receiver) {
	return Get(path, headers, std::move(response_handler), content_receiver,
		Progress());
}

std::shared_ptr<Response> Client::Get(const char *path,
	const Headers &headers,
	ResponseHandler response_handler,
	ContentReceiver content_receiver,
	Progress progress) {
	Request req;
	req.method = "GET";
	req.path = path;
	req.headers = headers;
	req.response_handler = std::move(response_handler);
	req.content_receiver = std::move(content_receiver);
	req.progress = std::move(progress);

	auto res = std::make_shared<Response>();
	return send(req, *res) ? res : nullptr;
}

std::shared_ptr<Response> Client::Head(const char *path) {
	return Head(path, Headers());
}

std::shared_ptr<Response> Client::Head(const char *path,
	const Headers &headers) {
	Request req;
	req.method = "HEAD";
	req.headers = headers;
	req.path = path;

	auto res = std::make_shared<Response>();

	return send(req, *res) ? res : nullptr;
}

std::shared_ptr<Response> Client::Post(const char *path,
	const std::string &body,
	const char *content_type) {
	return Post(path, Headers(), body, content_type);
}

std::shared_ptr<Response> Client::Post(const char *path,
	const Headers &headers,
	const std::string &body,
	const char *content_type) {
	return send_with_content_provider("POST", path, headers, body, 0, nullptr,
		content_type);
}

std::shared_ptr<Response> Client::Post(const char *path,
	const Params &params) {
	return Post(path, Headers(), params);
}

std::shared_ptr<Response> Client::Post(const char *path,
	size_t content_length,
	ContentProvider content_provider,
	const char *content_type) {
	return Post(path, Headers(), content_length, content_provider, content_type);
}

std::shared_ptr<Response>
Client::Post(const char *path, const Headers &headers, size_t content_length,
	ContentProvider content_provider, const char *content_type) {
	return send_with_content_provider("POST", path, headers, std::string(),
		content_length, content_provider,
		content_type);
}

std::shared_ptr<Response>
Client::Post(const char *path, const Headers &headers, const Params &params) {
	std::string query;
	for (auto it = params.begin(); it != params.end(); ++it) {
		if (it != params.begin()) { query += "&"; }
		query += it->first;
		query += "=";
		query += detail::encode_url(it->second);
	}

	return Post(path, headers, query, "application/x-www-form-urlencoded");
}

std::shared_ptr<Response>
Client::Post(const char *path, const MultipartFormDataItems &items) {
	return Post(path, Headers(), items);
}

std::shared_ptr<Response>
Client::Post(const char *path, const Headers &headers,
	const MultipartFormDataItems &items) {
	auto boundary = detail::make_multipart_data_boundary();

	std::string body;

	for (const auto &item : items) {
		body += "--" + boundary + "\r\n";
		body += "Content-Disposition: form-data; name=\"" + item.name + "\"";
		if (!item.filename.empty()) {
			body += "; filename=\"" + item.filename + "\"";
		}
		body += "\r\n";
		if (!item.content_type.empty()) {
			body += "Content-Type: " + item.content_type + "\r\n";
		}
		body += "\r\n";
		body += item.content + "\r\n";
	}

	body += "--" + boundary + "--\r\n";

	std::string content_type = "multipart/form-data; boundary=" + boundary;
	return Post(path, headers, body, content_type.c_str());
}

std::shared_ptr<Response> Client::Put(const char *path,
	const std::string &body,
	const char *content_type) {
	return Put(path, Headers(), body, content_type);
}

std::shared_ptr<Response> Client::Put(const char *path,
	const Headers &headers,
	const std::string &body,
	const char *content_type) {
	return send_with_content_provider("PUT", path, headers, body, 0, nullptr,
		content_type);
}

std::shared_ptr<Response> Client::Put(const char *path,
	size_t content_length,
	ContentProvider content_provider,
	const char *content_type) {
	return Put(path, Headers(), content_length, content_provider, content_type);
}

std::shared_ptr<Response>
Client::Put(const char *path, const Headers &headers, size_t content_length,
	ContentProvider content_provider, const char *content_type) {
	return send_with_content_provider("PUT", path, headers, std::string(),
		content_length, content_provider,
		content_type);
}

std::shared_ptr<Response> Client::Put(const char *path,
	const Params &params) {
	return Put(path, Headers(), params);
}

std::shared_ptr<Response>
Client::Put(const char *path, const Headers &headers, const Params &params) {
	std::string query;
	for (auto it = params.begin(); it != params.end(); ++it) {
		if (it != params.begin()) { query += "&"; }
		query += it->first;
		query += "=";
		query += detail::encode_url(it->second);
	}

	return Put(path, headers, query, "application/x-www-form-urlencoded");
}

std::shared_ptr<Response> Client::Patch(const char *path,
	const std::string &body,
	const char *content_type) {
	return Patch(path, Headers(), body, content_type);
}

std::shared_ptr<Response> Client::Patch(const char *path,
	const Headers &headers,
	const std::string &body,
	const char *content_type) {
	return send_with_content_provider("PATCH", path, headers, body, 0, nullptr,
		content_type);
}

std::shared_ptr<Response> Client::Patch(const char *path,
	size_t content_length,
	ContentProvider content_provider,
	const char *content_type) {
	return Patch(path, Headers(), content_length, content_provider, content_type);
}

std::shared_ptr<Response>
Client::Patch(const char *path, const Headers &headers, size_t content_length,
	ContentProvider content_provider, const char *content_type) {
	return send_with_content_provider("PATCH", path, headers, std::string(),
		content_length, content_provider,
		content_type);
}

std::shared_ptr<Response> Client::Delete(const char *path) {
	return Delete(path, Headers(), std::string(), nullptr);
}

std::shared_ptr<Response> Client::Delete(const char *path,
	const std::string &body,
	const char *content_type) {
	return Delete(path, Headers(), body, content_type);
}

std::shared_ptr<Response> Client::Delete(const char *path,
	const Headers &headers) {
	return Delete(path, headers, std::string(), nullptr);
}

std::shared_ptr<Response> Client::Delete(const char *path,
	const Headers &headers,
	const std::string &body,
	const char *content_type) {
	Request req;
	req.method = "DELETE";
	req.headers = headers;
	req.path = path;

	if (content_type) { req.headers.emplace("Content-Type", content_type); }
	req.body = body;

	auto res = std::make_shared<Response>();

	return send(req, *res) ? res : nullptr;
}

std::shared_ptr<Response> Client::Options(const char *path) {
	return Options(path, Headers());
}

std::shared_ptr<Response> Client::Options(const char *path,
	const Headers &headers) {
	Request req;
	req.method = "OPTIONS";
	req.path = path;
	req.headers = headers;

	auto res = std::make_shared<Response>();

	return send(req, *res) ? res : nullptr;
}

void Client::set_timeout_sec(time_t timeout_sec) {
	timeout_sec_ = timeout_sec;
}

void Client::set_read_timeout(time_t sec, time_t usec) {
	read_timeout_sec_ = sec;
	read_timeout_usec_ = usec;
}

void Client::set_keep_alive_max_count(size_t count) {
	keep_alive_max_count_ = count;
}

void Client::set_basic_auth(const char *username, const char *password) {
	basic_auth_username_ = username;
	basic_auth_password_ = password;
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
inline void Client::set_digest_auth(const char *username,
	const char *password) {
	digest_auth_username_ = username;
	digest_auth_password_ = password;
}
#endif

void Client::set_follow_location(bool on) { follow_location_ = on; }

void Client::set_compress(bool on) { compress_ = on; }

void Client::set_interface(const char *intf) { interface_ = intf; }

void Client::set_proxy(const char *host, int port) {
	proxy_host_ = host;
	proxy_port_ = port;
}

void Client::set_proxy_basic_auth(const char *username,
	const char *password) {
	proxy_basic_auth_username_ = username;
	proxy_basic_auth_password_ = password;
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
inline void Client::set_proxy_digest_auth(const char *username,
	const char *password) {
	proxy_digest_auth_username_ = username;
	proxy_digest_auth_password_ = password;
}
#endif

void Client::set_logger(Logger logger) { logger_ = std::move(logger); }

}// namespace httplib

