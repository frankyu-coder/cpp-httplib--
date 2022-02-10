//
//  httplib.h
//
//  Copyright (c) 2020 Yuji Hirose. All rights reserved.
//  MIT License
//

#ifndef CPPHTTPLIB_HTTPLIB_H
#define CPPHTTPLIB_HTTPLIB_H

/*
 * Configuration
 */

#ifndef CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND
#define CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND 5
#endif

#ifndef CPPHTTPLIB_KEEPALIVE_TIMEOUT_USECOND
#define CPPHTTPLIB_KEEPALIVE_TIMEOUT_USECOND 0
#endif

#ifndef CPPHTTPLIB_KEEPALIVE_MAX_COUNT
#define CPPHTTPLIB_KEEPALIVE_MAX_COUNT 5
#endif

#ifndef CPPHTTPLIB_READ_TIMEOUT_SECOND
#define CPPHTTPLIB_READ_TIMEOUT_SECOND 5
#endif

#ifndef CPPHTTPLIB_READ_TIMEOUT_USECOND
#define CPPHTTPLIB_READ_TIMEOUT_USECOND 0
#endif

#ifndef CPPHTTPLIB_REQUEST_URI_MAX_LENGTH
#define CPPHTTPLIB_REQUEST_URI_MAX_LENGTH 8192
#endif

#ifndef CPPHTTPLIB_REDIRECT_MAX_COUNT
#define CPPHTTPLIB_REDIRECT_MAX_COUNT 20
#endif

#ifndef CPPHTTPLIB_PAYLOAD_MAX_LENGTH
#define CPPHTTPLIB_PAYLOAD_MAX_LENGTH (std::numeric_limits<size_t>::max)()
#endif

#ifndef CPPHTTPLIB_RECV_BUFSIZ
#define CPPHTTPLIB_RECV_BUFSIZ size_t(4096u)
#endif

#ifndef CPPHTTPLIB_THREAD_POOL_COUNT
// if hardware_concurrency() outputs 0 we still wants to use threads for this.
// -1 because we have one thread already in the main function.
#define CPPHTTPLIB_THREAD_POOL_COUNT                                           \
  (std::thread::hardware_concurrency()                                         \
       ? std::thread::hardware_concurrency() - 1                               \
       : 2)
#endif

/*
 * Headers
 */

#ifdef _WIN32
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif //_CRT_SECURE_NO_WARNINGS

#ifndef _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#endif //_CRT_NONSTDC_NO_DEPRECATE

#if defined(_MSC_VER)
#ifdef _WIN64
using ssize_t = __int64;
#else
using ssize_t = int;
#endif

#if _MSC_VER < 1900
#define snprintf _snprintf_s
#endif
#endif // _MSC_VER

#ifndef S_ISREG
#define S_ISREG(m) (((m)&S_IFREG) == S_IFREG)
#endif // S_ISREG

#ifndef S_ISDIR
#define S_ISDIR(m) (((m)&S_IFDIR) == S_IFDIR)
#endif // S_ISDIR

#ifndef NOMINMAX
#define NOMINMAX
#endif // NOMINMAX

#ifndef WSA_FLAG_NO_HANDLE_INHERIT
#define WSA_FLAG_NO_HANDLE_INHERIT 0x80
#endif

#ifndef strcasecmp
#define strcasecmp _stricmp
#endif // strcasecmp

#ifdef CPPHTTPLIB_USE_POLL
#define poll(fds, nfds, timeout) WSAPoll(fds, nfds, timeout)
#endif

#else // not _WIN32

#include <arpa/inet.h>
#include <cstring>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#ifdef CPPHTTPLIB_USE_POLL
#include <poll.h>
#endif
#include <csignal>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#endif //_WIN32

#include <array>
#include <atomic>
#include <cassert>
#include <condition_variable>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <regex>
#include <string.h>
#include <sys/stat.h>
#include <thread>

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <iomanip>
#include <sstream>

// #if OPENSSL_VERSION_NUMBER < 0x1010100fL
// #error Sorry, OpenSSL versions prior to 1.1.1 are not supported
// #endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/crypto.h>
inline const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *asn1) {
  return M_ASN1_STRING_data(asn1);
}
#endif
#endif

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
#include <zlib.h>
#endif


/*
 * Declaration
 */
namespace httplib {

class Stream;

namespace detail {

struct ci {
  bool operator()(const std::string &s1, const std::string &s2) const {
    return std::lexicographical_compare(
        s1.begin(), s1.end(), s2.begin(), s2.end(),
        [](char c1, char c2) { return ::tolower(c1) < ::tolower(c2); });
  }
};

} // namespace detail

using Headers = std::multimap<std::string, std::string, detail::ci>;

using Params = std::multimap<std::string, std::string>;
using Match = std::smatch;

using Progress = std::function<bool(uint64_t current, uint64_t total)>;

struct Response;
using ResponseHandler = std::function<bool(const Response &response)>;

struct MultipartFormData {
  std::string name;
  std::string content;
  std::string filename;
  std::string content_type;
};
using MultipartFormDataItems = std::vector<MultipartFormData>;
using MultipartFormDataMap = std::multimap<std::string, MultipartFormData>;

class DataSink {
public:
  DataSink() = default;
  DataSink(const DataSink &) = delete;
  DataSink &operator=(const DataSink &) = delete;
  DataSink(DataSink &&) = delete;
  DataSink &operator=(DataSink &&) = delete;

  std::function<void(const char *data, size_t data_len)> write;
  std::function<void()> done;
  std::function<bool()> is_writable;
};

using ContentProvider =
    std::function<void(size_t offset, size_t length, DataSink &sink)>;

using ContentReceiver =
    std::function<bool(const char *data, size_t data_length)>;

using MultipartContentHeader =
    std::function<bool(const MultipartFormData &file)>;

class ContentReader {
public:
  using Reader = std::function<bool(ContentReceiver receiver)>;
  using MultipartReader = std::function<bool(MultipartContentHeader header,
                                             ContentReceiver receiver)>;

  ContentReader(Reader reader, MultipartReader muitlpart_reader)
      : reader_(reader), muitlpart_reader_(muitlpart_reader) {}

  bool operator()(MultipartContentHeader header,
                  ContentReceiver receiver) const {
    return muitlpart_reader_(header, receiver);
  }

  bool operator()(ContentReceiver receiver) const { return reader_(receiver); }

  Reader reader_;
  MultipartReader muitlpart_reader_;
};

using Range = std::pair<ssize_t, ssize_t>;
using Ranges = std::vector<Range>;

struct Request {
  std::string method;
  std::string path;
  Headers headers;
  std::string body;

  // for server
  std::string version;
  std::string target;
  Params params;
  MultipartFormDataMap files;
  Ranges ranges;
  Match matches;

  // for client
  size_t redirect_count = CPPHTTPLIB_REDIRECT_MAX_COUNT;
  ResponseHandler response_handler;
  ContentReceiver content_receiver;
  Progress progress;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  const SSL *ssl;
#endif

  bool has_header(const char *key) const;
  std::string get_header_value(const char *key, size_t id = 0) const;
  size_t get_header_value_count(const char *key) const;
  void set_header(const char *key, const char *val);
  void set_header(const char *key, const std::string &val);

  bool has_param(const char *key) const;
  std::string get_param_value(const char *key, size_t id = 0) const;
  size_t get_param_value_count(const char *key) const;

  bool is_multipart_form_data() const;

  bool has_file(const char *key) const;
  MultipartFormData get_file_value(const char *key) const;

  // private members...
  size_t content_length;
  ContentProvider content_provider;
};

struct Response {
  std::string version;
  int status = -1;
  Headers headers;
  std::string body;

  bool has_header(const char *key) const;
  std::string get_header_value(const char *key, size_t id = 0) const;
  size_t get_header_value_count(const char *key) const;
  void set_header(const char *key, const char *val);
  void set_header(const char *key, const std::string &val);

  void set_redirect(const char *url);
  void set_content(const char *s, size_t n, const char *content_type);
  void set_content(const std::string &s, const char *content_type);

  void set_content_provider(
      size_t length,
      std::function<void(size_t offset, size_t length, DataSink &sink)>
          provider,
      std::function<void()> resource_releaser = [] {});

  void set_chunked_content_provider(
      std::function<void(size_t offset, DataSink &sink)> provider,
      std::function<void()> resource_releaser = [] {});

  Response() = default;
  Response(const Response &) = default;
  Response &operator=(const Response &) = default;
  Response(Response &&) = default;
  Response &operator=(Response &&) = default;
  ~Response() {
    if (content_provider_resource_releaser) {
      content_provider_resource_releaser();
    }
  }

  // private members...
  size_t content_length = 0;
  ContentProvider content_provider;
  std::function<void()> content_provider_resource_releaser;
};

class TaskQueue {
public:
  TaskQueue() = default;
  virtual ~TaskQueue() = default;
  virtual void enqueue(std::function<void()> fn) = 0;
  virtual void shutdown() = 0;
};

class ThreadPool : public TaskQueue {
public:
  explicit ThreadPool(size_t n) : shutdown_(false) {
    while (n) {
      threads_.emplace_back(worker(*this));
      n--;
    }
  }

  ThreadPool(const ThreadPool &) = delete;
  ~ThreadPool() override = default;

  void enqueue(std::function<void()> fn) override {
    std::unique_lock<std::mutex> lock(mutex_);
    jobs_.push_back(fn);
    cond_.notify_one();
  }

  void shutdown() override {
    // Stop all worker threads...
    {
      std::unique_lock<std::mutex> lock(mutex_);
      shutdown_ = true;
    }

    cond_.notify_all();

    // Join...
    for (auto &t : threads_) {
      t.join();
    }
  }

private:
  struct worker {
    explicit worker(ThreadPool &pool) : pool_(pool) {}

    void operator()() {
      for (;;) {
        std::function<void()> fn;
        {
          std::unique_lock<std::mutex> lock(pool_.mutex_);

          pool_.cond_.wait(
              lock, [&] { return !pool_.jobs_.empty() || pool_.shutdown_; });

          if (pool_.shutdown_ && pool_.jobs_.empty()) { break; }

          fn = pool_.jobs_.front();
          pool_.jobs_.pop_front();
        }

        assert(true == static_cast<bool>(fn));
        fn();
      }
    }

    ThreadPool &pool_;
  };
  friend struct worker;

  std::vector<std::thread> threads_;
  std::list<std::function<void()>> jobs_;

  bool shutdown_;

  std::condition_variable cond_;
  std::mutex mutex_;
};

using Logger = std::function<void(const Request &, const Response &)>;

class Server {
public:
  using Handler = std::function<void(const Request &, Response &)>;
  using HandlerWithContentReader = std::function<void(
      const Request &, Response &, const ContentReader &content_reader)>;
  using Expect100ContinueHandler =
      std::function<int(const Request &, Response &)>;

  Server();

  virtual ~Server();

  virtual bool is_valid() const;

  Server &Get(const char *pattern, Handler handler);
  Server &Post(const char *pattern, Handler handler);
  Server &Post(const char *pattern, HandlerWithContentReader handler);
  Server &Put(const char *pattern, Handler handler);
  Server &Put(const char *pattern, HandlerWithContentReader handler);
  Server &Patch(const char *pattern, Handler handler);
  Server &Patch(const char *pattern, HandlerWithContentReader handler);
  Server &Delete(const char *pattern, Handler handler);
  Server &Options(const char *pattern, Handler handler);

  [[deprecated]] bool set_base_dir(const char *dir,
                                   const char *mount_point = nullptr);
  bool set_mount_point(const char *mount_point, const char *dir);
  bool remove_mount_point(const char *mount_point);
  void set_file_extension_and_mimetype_mapping(const char *ext,
                                               const char *mime);
  void set_file_request_handler(Handler handler);

  void set_error_handler(Handler handler);
  void set_logger(Logger logger);

  void set_expect_100_continue_handler(Expect100ContinueHandler handler);

  void set_keep_alive_max_count(size_t count);
  void set_read_timeout(time_t sec, time_t usec);
  void set_payload_max_length(size_t length);

  bool bind_to_port(const char *host, int port, int socket_flags = 0);
  int bind_to_any_port(const char *host, int socket_flags = 0);
  bool listen_after_bind();

  bool listen(const char *host, int port, int socket_flags = 0);

  bool is_running() const;
  void stop();

  std::function<TaskQueue *(void)> new_task_queue;

protected:
  bool process_request(Stream &strm, bool last_connection,
                       bool &connection_close,
                       const std::function<void(Request &)> &setup_request);

  size_t keep_alive_max_count_;
  time_t read_timeout_sec_;
  time_t read_timeout_usec_;
  size_t payload_max_length_;

private:
  using Handlers = std::vector<std::pair<std::regex, Handler>>;
  using HandlersForContentReader =
      std::vector<std::pair<std::regex, HandlerWithContentReader>>;

  //socket_t create_server_socket(const char *host, int port,
  //                              int socket_flags) const;
  int bind_internal(const char *host, int port, int socket_flags);
  bool listen_internal();

  bool routing(Request &req, Response &res, Stream &strm, bool last_connection);
  bool handle_file_request(Request &req, Response &res, bool head = false);
  bool dispatch_request(Request &req, Response &res, Handlers &handlers);
  bool dispatch_request_for_content_reader(Request &req, Response &res,
                                           ContentReader content_reader,
                                           HandlersForContentReader &handlers);

  bool parse_request_line(const char *s, Request &req);

  bool write_response(Stream &strm, bool last_connection, const Request &req,
                      Response &res);
  bool write_content_with_provider(Stream &strm, const Request &req,
                                   Response &res, const std::string &boundary,
                                   const std::string &content_type);
  bool read_content(Stream &strm, bool last_connection, Request &req,
                    Response &res);
  bool read_content_with_content_receiver(
      Stream &strm, bool last_connection, Request &req, Response &res,
      ContentReceiver receiver, MultipartContentHeader multipart_header,
      ContentReceiver multipart_receiver);
  bool read_content_core(Stream &strm, bool last_connection, Request &req,
                         Response &res, ContentReceiver receiver,
                         MultipartContentHeader mulitpart_header,
                         ContentReceiver multipart_receiver);

 // virtual bool process_and_close_socket(socket_t sock);

  std::atomic<bool> is_running_;
 // std::atomic<socket_t> svr_sock_;
  std::vector<std::pair<std::string, std::string>> base_dirs_;
  std::map<std::string, std::string> file_extension_and_mimetype_map_;
  Handler file_request_handler_;
  Handlers get_handlers_;
  Handlers post_handlers_;
  HandlersForContentReader post_handlers_for_content_reader_;
  Handlers put_handlers_;
  HandlersForContentReader put_handlers_for_content_reader_;
  Handlers patch_handlers_;
  HandlersForContentReader patch_handlers_for_content_reader_;
  Handlers delete_handlers_;
  Handlers options_handlers_;
  Handler error_handler_;
  Logger logger_;
  Expect100ContinueHandler expect_100_continue_handler_;
};

class Client {
public:
  explicit Client(const std::string &host, int port = 80,
                  const std::string &client_cert_path = std::string(),
                  const std::string &client_key_path = std::string());

  virtual ~Client();

  virtual bool is_valid() const;

  std::shared_ptr<Response> Get(const char *path);

  std::shared_ptr<Response> Get(const char *path, const Headers &headers);

  std::shared_ptr<Response> Get(const char *path, Progress progress);

  std::shared_ptr<Response> Get(const char *path, const Headers &headers,
                                Progress progress);

  std::shared_ptr<Response> Get(const char *path,
                                ContentReceiver content_receiver);

  std::shared_ptr<Response> Get(const char *path, const Headers &headers,
                                ContentReceiver content_receiver);

  std::shared_ptr<Response>
  Get(const char *path, ContentReceiver content_receiver, Progress progress);

  std::shared_ptr<Response> Get(const char *path, const Headers &headers,
                                ContentReceiver content_receiver,
                                Progress progress);

  std::shared_ptr<Response> Get(const char *path, const Headers &headers,
                                ResponseHandler response_handler,
                                ContentReceiver content_receiver);

  std::shared_ptr<Response> Get(const char *path, const Headers &headers,
                                ResponseHandler response_handler,
                                ContentReceiver content_receiver,
                                Progress progress);

  std::shared_ptr<Response> Head(const char *path);

  std::shared_ptr<Response> Head(const char *path, const Headers &headers);

  std::shared_ptr<Response> Post(const char *path, const std::string &body,
                                 const char *content_type);

  std::shared_ptr<Response> Post(const char *path, const Headers &headers,
                                 const std::string &body,
                                 const char *content_type);

  std::shared_ptr<Response> Post(const char *path, size_t content_length,
                                 ContentProvider content_provider,
                                 const char *content_type);

  std::shared_ptr<Response> Post(const char *path, const Headers &headers,
                                 size_t content_length,
                                 ContentProvider content_provider,
                                 const char *content_type);

  std::shared_ptr<Response> Post(const char *path, const Params &params);

  std::shared_ptr<Response> Post(const char *path, const Headers &headers,
                                 const Params &params);

  std::shared_ptr<Response> Post(const char *path,
                                 const MultipartFormDataItems &items);

  std::shared_ptr<Response> Post(const char *path, const Headers &headers,
                                 const MultipartFormDataItems &items);

  std::shared_ptr<Response> Put(const char *path, const std::string &body,
                                const char *content_type);

  std::shared_ptr<Response> Put(const char *path, const Headers &headers,
                                const std::string &body,
                                const char *content_type);

  std::shared_ptr<Response> Put(const char *path, size_t content_length,
                                ContentProvider content_provider,
                                const char *content_type);

  std::shared_ptr<Response> Put(const char *path, const Headers &headers,
                                size_t content_length,
                                ContentProvider content_provider,
                                const char *content_type);

  std::shared_ptr<Response> Put(const char *path, const Params &params);

  std::shared_ptr<Response> Put(const char *path, const Headers &headers,
                                const Params &params);

  std::shared_ptr<Response> Patch(const char *path, const std::string &body,
                                  const char *content_type);

  std::shared_ptr<Response> Patch(const char *path, const Headers &headers,
                                  const std::string &body,
                                  const char *content_type);

  std::shared_ptr<Response> Patch(const char *path, size_t content_length,
                                  ContentProvider content_provider,
                                  const char *content_type);

  std::shared_ptr<Response> Patch(const char *path, const Headers &headers,
                                  size_t content_length,
                                  ContentProvider content_provider,
                                  const char *content_type);

  std::shared_ptr<Response> Delete(const char *path);

  std::shared_ptr<Response> Delete(const char *path, const std::string &body,
                                   const char *content_type);

  std::shared_ptr<Response> Delete(const char *path, const Headers &headers);

  std::shared_ptr<Response> Delete(const char *path, const Headers &headers,
                                   const std::string &body,
                                   const char *content_type);

  std::shared_ptr<Response> Options(const char *path);

  std::shared_ptr<Response> Options(const char *path, const Headers &headers);

  bool send(const Request &req, Response &res);

  bool send(const std::vector<Request> &requests,
            std::vector<Response> &responses);

  void set_timeout_sec(time_t timeout_sec);

  void set_read_timeout(time_t sec, time_t usec);

  void set_keep_alive_max_count(size_t count);

  void set_basic_auth(const char *username, const char *password);

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void set_digest_auth(const char *username, const char *password);
#endif

  void set_follow_location(bool on);

  void set_compress(bool on);

  void set_interface(const char *intf);

  void set_proxy(const char *host, int port);

  void set_proxy_basic_auth(const char *username, const char *password);

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void set_proxy_digest_auth(const char *username, const char *password);
#endif

  void set_logger(Logger logger);

protected:
  bool process_request(Stream &strm, const Request &req, Response &res,
                       bool last_connection, bool &connection_close);

  const std::string host_;
  const int port_;
  const std::string host_and_port_;

  // Settings
  std::string client_cert_path_;
  std::string client_key_path_;

  time_t timeout_sec_ = 300;
  time_t read_timeout_sec_ = CPPHTTPLIB_READ_TIMEOUT_SECOND;
  time_t read_timeout_usec_ = CPPHTTPLIB_READ_TIMEOUT_USECOND;

  size_t keep_alive_max_count_ = CPPHTTPLIB_KEEPALIVE_MAX_COUNT;

  std::string basic_auth_username_;
  std::string basic_auth_password_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  std::string digest_auth_username_;
  std::string digest_auth_password_;
#endif

  bool follow_location_ = false;

  bool compress_ = false;

  std::string interface_;

  std::string proxy_host_;
  int proxy_port_;

  std::string proxy_basic_auth_username_;
  std::string proxy_basic_auth_password_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  std::string proxy_digest_auth_username_;
  std::string proxy_digest_auth_password_;
#endif

  Logger logger_;

  void copy_settings(const Client &rhs) {
    client_cert_path_ = rhs.client_cert_path_;
    client_key_path_ = rhs.client_key_path_;
    timeout_sec_ = rhs.timeout_sec_;
    read_timeout_sec_ = rhs.read_timeout_sec_;
    read_timeout_usec_ = rhs.read_timeout_usec_;
    keep_alive_max_count_ = rhs.keep_alive_max_count_;
    basic_auth_username_ = rhs.basic_auth_username_;
    basic_auth_password_ = rhs.basic_auth_password_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    digest_auth_username_ = rhs.digest_auth_username_;
    digest_auth_password_ = rhs.digest_auth_password_;
#endif
    follow_location_ = rhs.follow_location_;
    compress_ = rhs.compress_;
    interface_ = rhs.interface_;
    proxy_host_ = rhs.proxy_host_;
    proxy_port_ = rhs.proxy_port_;
    proxy_basic_auth_username_ = rhs.proxy_basic_auth_username_;
    proxy_basic_auth_password_ = rhs.proxy_basic_auth_password_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    proxy_digest_auth_username_ = rhs.proxy_digest_auth_username_;
    proxy_digest_auth_password_ = rhs.proxy_digest_auth_password_;
#endif
    logger_ = rhs.logger_;
  }

private:
  //socket_t create_client_socket() const;
  bool read_response_line(Stream &strm, Response &res);
  bool write_request(Stream &strm, const Request &req, bool last_connection);
  bool redirect(const Request &req, Response &res);
  bool handle_request(Stream &strm, const Request &req, Response &res,
                      bool last_connection, bool &connection_close);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  bool connect(socket_t sock, Response &res, bool &error);
#endif

  std::shared_ptr<Response> send_with_content_provider(
      const char *method, const char *path, const Headers &headers,
      const std::string &body, size_t content_length,
      ContentProvider content_provider, const char *content_type);

  //virtual bool process_and_close_socket(
  //    socket_t sock, size_t request_count,
  //    std::function<bool(Stream &strm, bool last_connection,
  //                       bool &connection_close)>
  //        callback);

  virtual bool is_ssl() const;
};

inline void Get(std::vector<Request> &requests, const char *path,
                const Headers &headers) {
  Request req;
  req.method = "GET";
  req.path = path;
  req.headers = headers;
  requests.emplace_back(std::move(req));
}

inline void Get(std::vector<Request> &requests, const char *path) {
  Get(requests, path, Headers());
}

inline void Post(std::vector<Request> &requests, const char *path,
                 const Headers &headers, const std::string &body,
                 const char *content_type) {
  Request req;
  req.method = "POST";
  req.path = path;
  req.headers = headers;
  req.headers.emplace("Content-Type", content_type);
  req.body = body;
  requests.emplace_back(std::move(req));
}

inline void Post(std::vector<Request> &requests, const char *path,
                 const std::string &body, const char *content_type) {
  Post(requests, path, Headers(), body, content_type);
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
class SSLServer : public Server {
public:
  SSLServer(const char *cert_path, const char *private_key_path,
            const char *client_ca_cert_file_path = nullptr,
            const char *client_ca_cert_dir_path = nullptr);

  virtual ~SSLServer();

  virtual bool is_valid() const;

private:
  virtual bool process_and_close_socket(socket_t sock);

  SSL_CTX *ctx_;
  std::mutex ctx_mutex_;
};

class SSLClient : public Client {
public:
  SSLClient(const std::string &host, int port = 443,
            const std::string &client_cert_path = std::string(),
            const std::string &client_key_path = std::string());

  virtual ~SSLClient();

  virtual bool is_valid() const;

  void set_ca_cert_path(const char *ca_ceert_file_path,
                        const char *ca_cert_dir_path = nullptr);

  void enable_server_certificate_verification(bool enabled);

  long get_openssl_verify_result() const;

  SSL_CTX *ssl_context() const noexcept;

private:
  virtual bool process_and_close_socket(
      socket_t sock, size_t request_count,
      std::function<bool(Stream &strm, bool last_connection,
                         bool &connection_close)>
          callback);
  virtual bool is_ssl() const;

  bool verify_host(X509 *server_cert) const;
  bool verify_host_with_subject_alt_name(X509 *server_cert) const;
  bool verify_host_with_common_name(X509 *server_cert) const;
  bool check_host_name(const char *pattern, size_t pattern_len) const;

  SSL_CTX *ctx_;
  std::mutex ctx_mutex_;
  std::vector<std::string> host_components_;

  std::string ca_cert_file_path_;
  std::string ca_cert_dir_path_;
  bool server_certificate_verification_ = false;
  long verify_result_ = 0;
};
#endif

// ----------------------------------------------------------------------------

/*
 * Implementation
 */

namespace detail {

inline bool is_hex(char c, int &v) {
  if (0x20 <= c && isdigit(c)) {
    v = c - '0';
    return true;
  } else if ('A' <= c && c <= 'F') {
    v = c - 'A' + 10;
    return true;
  } else if ('a' <= c && c <= 'f') {
    v = c - 'a' + 10;
    return true;
  }
  return false;
}

inline bool from_hex_to_i(const std::string &s, size_t i, size_t cnt,
                          int &val) {
  if (i >= s.size()) { return false; }

  val = 0;
  for (; cnt; i++, cnt--) {
    if (!s[i]) { return false; }
    int v = 0;
    if (is_hex(s[i], v)) {
      val = val * 16 + v;
    } else {
      return false;
    }
  }
  return true;
}

inline size_t to_utf8(int code, char *buff) {
  if (code < 0x0080) {
    buff[0] = (code & 0x7F);
    return 1;
  } else if (code < 0x0800) {
    buff[0] = (0xC0 | ((code >> 6) & 0x1F));
    buff[1] = (0x80 | (code & 0x3F));
    return 2;
  } else if (code < 0xD800) {
    buff[0] = (0xE0 | ((code >> 12) & 0xF));
    buff[1] = (0x80 | ((code >> 6) & 0x3F));
    buff[2] = (0x80 | (code & 0x3F));
    return 3;
  } else if (code < 0xE000) { // D800 - DFFF is invalid...
    return 0;
  } else if (code < 0x10000) {
    buff[0] = (0xE0 | ((code >> 12) & 0xF));
    buff[1] = (0x80 | ((code >> 6) & 0x3F));
    buff[2] = (0x80 | (code & 0x3F));
    return 3;
  } else if (code < 0x110000) {
    buff[0] = (0xF0 | ((code >> 18) & 0x7));
    buff[1] = (0x80 | ((code >> 12) & 0x3F));
    buff[2] = (0x80 | ((code >> 6) & 0x3F));
    buff[3] = (0x80 | (code & 0x3F));
    return 4;
  }

  // NOTREACHED
  return 0;
}

// NOTE: This code came up with the following stackoverflow post:
// https://stackoverflow.com/questions/180947/base64-decode-snippet-in-c
inline std::string base64_encode(const std::string &in) {
  static const auto lookup =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string out;
  out.reserve(in.size());

  int val = 0;
  int valb = -6;

  for (uint8_t c : in) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(lookup[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }

  if (valb > -6) { out.push_back(lookup[((val << 8) >> (valb + 8)) & 0x3F]); }

  while (out.size() % 4) {
    out.push_back('=');
  }

  return out;
}

inline bool is_file(const std::string &path) {
  struct stat st;
  return stat(path.c_str(), &st) >= 0 && S_ISREG(st.st_mode);
}

inline bool is_dir(const std::string &path) {
  struct stat st;
  return stat(path.c_str(), &st) >= 0 && S_ISDIR(st.st_mode);
}

inline bool is_valid_path(const std::string &path) {
  size_t level = 0;
  size_t i = 0;

  // Skip slash
  while (i < path.size() && path[i] == '/') {
    i++;
  }

  while (i < path.size()) {
    // Read component
    auto beg = i;
    while (i < path.size() && path[i] != '/') {
      i++;
    }

    auto len = i - beg;
    assert(len > 0);

    if (!path.compare(beg, len, ".")) {
      ;
    } else if (!path.compare(beg, len, "..")) {
      if (level == 0) { return false; }
      level--;
    } else {
      level++;
    }

    // Skip slash
    while (i < path.size() && path[i] == '/') {
      i++;
    }
  }

  return true;
}

inline void read_file(const std::string &path, std::string &out) {
  std::ifstream fs(path, std::ios_base::binary);
  fs.seekg(0, std::ios_base::end);
  auto size = fs.tellg();
  fs.seekg(0);
  out.resize(static_cast<size_t>(size));
  fs.read(&out[0], size);
}

template <class Fn> void split(const char *b, const char *e, char d, Fn fn) {
  int i = 0;
  int beg = 0;

  while (e ? (b + i != e) : (b[i] != '\0')) {
    if (b[i] == d) {
      fn(&b[beg], &b[i]);
      beg = i + 1;
    }
    i++;
  }

  if (i) { fn(&b[beg], &b[i]); }
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
class SSLSocketStream : public Stream {
public:
  SSLSocketStream(socket_t sock, SSL *ssl, time_t read_timeout_sec,
                  time_t read_timeout_usec);
  virtual ~SSLSocketStream();

  bool is_readable() const override;
  bool is_writable() const override;
  int read(char *ptr, size_t size) override;
  int write(const char *ptr, size_t size) override;
  std::string get_remote_addr() const override;

private:
  socket_t sock_;
  SSL *ssl_;
  time_t read_timeout_sec_;
  time_t read_timeout_usec_;
};
#endif

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
inline bool can_compress(const std::string &content_type) {
  return !content_type.find("text/") || content_type == "image/svg+xml" ||
         content_type == "application/javascript" ||
         content_type == "application/json" ||
         content_type == "application/xml" ||
         content_type == "application/xhtml+xml";
}

inline bool compress(std::string &content) {
  z_stream strm;
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;

  auto ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8,
                          Z_DEFAULT_STRATEGY);
  if (ret != Z_OK) { return false; }

  strm.avail_in = content.size();
  strm.next_in =
      const_cast<Bytef *>(reinterpret_cast<const Bytef *>(content.data()));

  std::string compressed;

  std::array<char, 16384> buff{};
  do {
    strm.avail_out = buff.size();
    strm.next_out = reinterpret_cast<Bytef *>(buff.data());
    ret = deflate(&strm, Z_FINISH);
    assert(ret != Z_STREAM_ERROR);
    compressed.append(buff.data(), buff.size() - strm.avail_out);
  } while (strm.avail_out == 0);

  assert(ret == Z_STREAM_END);
  assert(strm.avail_in == 0);

  content.swap(compressed);

  deflateEnd(&strm);
  return true;
}

class decompressor {
public:
  decompressor() {
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    // 15 is the value of wbits, which should be at the maximum possible value
    // to ensure that any gzip stream can be decoded. The offset of 16 specifies
    // that the stream to decompress will be formatted with a gzip wrapper.
    is_valid_ = inflateInit2(&strm, 16 + 15) == Z_OK;
  }

  ~decompressor() { inflateEnd(&strm); }

  bool is_valid() const { return is_valid_; }

  template <typename T>
  bool decompress(const char *data, size_t data_length, T callback) {
    int ret = Z_OK;

    strm.avail_in = data_length;
    strm.next_in = const_cast<Bytef *>(reinterpret_cast<const Bytef *>(data));

    std::array<char, 16384> buff{};
    do {
      strm.avail_out = buff.size();
      strm.next_out = reinterpret_cast<Bytef *>(buff.data());

      ret = inflate(&strm, Z_NO_FLUSH);
      assert(ret != Z_STREAM_ERROR);
      switch (ret) {
      case Z_NEED_DICT:
      case Z_DATA_ERROR:
      case Z_MEM_ERROR: inflateEnd(&strm); return false;
      }

      if (!callback(buff.data(), buff.size() - strm.avail_out)) {
        return false;
      }
    } while (strm.avail_out == 0);

    return ret == Z_OK || ret == Z_STREAM_END;
  }

private:
  bool is_valid_;
  z_stream strm;
};
#endif

inline bool has_header(const Headers &headers, const char *key) {
  return headers.find(key) != headers.end();
}

inline const char *get_header_value(const Headers &headers, const char *key,
                                    size_t id = 0, const char *def = nullptr) {
  auto it = headers.find(key);
  std::advance(it, id);
  if (it != headers.end()) { return it->second.c_str(); }
  return def;
}

inline uint64_t get_header_value_uint64(const Headers &headers, const char *key,
                                        int def = 0) {
  auto it = headers.find(key);
  if (it != headers.end()) {
    return std::strtoull(it->second.data(), nullptr, 10);
  }
  return def;
}

inline bool is_chunked_transfer_encoding(const Headers &headers) {
  return !strcasecmp(get_header_value(headers, "Transfer-Encoding", 0, ""),
                     "chunked");
}

template <typename T>
inline bool redirect(T &cli, const Request &req, Response &res,
                     const std::string &path) {
  Request new_req = req;
  new_req.path = path;
  new_req.redirect_count -= 1;

  Response new_res;

  auto ret = cli.send(new_req, new_res);
  if (ret) { res = new_res; }
  return ret;
}

inline std::string encode_url(const std::string &s) {
  std::string result;

  for (auto i = 0; s[i]; i++) {
    switch (s[i]) {
    case ' ': result += "%20"; break;
    case '+': result += "%2B"; break;
    case '\r': result += "%0D"; break;
    case '\n': result += "%0A"; break;
    case '\'': result += "%27"; break;
    case ',': result += "%2C"; break;
    // case ':': result += "%3A"; break; // ok? probably...
    case ';': result += "%3B"; break;
    default:
      auto c = static_cast<uint8_t>(s[i]);
      if (c >= 0x80) {
        result += '%';
        char hex[4];
        size_t len = snprintf(hex, sizeof(hex) - 1, "%02X", c);
        assert(len == 2);
        result.append(hex, len);
      } else {
        result += s[i];
      }
      break;
    }
  }

  return result;
}

inline std::string decode_url(const std::string &s) {
  std::string result;

  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] == '%' && i + 1 < s.size()) {
      if (s[i + 1] == 'u') {
        int val = 0;
        if (from_hex_to_i(s, i + 2, 4, val)) {
          // 4 digits Unicode codes
          char buff[4];
          size_t len = to_utf8(val, buff);
          if (len > 0) { result.append(buff, len); }
          i += 5; // 'u0000'
        } else {
          result += s[i];
        }
      } else {
        int val = 0;
        if (from_hex_to_i(s, i + 1, 2, val)) {
          // 2 digits hex codes
          result += static_cast<char>(val);
          i += 2; // '00'
        } else {
          result += s[i];
        }
      }
    } else if (s[i] == '+') {
      result += ' ';
    } else {
      result += s[i];
    }
  }

  return result;
}

inline void parse_query_text(const std::string &s, Params &params) {
  split(&s[0], &s[s.size()], '&', [&](const char *b, const char *e) {
    std::string key;
    std::string val;
    split(b, e, '=', [&](const char *b, const char *e) {
      if (key.empty()) {
        key.assign(b, e);
      } else {
        val.assign(b, e);
      }
    });
    params.emplace(key, decode_url(val));
  });
}

inline bool parse_multipart_boundary(const std::string &content_type,
                                     std::string &boundary) {
  auto pos = content_type.find("boundary=");
  if (pos == std::string::npos) { return false; }

  boundary = content_type.substr(pos + 9);
  return true;
}

inline bool parse_range_header(const std::string &s, Ranges &ranges) {
  static auto re_first_range = std::regex(R"(bytes=(\d*-\d*(?:,\s*\d*-\d*)*))");
  std::smatch m;
  if (std::regex_match(s, m, re_first_range)) {
    auto pos = m.position(1);
    auto len = m.length(1);
    bool all_valid_ranges = true;
    split(&s[pos], &s[pos + len], ',', [&](const char *b, const char *e) {
      if (!all_valid_ranges) return;
      static auto re_another_range = std::regex(R"(\s*(\d*)-(\d*))");
      std::cmatch m;
      if (std::regex_match(b, e, m, re_another_range)) {
        ssize_t first = -1;
        if (!m.str(1).empty()) {
          first = static_cast<ssize_t>(std::stoll(m.str(1)));
        }

        ssize_t last = -1;
        if (!m.str(2).empty()) {
          last = static_cast<ssize_t>(std::stoll(m.str(2)));
        }

        if (first != -1 && last != -1 && first > last) {
          all_valid_ranges = false;
          return;
        }
        ranges.emplace_back(std::make_pair(first, last));
      }
    });
    return all_valid_ranges;
  }
  return false;
}

class MultipartFormDataParser {
public:
  MultipartFormDataParser() {}

  void set_boundary(const std::string &boundary) { boundary_ = boundary; }

  bool is_valid() const { return is_valid_; }

  template <typename T, typename U>
  bool parse(const char *buf, size_t n, T content_callback, U header_callback) {
    static const std::regex re_content_type(R"(^Content-Type:\s*(.*?)\s*$)",
                                            std::regex_constants::icase);

    static const std::regex re_content_disposition(
        "^Content-Disposition:\\s*form-data;\\s*name=\"(.*?)\"(?:;\\s*filename="
        "\"(.*?)\")?\\s*$",
        std::regex_constants::icase);

    buf_.append(buf, n); // TODO: performance improvement

    while (!buf_.empty()) {
      switch (state_) {
      case 0: { // Initial boundary
        auto pattern = dash_ + boundary_ + crlf_;
        if (pattern.size() > buf_.size()) { return true; }
        auto pos = buf_.find(pattern);
        if (pos != 0) {
          is_done_ = true;
          return false;
        }
        buf_.erase(0, pattern.size());
        off_ += pattern.size();
        state_ = 1;
        break;
      }
      case 1: { // New entry
        clear_file_info();
        state_ = 2;
        break;
      }
      case 2: { // Headers
        auto pos = buf_.find(crlf_);
        while (pos != std::string::npos) {
          // Empty line
          if (pos == 0) {
            if (!header_callback(file_)) {
              is_valid_ = false;
              is_done_ = false;
              return false;
            }
            buf_.erase(0, crlf_.size());
            off_ += crlf_.size();
            state_ = 3;
            break;
          }

          auto header = buf_.substr(0, pos);
          {
            std::smatch m;
            if (std::regex_match(header, m, re_content_type)) {
              file_.content_type = m[1];
            } else if (std::regex_match(header, m, re_content_disposition)) {
              file_.name = m[1];
              file_.filename = m[2];
            }
          }

          buf_.erase(0, pos + crlf_.size());
          off_ += pos + crlf_.size();
          pos = buf_.find(crlf_);
        }
        break;
      }
      case 3: { // Body
        {
          auto pattern = crlf_ + dash_;
          if (pattern.size() > buf_.size()) { return true; }

          auto pos = buf_.find(pattern);
          if (pos == std::string::npos) { pos = buf_.size(); }
          if (!content_callback(buf_.data(), pos)) {
            is_valid_ = false;
            is_done_ = false;
            return false;
          }

          off_ += pos;
          buf_.erase(0, pos);
        }

        {
          auto pattern = crlf_ + dash_ + boundary_;
          if (pattern.size() > buf_.size()) { return true; }

          auto pos = buf_.find(pattern);
          if (pos != std::string::npos) {
            if (!content_callback(buf_.data(), pos)) {
              is_valid_ = false;
              is_done_ = false;
              return false;
            }

            off_ += pos + pattern.size();
            buf_.erase(0, pos + pattern.size());
            state_ = 4;
          } else {
            if (!content_callback(buf_.data(), pattern.size())) {
              is_valid_ = false;
              is_done_ = false;
              return false;
            }

            off_ += pattern.size();
            buf_.erase(0, pattern.size());
          }
        }
        break;
      }
      case 4: { // Boundary
        if (crlf_.size() > buf_.size()) { return true; }
        if (buf_.find(crlf_) == 0) {
          buf_.erase(0, crlf_.size());
          off_ += crlf_.size();
          state_ = 1;
        } else {
          auto pattern = dash_ + crlf_;
          if (pattern.size() > buf_.size()) { return true; }
          if (buf_.find(pattern) == 0) {
            buf_.erase(0, pattern.size());
            off_ += pattern.size();
            is_valid_ = true;
            state_ = 5;
          } else {
            is_done_ = true;
            return true;
          }
        }
        break;
      }
      case 5: { // Done
        is_valid_ = false;
        return false;
      }
      }
    }

    return true;
  }

private:
  void clear_file_info() {
    file_.name.clear();
    file_.filename.clear();
    file_.content_type.clear();
  }

  const std::string dash_ = "--";
  const std::string crlf_ = "\r\n";
  std::string boundary_;

  std::string buf_;
  size_t state_ = 0;
  size_t is_valid_ = false;
  size_t is_done_ = false;
  size_t off_ = 0;
  MultipartFormData file_;
};

inline std::string to_lower(const char *beg, const char *end) {
  std::string out;
  auto it = beg;
  while (it != end) {
    out += static_cast<char>(::tolower(*it));
    it++;
  }
  return out;
}

inline std::string make_multipart_data_boundary() {
  static const char data[] =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  std::random_device seed_gen;
  std::mt19937 engine(seed_gen());

  std::string result = "--cpp-httplib-multipart-data-";

  for (auto i = 0; i < 16; i++) {
    result += data[engine() % (sizeof(data) - 1)];
  }

  return result;
}

inline bool expect_content(const Request &req) {
  if (req.method == "POST" || req.method == "PUT" || req.method == "PATCH" ||
      req.method == "PRI") {
    return true;
  }
  // TODO: check if Content-Length is set
  return false;
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
template <typename CTX, typename Init, typename Update, typename Final>
inline std::string message_digest(const std::string &s, Init init,
                                  Update update, Final final,
                                  size_t digest_length) {
  using namespace std;

  std::vector<unsigned char> md(digest_length, 0);
  CTX ctx;
  init(&ctx);
  update(&ctx, s.data(), s.size());
  final(md.data(), &ctx);

  stringstream ss;
  for (auto c : md) {
    ss << setfill('0') << setw(2) << hex << (unsigned int)c;
  }
  return ss.str();
}

inline std::string MD5(const std::string &s) {
  return message_digest<MD5_CTX>(s, MD5_Init, MD5_Update, MD5_Final,
                                 MD5_DIGEST_LENGTH);
}

inline std::string SHA_256(const std::string &s) {
  return message_digest<SHA256_CTX>(s, SHA256_Init, SHA256_Update, SHA256_Final,
                                    SHA256_DIGEST_LENGTH);
}

inline std::string SHA_512(const std::string &s) {
  return message_digest<SHA512_CTX>(s, SHA512_Init, SHA512_Update, SHA512_Final,
                                    SHA512_DIGEST_LENGTH);
}
#endif

} // namespace detail

// Header utilities
inline std::pair<std::string, std::string> make_range_header(Ranges ranges) {
  std::string field = "bytes=";
  auto i = 0;
  for (auto r : ranges) {
    if (i != 0) { field += ", "; }
    if (r.first != -1) { field += std::to_string(r.first); }
    field += '-';
    if (r.second != -1) { field += std::to_string(r.second); }
    i++;
  }
  return std::make_pair("Range", field);
}

inline std::pair<std::string, std::string>
make_basic_authentication_header(const std::string &username,
                                 const std::string &password,
                                 bool is_proxy = false) {
  auto field = "Basic " + detail::base64_encode(username + ":" + password);
  auto key = is_proxy ? "Proxy-Authorization" : "Authorization";
  return std::make_pair(key, field);
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
inline std::pair<std::string, std::string> make_digest_authentication_header(
    const Request &req, const std::map<std::string, std::string> &auth,
    size_t cnonce_count, const std::string &cnonce, const std::string &username,
    const std::string &password, bool is_proxy = false) {
  using namespace std;

  string nc;
  {
    stringstream ss;
    ss << setfill('0') << setw(8) << hex << cnonce_count;
    nc = ss.str();
  }

  auto qop = auth.at("qop");
  if (qop.find("auth-int") != std::string::npos) {
    qop = "auth-int";
  } else {
    qop = "auth";
  }

  std::string algo = "MD5";
  if (auth.find("algorithm") != auth.end()) { algo = auth.at("algorithm"); }

  string response;
  {
    auto H = algo == "SHA-256"
                 ? detail::SHA_256
                 : algo == "SHA-512" ? detail::SHA_512 : detail::MD5;

    auto A1 = username + ":" + auth.at("realm") + ":" + password;

    auto A2 = req.method + ":" + req.path;
    if (qop == "auth-int") { A2 += ":" + H(req.body); }

    response = H(H(A1) + ":" + auth.at("nonce") + ":" + nc + ":" + cnonce +
                 ":" + qop + ":" + H(A2));
  }

  auto field = "Digest username=\"hello\", realm=\"" + auth.at("realm") +
               "\", nonce=\"" + auth.at("nonce") + "\", uri=\"" + req.path +
               "\", algorithm=" + algo + ", qop=" + qop + ", nc=\"" + nc +
               "\", cnonce=\"" + cnonce + "\", response=\"" + response + "\"";

  auto key = is_proxy ? "Proxy-Authorization" : "Authorization";
  return std::make_pair(key, field);
}
#endif

inline bool parse_www_authenticate(const httplib::Response &res,
                                   std::map<std::string, std::string> &auth,
                                   bool is_proxy) {
  auto key = is_proxy ? "Proxy-Authenticate" : "WWW-Authenticate";
  if (res.has_header(key)) {
    static auto re = std::regex(R"~((?:(?:,\s*)?(.+?)=(?:"(.*?)"|([^,]*))))~");
    auto s = res.get_header_value(key);
    auto pos = s.find(' ');
    if (pos != std::string::npos) {
      auto type = s.substr(0, pos);
      if (type == "Basic") {
        return false;
      } else if (type == "Digest") {
        s = s.substr(pos + 1);
        auto beg = std::sregex_iterator(s.begin(), s.end(), re);
        for (auto i = beg; i != std::sregex_iterator(); ++i) {
          auto m = *i;
          auto key = s.substr(m.position(1), m.length(1));
          auto val = m.length(2) > 0 ? s.substr(m.position(2), m.length(2))
                                     : s.substr(m.position(3), m.length(3));
          auth[key] = val;
        }
        return true;
      }
    }
  }
  return false;
}

// https://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c/440240#answer-440240
inline std::string random_string(size_t length) {
  auto randchar = []() -> char {
    const char charset[] = "0123456789"
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz";
    const size_t max_index = (sizeof(charset) - 1);
    return charset[rand() % max_index];
  };
  std::string str(length, 0);
  std::generate_n(str.begin(), length, randchar);
  return str;
}

// Request implementation
inline bool Request::has_header(const char *key) const {
  return detail::has_header(headers, key);
}

inline std::string Request::get_header_value(const char *key, size_t id) const {
  return detail::get_header_value(headers, key, id, "");
}

inline size_t Request::get_header_value_count(const char *key) const {
  auto r = headers.equal_range(key);
  return std::distance(r.first, r.second);
}

inline void Request::set_header(const char *key, const char *val) {
  headers.emplace(key, val);
}

inline void Request::set_header(const char *key, const std::string &val) {
  headers.emplace(key, val);
}

inline bool Request::has_param(const char *key) const {
  return params.find(key) != params.end();
}

inline std::string Request::get_param_value(const char *key, size_t id) const {
  auto it = params.find(key);
  std::advance(it, id);
  if (it != params.end()) { return it->second; }
  return std::string();
}

inline size_t Request::get_param_value_count(const char *key) const {
  auto r = params.equal_range(key);
  return std::distance(r.first, r.second);
}

inline bool Request::is_multipart_form_data() const {
  const auto &content_type = get_header_value("Content-Type");
  return !content_type.find("multipart/form-data");
}

inline bool Request::has_file(const char *key) const {
  return files.find(key) != files.end();
}

inline MultipartFormData Request::get_file_value(const char *key) const {
  auto it = files.find(key);
  if (it != files.end()) { return it->second; }
  return MultipartFormData();
}

// Response implementation
inline bool Response::has_header(const char *key) const {
  return headers.find(key) != headers.end();
}

inline std::string Response::get_header_value(const char *key,
                                              size_t id) const {
  return detail::get_header_value(headers, key, id, "");
}

inline size_t Response::get_header_value_count(const char *key) const {
  auto r = headers.equal_range(key);
  return std::distance(r.first, r.second);
}

inline void Response::set_header(const char *key, const char *val) {
  headers.emplace(key, val);
}

inline void Response::set_header(const char *key, const std::string &val) {
  headers.emplace(key, val);
}

inline void Response::set_redirect(const char *url) {
  set_header("Location", url);
  status = 302;
}

inline void Response::set_content(const char *s, size_t n,
                                  const char *content_type) {
  body.assign(s, n);
  set_header("Content-Type", content_type);
}

inline void Response::set_content(const std::string &s,
                                  const char *content_type) {
  body = s;
  set_header("Content-Type", content_type);
}

inline void Response::set_content_provider(
    size_t length,
    std::function<void(size_t offset, size_t length, DataSink &sink)> provider,
    std::function<void()> resource_releaser) {
  assert(length > 0);
  content_length = length;
  content_provider = [provider](size_t offset, size_t length, DataSink &sink) {
    provider(offset, length, sink);
  };
  content_provider_resource_releaser = resource_releaser;
}

inline void Response::set_chunked_content_provider(
    std::function<void(size_t offset, DataSink &sink)> provider,
    std::function<void()> resource_releaser) {
  content_length = 0;
  content_provider = [provider](size_t offset, size_t, DataSink &sink) {
    provider(offset, sink);
  };
  content_provider_resource_releaser = resource_releaser;
}

/*
 * SSL Implementation
 */
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
namespace detail {

template <typename U, typename V, typename T>
inline bool process_and_close_socket_ssl(
    bool is_client_request, socket_t sock, size_t keep_alive_max_count,
    time_t read_timeout_sec, time_t read_timeout_usec, SSL_CTX *ctx,
    std::mutex &ctx_mutex, U SSL_connect_or_accept, V setup, T callback) {
  assert(keep_alive_max_count > 0);

  SSL *ssl = nullptr;
  {
    std::lock_guard<std::mutex> guard(ctx_mutex);
    ssl = SSL_new(ctx);
  }

  if (!ssl) {
    close_socket(sock);
    return false;
  }

  auto bio = BIO_new_socket(static_cast<int>(sock), BIO_NOCLOSE);
  SSL_set_bio(ssl, bio, bio);

  if (!setup(ssl)) {
    SSL_shutdown(ssl);
    {
      std::lock_guard<std::mutex> guard(ctx_mutex);
      SSL_free(ssl);
    }

    close_socket(sock);
    return false;
  }

  auto ret = false;

  if (SSL_connect_or_accept(ssl) == 1) {
    if (keep_alive_max_count > 1) {
      auto count = keep_alive_max_count;
      while (count > 0 &&
             (is_client_request ||
              detail::select_read(sock, CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND,
                                  CPPHTTPLIB_KEEPALIVE_TIMEOUT_USECOND) > 0)) {
        SSLSocketStream strm(sock, ssl, read_timeout_sec, read_timeout_usec);
        auto last_connection = count == 1;
        auto connection_close = false;

        ret = callback(ssl, strm, last_connection, connection_close);
        if (!ret || connection_close) { break; }

        count--;
      }
    } else {
      SSLSocketStream strm(sock, ssl, read_timeout_sec, read_timeout_usec);
      auto dummy_connection_close = false;
      ret = callback(ssl, strm, true, dummy_connection_close);
    }
  }

  SSL_shutdown(ssl);
  {
    std::lock_guard<std::mutex> guard(ctx_mutex);
    SSL_free(ssl);
  }

  close_socket(sock);

  return ret;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static std::shared_ptr<std::vector<std::mutex>> openSSL_locks_;

class SSLThreadLocks {
public:
  SSLThreadLocks() {
    openSSL_locks_ =
        std::make_shared<std::vector<std::mutex>>(CRYPTO_num_locks());
    CRYPTO_set_locking_callback(locking_callback);
  }

  ~SSLThreadLocks() { CRYPTO_set_locking_callback(nullptr); }

private:
  static void locking_callback(int mode, int type, const char * /*file*/,
                               int /*line*/) {
    auto &locks = *openSSL_locks_;
    if (mode & CRYPTO_LOCK) {
      locks[type].lock();
    } else {
      locks[type].unlock();
    }
  }
};

#endif

class SSLInit {
public:
  SSLInit() {
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
    SSL_load_error_strings();
    SSL_library_init();
#else
    OPENSSL_init_ssl(
        OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif
  }

  ~SSLInit() {
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
    ERR_free_strings();
#endif
  }

private:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  SSLThreadLocks thread_init_;
#endif
};

// SSL socket stream implementation
inline SSLSocketStream::SSLSocketStream(socket_t sock, SSL *ssl,
                                        time_t read_timeout_sec,
                                        time_t read_timeout_usec)
    : sock_(sock), ssl_(ssl), read_timeout_sec_(read_timeout_sec),
      read_timeout_usec_(read_timeout_usec) {}

inline SSLSocketStream::~SSLSocketStream() {}

inline bool SSLSocketStream::is_readable() const {
  return detail::select_read(sock_, read_timeout_sec_, read_timeout_usec_) > 0;
}

inline bool SSLSocketStream::is_writable() const {
  return detail::select_write(sock_, 0, 0) > 0;
}

inline int SSLSocketStream::read(char *ptr, size_t size) {
  if (SSL_pending(ssl_) > 0 ||
      select_read(sock_, read_timeout_sec_, read_timeout_usec_) > 0) {
    return SSL_read(ssl_, ptr, static_cast<int>(size));
  }
  return -1;
}

inline int SSLSocketStream::write(const char *ptr, size_t size) {
  if (is_writable()) { return SSL_write(ssl_, ptr, static_cast<int>(size)); }
  return -1;
}

inline std::string SSLSocketStream::get_remote_addr() const {
  return detail::get_remote_addr(sock_);
}

static SSLInit sslinit_;

} // namespace detail

// SSL HTTP server implementation
inline SSLServer::SSLServer(const char *cert_path, const char *private_key_path,
                            const char *client_ca_cert_file_path,
                            const char *client_ca_cert_dir_path) {
  ctx_ = SSL_CTX_new(SSLv23_server_method());

  if (ctx_) {
    SSL_CTX_set_options(ctx_,
                        SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                            SSL_OP_NO_COMPRESSION |
                            SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    // auto ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    // SSL_CTX_set_tmp_ecdh(ctx_, ecdh);
    // EC_KEY_free(ecdh);

    if (SSL_CTX_use_certificate_chain_file(ctx_, cert_path) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx_, private_key_path, SSL_FILETYPE_PEM) !=
            1) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    } else if (client_ca_cert_file_path || client_ca_cert_dir_path) {
      // if (client_ca_cert_file_path) {
      //   auto list = SSL_load_client_CA_file(client_ca_cert_file_path);
      //   SSL_CTX_set_client_CA_list(ctx_, list);
      // }

      SSL_CTX_load_verify_locations(ctx_, client_ca_cert_file_path,
                                    client_ca_cert_dir_path);

      SSL_CTX_set_verify(
          ctx_,
          SSL_VERIFY_PEER |
              SSL_VERIFY_FAIL_IF_NO_PEER_CERT, // SSL_VERIFY_CLIENT_ONCE,
          nullptr);
    }
  }
}

inline SSLServer::~SSLServer() {
  if (ctx_) { SSL_CTX_free(ctx_); }
}

inline bool SSLServer::is_valid() const { return ctx_; }

inline bool SSLServer::process_and_close_socket(socket_t sock) {
  return detail::process_and_close_socket_ssl(
      false, sock, keep_alive_max_count_, read_timeout_sec_, read_timeout_usec_,
      ctx_, ctx_mutex_, SSL_accept, [](SSL * /*ssl*/) { return true; },
      [this](SSL *ssl, Stream &strm, bool last_connection,
             bool &connection_close) {
        return process_request(strm, last_connection, connection_close,
                               [&](Request &req) { req.ssl = ssl; });
      });
}

// SSL HTTP client implementation
inline SSLClient::SSLClient(const std::string &host, int port,
                            const std::string &client_cert_path,
                            const std::string &client_key_path)
    : Client(host, port, client_cert_path, client_key_path) {
  ctx_ = SSL_CTX_new(SSLv23_client_method());

  detail::split(&host_[0], &host_[host_.size()], '.',
                [&](const char *b, const char *e) {
                  host_components_.emplace_back(std::string(b, e));
                });
  if (!client_cert_path.empty() && !client_key_path.empty()) {
    if (SSL_CTX_use_certificate_file(ctx_, client_cert_path.c_str(),
                                     SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx_, client_key_path.c_str(),
                                    SSL_FILETYPE_PEM) != 1) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }
}

inline SSLClient::~SSLClient() {
  if (ctx_) { SSL_CTX_free(ctx_); }
}

inline bool SSLClient::is_valid() const { return ctx_; }

inline void SSLClient::set_ca_cert_path(const char *ca_cert_file_path,
                                        const char *ca_cert_dir_path) {
  if (ca_cert_file_path) { ca_cert_file_path_ = ca_cert_file_path; }
  if (ca_cert_dir_path) { ca_cert_dir_path_ = ca_cert_dir_path; }
}

inline void SSLClient::enable_server_certificate_verification(bool enabled) {
  server_certificate_verification_ = enabled;
}

inline long SSLClient::get_openssl_verify_result() const {
  return verify_result_;
}

inline SSL_CTX *SSLClient::ssl_context() const noexcept { return ctx_; }

inline bool SSLClient::process_and_close_socket(
    socket_t sock, size_t request_count,
    std::function<bool(Stream &strm, bool last_connection,
                       bool &connection_close)>
        callback) {

  request_count = std::min(request_count, keep_alive_max_count_);

  return is_valid() &&
         detail::process_and_close_socket_ssl(
             true, sock, request_count, read_timeout_sec_, read_timeout_usec_,
             ctx_, ctx_mutex_,
             [&](SSL *ssl) {
               if (ca_cert_file_path_.empty()) {
                 SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
               } else {
                 if (!SSL_CTX_load_verify_locations(
                         ctx_, ca_cert_file_path_.c_str(), nullptr)) {
                   return false;
                 }
                 SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
               }

               if (SSL_connect(ssl) != 1) { return false; }

               if (server_certificate_verification_) {
                 verify_result_ = SSL_get_verify_result(ssl);

                 if (verify_result_ != X509_V_OK) { return false; }

                 auto server_cert = SSL_get_peer_certificate(ssl);

                 if (server_cert == nullptr) { return false; }

                 if (!verify_host(server_cert)) {
                   X509_free(server_cert);
                   return false;
                 }
                 X509_free(server_cert);
               }

               return true;
             },
             [&](SSL *ssl) {
               SSL_set_tlsext_host_name(ssl, host_.c_str());
               return true;
             },
             [&](SSL * /*ssl*/, Stream &strm, bool last_connection,
                 bool &connection_close) {
               return callback(strm, last_connection, connection_close);
             });
}

inline bool SSLClient::is_ssl() const { return true; }

inline bool SSLClient::verify_host(X509 *server_cert) const {
  /* Quote from RFC2818 section 3.1 "Server Identity"

     If a subjectAltName extension of type dNSName is present, that MUST
     be used as the identity. Otherwise, the (most specific) Common Name
     field in the Subject field of the certificate MUST be used. Although
     the use of the Common Name is existing practice, it is deprecated and
     Certification Authorities are encouraged to use the dNSName instead.

     Matching is performed using the matching rules specified by
     [RFC2459].  If more than one identity of a given type is present in
     the certificate (e.g., more than one dNSName name, a match in any one
     of the set is considered acceptable.) Names may contain the wildcard
     character * which is considered to match any single domain name
     component or component fragment. E.g., *.a.com matches foo.a.com but
     not bar.foo.a.com. f*.com matches foo.com but not bar.com.

     In some cases, the URI is specified as an IP address rather than a
     hostname. In this case, the iPAddress subjectAltName must be present
     in the certificate and must exactly match the IP in the URI.

  */
  return verify_host_with_subject_alt_name(server_cert) ||
         verify_host_with_common_name(server_cert);
}

inline bool
SSLClient::verify_host_with_subject_alt_name(X509 *server_cert) const {
  auto ret = false;

  auto type = GEN_DNS;

  struct in6_addr addr6;
  struct in_addr addr;
  size_t addr_len = 0;

#ifndef __MINGW32__
  if (inet_pton(AF_INET6, host_.c_str(), &addr6)) {
    type = GEN_IPADD;
    addr_len = sizeof(struct in6_addr);
  } else if (inet_pton(AF_INET, host_.c_str(), &addr)) {
    type = GEN_IPADD;
    addr_len = sizeof(struct in_addr);
  }
#endif

  auto alt_names = static_cast<const struct stack_st_GENERAL_NAME *>(
      X509_get_ext_d2i(server_cert, NID_subject_alt_name, nullptr, nullptr));

  if (alt_names) {
    auto dsn_matched = false;
    auto ip_mached = false;

    auto count = sk_GENERAL_NAME_num(alt_names);

    for (auto i = 0; i < count && !dsn_matched; i++) {
      auto val = sk_GENERAL_NAME_value(alt_names, i);
      if (val->type == type) {
        auto name = (const char *)ASN1_STRING_get0_data(val->d.ia5);
        auto name_len = (size_t)ASN1_STRING_length(val->d.ia5);

        if (strlen(name) == name_len) {
          switch (type) {
          case GEN_DNS: dsn_matched = check_host_name(name, name_len); break;

          case GEN_IPADD:
            if (!memcmp(&addr6, name, addr_len) ||
                !memcmp(&addr, name, addr_len)) {
              ip_mached = true;
            }
            break;
          }
        }
      }
    }

    if (dsn_matched || ip_mached) { ret = true; }
  }

  GENERAL_NAMES_free((STACK_OF(GENERAL_NAME) *)alt_names);

  return ret;
}

inline bool SSLClient::verify_host_with_common_name(X509 *server_cert) const {
  const auto subject_name = X509_get_subject_name(server_cert);

  if (subject_name != nullptr) {
    char name[BUFSIZ];
    auto name_len = X509_NAME_get_text_by_NID(subject_name, NID_commonName,
                                              name, sizeof(name));

    if (name_len != -1) { return check_host_name(name, name_len); }
  }

  return false;
}

inline bool SSLClient::check_host_name(const char *pattern,
                                       size_t pattern_len) const {
  if (host_.size() == pattern_len && host_ == pattern) { return true; }

  // Wildcard match
  // https://bugs.launchpad.net/ubuntu/+source/firefox-3.0/+bug/376484
  std::vector<std::string> pattern_components;
  detail::split(&pattern[0], &pattern[pattern_len], '.',
                [&](const char *b, const char *e) {
                  pattern_components.emplace_back(std::string(b, e));
                });

  if (host_components_.size() != pattern_components.size()) { return false; }

  auto itr = pattern_components.begin();
  for (const auto &h : host_components_) {
    auto &p = *itr;
    if (p != h && p != "*") {
      auto partial_match = (p.size() > 0 && p[p.size() - 1] == '*' &&
                            !p.compare(0, p.size() - 1, h));
      if (!partial_match) { return false; }
    }
    ++itr;
  }

  return true;
}
#endif

// ----------------------------------------------------------------------------

} // namespace httplib

#endif // CPPHTTPLIB_HTTPLIB_H
