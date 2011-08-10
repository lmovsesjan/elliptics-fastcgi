#ifndef YANDEX_COMMON_HTTP_WRITER_HPP_INCLUDED
#define YANDEX_COMMON_HTTP_WRITER_HPP_INCLUDED

namespace yandex {
namespace common {
namespace detail {

static size_t
curl_write(char *ptr, size_t size, size_t nmemb, void *arg) {
	try {
		std::ostream *stream = static_cast<std::ostream*>(arg);
		stream->write(ptr, size * nmemb);
		return (size * nmemb);
	}
	catch(...) {
		return 0;
	}
	return 0;
}

} // namespace detail
} // namespace common
} // namespace yandex

#endif // YANDEX_COMMON_HTTP_WRITER_HPP_INCLUDED
