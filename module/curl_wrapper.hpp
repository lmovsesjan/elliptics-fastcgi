// elliptics-fastcgi - FastCGI-module component for Elliptics file storage
// Copyright (C) 2011 Leonid A. Movsesjan <lmovsesjan@yandex-team.ru>

// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#ifndef YANDEX_COMMON_HTTP_CURL_WRAPPER_HPP_INCLUDED
#define YANDEX_COMMON_HTTP_CURL_WRAPPER_HPP_INCLUDED

#include <string>
#include <sstream>
#include <stdexcept>

#include <curl/curl.h>
#include <openssl/crypto.h>

#include "resource.hpp"
#include "writer.hpp"

namespace yandex {
namespace common {


static pthread_mutex_t *lock_cs;

extern "C" void
pthreads_locking_callback(int mode, int type, const char *file, int line) {
	(void)file;
	(void)line;
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(lock_cs[type]));
	}
	else {
		pthread_mutex_unlock(&(lock_cs[type]));
	}
}

extern "C" unsigned long
pthreads_thread_id(void) {
	return (unsigned long)pthread_self();
}

static void
CRYPTO_thread_setup(void) {
	lock_cs = reinterpret_cast<pthread_mutex_t*>(
		OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t)));
	for (int i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_init(&(lock_cs[i]),NULL);
	}
	CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
	CRYPTO_set_locking_callback(pthreads_locking_callback);
}

static void
CRYPTO_thread_cleanup(void) {
	CRYPTO_set_locking_callback(NULL);
	for (int i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(lock_cs[i]));
	}
	OPENSSL_free(lock_cs);
}

template <> void
resource_traits<CURL*>::destroy_resource(CURL *curl) {
	curl_easy_cleanup(curl);
}

template <> void
resource_traits<curl_slist*>::destroy_resource(curl_slist *list) {
	curl_slist_free_all(list);
}

class single_threaded_threading_traits;

template <typename ThreadingTraits>
class curl_wrapper : private resource<CURL*> {

public:
	curl_wrapper(const char *url);
	curl_wrapper(const std::string &url);
	virtual ~curl_wrapper();

	void url(const char *url);
	void url(const std::string &url);
	void timeout(unsigned short timeout);
#if (LIBCURL_VERSION_MAJOR > 7) || ((LIBCURL_VERSION_MAJOR == 7) && (LIBCURL_VERSION_MINOR >= 16))
	void timeout_ms(unsigned long timeout);
#endif
	
	template <typename T> void setopt(CURLoption opt, T value);
	template <typename T> void header(const char *name, const T &value);
	template <typename T> void header(const std::string &name, const T &value);

	void add_file(const char *name, const char *content_type, const std::string &buf);
	void add_file(const char *name, const char *content_type, const char *buf, size_t buf_size);

	void add_param(const std::string &name, const std::string &value);
	void add_param(const char *name, const char *value);

	template <typename Result> long perform(Result &result, bool throw_exc = true);
	// For multipart post
	template <typename Result> long perform_post(Result &result, bool throw_exc = true);
	// For simple post
	template <typename Result> long perform_post(Result &result, const std::string &buf, bool throw_exc = true);
	template <typename Result> long perform_post(Result &result, const char *buf, size_t buf_size, bool throw_exc = true);

private:
	curl_wrapper(const curl_wrapper &);
	curl_wrapper& operator = (const curl_wrapper &);

	void init();
	void header(const char *value);
	void check_error(CURLcode code) const;
	void check_error(CURLFORMcode code) const;
	
private:
	resource<curl_slist*> headers_;
	curl_httppost *post_;
	curl_httppost *last_;
};

template <typename ThreadingTraits> inline
curl_wrapper<ThreadingTraits>::curl_wrapper(const char *url) :
	resource<CURL*>(curl_easy_init()),
	post_(NULL),
	last_(NULL)
{
	init();
	this->url(url);
}

template <typename ThreadingTraits> inline
curl_wrapper<ThreadingTraits>::curl_wrapper(const std::string &url) :
	resource<CURL*>(curl_easy_init()),
	post_(NULL),
	last_(NULL)
{
	init();
	this->url(url);
}

template <typename ThreadingTraits> inline
curl_wrapper<ThreadingTraits>::~curl_wrapper() {
	curl_formfree(post_);
}

template <typename ThreadingTraits> inline void
curl_wrapper<ThreadingTraits>::url(const char *url) {
	check_error(curl_easy_setopt(get(), CURLOPT_URL, url));
}

template <typename ThreadingTraits> inline void 
curl_wrapper<ThreadingTraits>::url(const std::string &url) {
	this->url(url.c_str());
}

template <typename ThreadingTraits> inline void
curl_wrapper<ThreadingTraits>::timeout(unsigned short timeout) {
	check_error(curl_easy_setopt(get(), CURLOPT_TIMEOUT, static_cast<int>(timeout)));
}

#if (LIBCURL_VERSION_MAJOR > 7) || ((LIBCURL_VERSION_MAJOR == 7) && (LIBCURL_VERSION_MINOR >= 16))
template <typename ThreadingTraits> inline void
curl_wrapper<ThreadingTraits>::timeout_ms(unsigned long timeout) {
	check_error(curl_easy_setopt(get(), CURLOPT_TIMEOUT_MS, static_cast<int>(timeout)));
}
#endif

template <typename ThreadingTraits> template <typename T> inline void
curl_wrapper<ThreadingTraits>::setopt(CURLoption opt, T value) {
	check_error(curl_easy_setopt(get(), opt, value));
}

template <typename ThreadingTraits> template <typename T> inline void
curl_wrapper<ThreadingTraits>::header(const char *name, const T &value) {
	std::stringstream stream;
	stream << name << ": " << value;
	this->header(stream.str().c_str());
}

template <typename ThreadingTraits> template <typename T> inline void
curl_wrapper<ThreadingTraits>::header(const std::string &name, const T &value) {
	std::stringstream stream;
	stream << name << ": " << value;
	this->header(stream.str().c_str());
}

template <typename ThreadingTraits> inline void
curl_wrapper<ThreadingTraits>::add_file(const char *name, const char *content_type, const std::string &buf) {
	add_file(name, content_type, buf.c_str(), buf.length());
}

template <typename ThreadingTraits> inline void
curl_wrapper<ThreadingTraits>::add_file(const char *name, const char *content_type, const char *buf, size_t buf_size) {
	check_error(curl_formadd(&post_, &last_,
		CURLFORM_PTRNAME, name,
		CURLFORM_BUFFER, name,
		CURLFORM_CONTENTTYPE, content_type,
		CURLFORM_BUFFERPTR, buf,
		CURLFORM_BUFFERLENGTH, buf_size,
		CURLFORM_END));
}

template <typename ThreadingTraits> inline void
curl_wrapper<ThreadingTraits>::add_param(const std::string &name, const std::string &value) {
	add_param(name.c_str(), value.c_str());
}

template <typename ThreadingTraits> inline void
curl_wrapper<ThreadingTraits>::add_param(const char *name, const char *value) {
	check_error(curl_formadd(&post_, &last_,
		CURLFORM_PTRNAME, name,
		CURLFORM_PTRCONTENTS, value,
		CURLFORM_END));
}

template <typename ThreadingTraits> template <typename Result> inline long
curl_wrapper<ThreadingTraits>::perform(Result &result, bool throw_exc) {
	long status;

	check_error(curl_easy_setopt(get(), CURLOPT_HTTPHEADER, headers_.get()));

	check_error(curl_easy_setopt(get(), CURLOPT_WRITEDATA, &result));
	check_error(curl_easy_setopt(get(), CURLOPT_WRITEFUNCTION, detail::curl_write));
	
	CURLcode code = curl_easy_perform(get());
	if (throw_exc) {
		check_error(code);
	}
	if (CURLE_OK == code) {
		check_error(curl_easy_getinfo(get(), CURLINFO_HTTP_CODE, &status));
		return status;
	}
	return 0;
}

template <typename ThreadingTraits> template <typename Result> inline long
curl_wrapper<ThreadingTraits>::perform_post(Result &result, bool throw_exc) {
	long status;

	check_error(curl_easy_setopt(get(), CURLOPT_HTTPHEADER, headers_.get()));

	check_error(curl_easy_setopt(get(), CURLOPT_HTTPPOST, post_));

	check_error(curl_easy_setopt(get(), CURLOPT_WRITEDATA, &result));
	check_error(curl_easy_setopt(get(), CURLOPT_WRITEFUNCTION, detail::curl_write));

	CURLcode code = curl_easy_perform(get());
	if (throw_exc) {
		check_error(code);
	}
	if (CURLE_OK == code) {
		check_error(curl_easy_getinfo(get(), CURLINFO_HTTP_CODE, &status));
		return status;
	}
	return 0;
}

template <typename ThreadingTraits> template <typename Result> inline long
curl_wrapper<ThreadingTraits>::perform_post(Result &result, const std::string &buf, bool throw_exc) {
	return perform_post(result, buf.c_str(), buf.length(), throw_exc);
}

template <typename ThreadingTraits> template <typename Result> inline long
curl_wrapper<ThreadingTraits>::perform_post(Result &result, const char *buf, size_t buf_size, bool throw_exc) {
	long status;

	check_error(curl_easy_setopt(get(), CURLOPT_POSTFIELDS, buf));
	check_error(curl_easy_setopt(get(), CURLOPT_POSTFIELDSIZE, buf_size));

	check_error(curl_easy_setopt(get(), CURLOPT_WRITEDATA, &result));
	check_error(curl_easy_setopt(get(), CURLOPT_WRITEFUNCTION, detail::curl_write));

	CURLcode code = curl_easy_perform(get());
	if (throw_exc) {
		check_error(code);
	}
	if (CURLE_OK == code) {
		check_error(curl_easy_getinfo(get(), CURLINFO_HTTP_CODE, &status));
		return status;
	}
	return 0;
}

template <typename ThreadingTraits> inline void
curl_wrapper<ThreadingTraits>::init() {
	check_error(curl_easy_setopt(get(), CURLOPT_NOSIGNAL, 1));
	check_error(curl_easy_setopt(get(), CURLOPT_FORBID_REUSE, 1));
}

template <> inline void
curl_wrapper<single_threaded_threading_traits>::init() {
}

template <typename ThreadingTraits> inline void
curl_wrapper<ThreadingTraits>::header(const char *value) {
	headers_.reset(curl_slist_append(headers_.release(), value));
	if (!headers_) {
		throw std::runtime_error("failed to add curl header");
	}
}

template <typename ThreadingTraits> inline void
curl_wrapper<ThreadingTraits>::check_error(CURLcode code) const {
	if (CURLE_OK != code) {
		throw std::runtime_error(curl_easy_strerror(code));
	}
}

template <typename ThreadingTraits> inline void
curl_wrapper<ThreadingTraits>::check_error(CURLFORMcode code) const {
	if (CURL_FORMADD_OK != code) {
		throw std::runtime_error("CURLFORMcode not CURL_FORMADD_OK");
	}
}

} // namespace common
} // namespace yandex

#endif // YANDEX_COMMON_HTTP_CURL_WRAPPER_HPP_INCLUDED
