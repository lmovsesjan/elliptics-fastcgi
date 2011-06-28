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
