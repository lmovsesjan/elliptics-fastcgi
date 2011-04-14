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

#ifndef _ELLIPTICS_FASTCGI_REFRESHER_HPP_INCLUDED_
#define _ELLIPTICS_FASTCGI_REFRESHER_HPP_INCLUDED_

#include <boost/function.hpp>
#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>
#include <boost/thread/mutex.hpp>

namespace elliptics {

class Refresher : private boost::noncopyable {

public:
	Refresher(boost::function<void()> f, boost::uint32_t timeout);
	virtual ~Refresher();

private:
	void refreshingThread();

private:
	boost::function<void()> f_;
	boost::uint32_t timeout_;
	volatile bool stopping_;
	boost::condition condition_;
	boost::mutex mutex_;
	boost::thread refreshing_thread_;

};

} // namespace elliptics

#endif // _ELLIPTICS_FASTCGI_REFRESHER_HPP_INCLUDED_

