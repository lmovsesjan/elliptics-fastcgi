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

#include "settings.h"

#include "refresher.hpp"

#include <boost/bind.hpp>

namespace elliptics {

Refresher::Refresher(boost::function<void()> f, boost::uint32_t timeout) :
	f_(f),
	timeout_(timeout),
	stopping_(false),
	refreshing_thread_(boost::bind(&Refresher::refreshingThread, this)) {
}

Refresher::~Refresher() {
	stopping_ = true;
	condition_.notify_one();
	refreshing_thread_.join();
}

void
Refresher::refreshingThread() {
	while (!stopping_) {
		boost::mutex::scoped_lock lock(mutex_);
		boost::xtime t;
		boost::xtime_get(&t, boost::TIME_UTC);
		t.sec += timeout_;
		condition_.timed_wait(lock, t);
		if (!stopping_) {
			f_();
		}
	}
}

} // namespace elliptics

