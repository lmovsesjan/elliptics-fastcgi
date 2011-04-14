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

