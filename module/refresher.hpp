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

