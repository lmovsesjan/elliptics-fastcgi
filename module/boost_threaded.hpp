/** @file threads/boost_threaded.hpp */

#ifndef YANDEX_COMMON_BOOST_THREADED_HPP_INCLUDED
#define YANDEX_COMMON_BOOST_THREADED_HPP_INCLUDED

#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>
#include <boost/function.hpp>

#include "resource.hpp"
#include "scoped_lock.hpp"
#include "threading_traits.hpp"

namespace yandex {
namespace common {

class boost_threaded_monitor {

public:
	boost_threaded_monitor();
	virtual ~boost_threaded_monitor();

	void wait();
	bool timed_wait(unsigned int sec, unsigned int nanos);

	void notify();
	void notify_all();

private:
	boost_threaded_monitor(boost_threaded_monitor const &);
	boost_threaded_monitor& operator = (boost_threaded_monitor &);
	friend class scoped_lock<boost_threaded_monitor>;

	void lock();
	void unlock();
	
private:
	boost::mutex mutex_;
	boost::condition cond_;
	boost::mutex::scoped_lock lock_;
};

struct boost_threading_traits : public threading_traits {

	typedef boost::mutex mutex;
	typedef boost::mutex::scoped_lock scoped_lock;
	
	typedef boost_threaded_monitor monitor;
	typedef yandex::common::scoped_lock<boost_threaded_monitor> synchronized;
	
	typedef resource<boost::thread*> thread_ptr;
	static thread_ptr create_thread(thread_function f, void *arg);
};

inline 
boost_threaded_monitor::boost_threaded_monitor() :
	mutex_(), cond_(), lock_(mutex_)
{
}

inline 
boost_threaded_monitor::~boost_threaded_monitor() {
}

inline void
boost_threaded_monitor::wait() {
	cond_.wait(lock_);
}

inline bool
boost_threaded_monitor::timed_wait(unsigned int sec, unsigned int nanos) {
	boost::xtime xtm = { sec, nanos };
	return cond_.timed_wait(lock_, xtm);
}

inline void
boost_threaded_monitor::notify() {
	cond_.notify_one();
}

inline void
boost_threaded_monitor::notify_all() {
	cond_.notify_all();
}

inline void 
boost_threaded_monitor::lock() {
	lock_.lock();
}

inline void
boost_threaded_monitor::unlock() {
	lock_.unlock();
}

inline boost_threading_traits::thread_ptr
boost_threading_traits::create_thread(boost_threading_traits::thread_function f, void *arg) {
	return thread_ptr(new boost::thread(boost::bind(f, arg)));
}

} // namespace common
} // namespace yandex

#endif // YANDEX_COMMON_BOOST_THREADED_HPP_INCLUDED
