/** @file threads/guard.hpp */

#ifndef YANDEX_COMMON_SCOPED_LOCK_HPP_INCLUDED
#define YANDEX_COMMON_SCOPED_LOCK_HPP_INCLUDED

namespace yandex {
namespace common {

class single_threaded_mutex;

template <typename Lock>
class scoped_lock {

public:
	scoped_lock(Lock &lock);
	virtual ~scoped_lock();

private:
	scoped_lock(const scoped_lock &);
	scoped_lock& operator = (const scoped_lock &);
	
private:
	Lock &lock_;
};

template <>
class scoped_lock<single_threaded_mutex> {

public:
	scoped_lock(single_threaded_mutex &lock);
	virtual ~scoped_lock();

private:
	scoped_lock(const scoped_lock &);
	scoped_lock& operator = (const scoped_lock &);
};

template <typename Lock> inline
scoped_lock<Lock>::scoped_lock(Lock &lock) : 
	lock_(lock)
{
	lock_.lock();
}

template <typename Lock> inline
scoped_lock<Lock>::~scoped_lock() {
	lock_.unlock();
}

inline
scoped_lock<single_threaded_mutex>::scoped_lock(single_threaded_mutex &)
{
}

inline
scoped_lock<single_threaded_mutex>::~scoped_lock()
{
}

} // namespace common
} // namespace yandex


#endif // YANDEX_COMMON_SCOPED_LOCK_HPP_INCLUDED
