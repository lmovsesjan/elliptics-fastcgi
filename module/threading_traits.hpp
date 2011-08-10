/** @file threads/threading_traits.hpp */

#ifndef YANDEX_COMMON_THREADS_THREADING_TRAITS_HPP_INCLUDED
#define YANDEX_COMMON_THREADS_THREADING_TRAITS_HPP_INCLUDED

namespace yandex {
namespace common {

struct threading_traits {

	typedef void (*thread_function)(void*);

};

} // namespace common
} // namespace yandex

#endif // _YANDEX_COMMON_THREADS_THREADING_TRAITS_HPP_INCLUDED_
