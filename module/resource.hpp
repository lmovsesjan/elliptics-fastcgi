/** @file resource.hpp */

#ifndef YANDEX_COMMON_RESOURCE_HPP_INCLUDED
#define YANDEX_COMMON_RESOURCE_HPP_INCLUDED

#include <cassert>
#include <algorithm>
#include <functional>

namespace yandex {
namespace common {
namespace detail {

template <typename Resource, typename Type>
struct pointer_access {
};

template <typename Resource, typename Type>
struct pointer_access<Resource, Type*> {
	Type* operator -> () const;
};

} // namespace details

template <typename Type>
struct resource_traits {
	static Type default_value();
	static void destroy_resource(Type value);
};

template <typename Type>
struct resource_traits<Type*> {
	static Type* default_value();
	static void destroy_resource(Type *value);
};

template <typename Type, typename Traits = resource_traits<Type> >
class resource : public detail::pointer_access<resource<Type, Traits>, Type> {

public:
	resource();
	explicit resource(Type value);
	resource(const resource<Type, Traits> &res);
	resource& operator = (const resource<Type, Traits> &res);
	virtual ~resource();

private:
	struct bool_convertible;

public:
	Type get() const;
	Type release() const;
	void reset(Type value);
	operator bool_convertible const* () const;

private:
	mutable Type value_;
};

template <typename Type, typename Traits = resource_traits<Type> >
struct resource_destroyer : public std::unary_function<Type, void> {
	void operator () (Type var) const;
};

namespace detail {

template <typename Resource, typename Type> inline Type*
pointer_access<Resource, Type*>::operator -> () const {
	return static_cast<const Resource*>(this)->get();
}

} // namespace detail

template <typename Type> inline Type*
resource_traits<Type*>::default_value() {
	return static_cast<Type*>(NULL);
}

template <typename Type> inline void 
resource_traits<Type*>::destroy_resource(Type *value) {
	delete value;
}

template <typename Type, typename Traits> inline
resource<Type, Traits>::resource() : 
	value_(Traits::default_value())
{
}

template <typename Type, typename Traits> inline
resource<Type, Traits>::resource(Type value) :
	value_(value)
{
}

template <typename Type, typename Traits> inline
resource<Type, Traits>::resource(const resource<Type, Traits> &res) :
	value_(Traits::default_value())
{
	std::swap(value_, res.value_);
	assert(Traits::default_value() == res.value_);
}

template <typename Type, typename Traits> inline resource<Type, Traits>&
resource<Type, Traits>::operator = (const resource<Type, Traits> &res) {
	if (&res != this) {
		reset(res.release());
		assert(Traits::default_value() == res.get());
	}
	return *this;
}

template <typename Type, typename Traits> inline
resource<Type, Traits>::~resource() {
	reset(Traits::default_value());
}

template <typename Type, typename Traits> inline Type
resource<Type, Traits>::get() const {
	return value_;
}

template <typename Type, typename Traits> inline Type
resource<Type, Traits>::release() const {
	Type tmp = Traits::default_value();
	std::swap(value_, tmp);
	return tmp;
}

template <typename Type, typename Traits> inline void 
resource<Type, Traits>::reset(Type value) {
	if (Traits::default_value() != value_) {
		Traits::destroy_resource(value_);
	}
	value_ = value;
}

template <typename Type, typename Traits> inline
resource<Type, Traits>::operator typename resource<Type, Traits>::bool_convertible const* () const {
	return (bool_convertible const*)(Traits::default_value() != value_);
}

template <typename Type, typename Traits> inline void
resource_destroyer<Type, Traits>::operator () (Type var) const {
	Traits::destroy_resource(var);
}

} // namespace common
} // namespace yandex

#endif // YANDEX_COMMON_RESOURCE_HPP_INCLUDED
