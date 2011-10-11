AC_DEFUN([AC_CHECK_ELLIPTICS],[
AC_MSG_CHECKING([whether Elliptics version is installed])
ELLIPTICS_LIBS="-lelliptics_cpp"
ac_have_elliptics="no"

AC_ARG_WITH([elliptics-path],
	AC_HELP_STRING([--with-elliptics-path=@<:@ARG@:>@],
		[Build with the different path to Elliptics (ARG=string)]),
	[
		ELLIPTICS_LIBS="-L$withval/lib -lelliptics_cpp"
		ELLIPTICS_CFLAGS="-I$withval/include"
	],
	[
		ELLIPTICS_LIBS="-lelliptics_cpp"
	]
)

saved_CFLAGS="$CFLAGS"
saved_LIBS="$LIBS"
LIBS="$ELLIPTICS_LIBS $LIBS"
CFLAGS="$ELLIPTICS_CFLAGS $CFLAGS"

AC_CHECK_LIB([elliptics_cpp], [exit],
	[
		AC_DEFINE(HAVE_ELLIPTICS_SUPPORT, 1, [Define this if Ellipitcs is installed])
		ac_have_elliptics="yes"
		AC_MSG_RESULT([yes])
        ],
        [
		AC_MSG_ERROR([Elliptics was not found. See http://elliptics.ru/])
		AC_MSG_RESULT([no])
	])

AC_SUBST(ELLIPTICS_LIBS)
AC_SUBST(ELLIPTICS_CFLAGS)
LIBS="$saved_LIBS"
CFLAGS="$saved_CFLAGS"
AM_CONDITIONAL(HAVE_ELLIPTICS, [test "f$ac_have_elliptics" = "fyes"])
])

