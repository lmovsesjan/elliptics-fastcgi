AC_DEFUN([AX_BOOST_PROGRAM_OPTIONS],
[
        ax_boost_program_options_stored_ldflags="$LDFLAGS"
        
        AC_REQUIRE([AX_BOOST_PREFIX])
        AX_BOOST_LIB([ax_boost_program_options_lib], [boost_program_options])
        
        LDFLAGS="$ax_boost_program_options_stored_ldflags $BOOST_LDFLAGS -l$ax_boost_program_options_lib"
        
        ax_have_boost_program_options="yes"
        AX_BOOST_HEADER([program_options.hpp], [], [ax_have_boost_program_options="no"])
        
        AC_MSG_CHECKING([trying to link with boost::program_options])
        AC_LINK_IFELSE(
                [ AC_LANG_PROGRAM([#include <boost/program_options.hpp>],
			[boost::program_options::options_description desc("Allowed options");]) ],
                [ AC_MSG_RESULT(yes) ],
                [ AC_MSG_RESULT(no); ax_have_boost_program_options="no" ])
        
        LDFLAGS="$ax_boost_program_options_stored_ldflags"
        
        if test "f$ax_have_boost_program_options" = "fyes"; then
                ifelse([$1], , :, [$1])
                AC_SUBST([BOOST_PROGRAM_OPTIONS_LDFLAGS], ["-l$ax_boost_program_options_lib"])
        else
                ifelse([$2], , :, [$2])
        fi      
])
