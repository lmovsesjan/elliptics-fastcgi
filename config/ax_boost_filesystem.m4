AC_DEFUN([AX_BOOST_FILESYSTEM],
[
        ax_boost_filesystem_stored_ldflags="$LDFLAGS"
        
        AC_REQUIRE([AX_BOOST_PREFIX])
        AX_BOOST_LIB([ax_boost_filesystem_lib], [boost_filesystem])
        
        LDFLAGS="$ax_boost_filesystem_stored_ldflags $BOOST_LDFLAGS -l$ax_boost_filesystem_lib"
        
        ax_have_boost_filesystem="yes"
        AX_BOOST_HEADER([filesystem/path.hpp], [], [ax_have_boost_filesystem="no"])
        
        AC_MSG_CHECKING([trying to link with boost::filesystem])
        AC_LINK_IFELSE(
                [ AC_LANG_PROGRAM([#include <boost/filesystem/path.hpp>], [boost::filesystem::path p;]) ],
                [ AC_MSG_RESULT(yes) ],
                [ AC_MSG_RESULT(no); ax_have_boost_filesystem="no" ])
        
        LDFLAGS="$ax_boost_filesystem_stored_ldflags"
        
        if test "f$ax_have_boost_filesystem" = "fyes"; then
                ifelse([$1], , :, [$1])
                AC_SUBST([BOOST_FILESYSTEM_LDFLAGS], ["-l$ax_boost_filesystem_lib"])
        else
                ifelse([$2], , :, [$2])
        fi      
])
