# This file is Copyright (C) 2014 magnum,
# and is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modifications, are permitted.
#
# All tests in this file are supposed to be cross compile compliant
#
AC_DEFUN([AX_JTR_GENERIC_LOGIC], [
CC_BACKUP=$CC

# Check for -march=native and add it to CPU_BEST_FLAGS
# This should be rewritten for aestethical reasons and readability
if test x${enable_native_tests} = xyes; then
  AC_MSG_CHECKING([whether compiler understands -march=native])
  CC="$CC_BACKUP -march=native"
  AC_LINK_IFELSE(
    [AC_LANG_SOURCE([int main() { return 0; }])],
    [AC_MSG_RESULT(yes)]
    [CPU_BEST_FLAGS="-march=native $CPU_BEST_FLAGS"],
    [AC_MSG_RESULT(no)]
    # or -xarch=native64
    [AC_MSG_CHECKING([whether compiler understands -xarch=native64])
     CC="$CC_BACKUP -xarch=native64"
     AC_LINK_IFELSE(
       [AC_LANG_SOURCE([int main() { return 0; }])],
       [AC_MSG_RESULT(yes)]
       [CPU_BEST_FLAGS="-xarch=native64 $CPU_BEST_FLAGS"],
       [AC_MSG_RESULT(no)]
       # or -xarch=native
       [AC_MSG_CHECKING([whether compiler understands -xarch=native])
	CC="$CC_BACKUP -xarch=native"
	AC_LINK_IFELSE(
	  [AC_LANG_SOURCE([int main() { return 0; }])],
	  [AC_MSG_RESULT(yes)]
	  [CPU_BEST_FLAGS="-xarch=native $CPU_BEST_FLAGS"],
	  [AC_MSG_RESULT(no)]
	  # or "-arch host"
	  [AC_MSG_CHECKING([whether compiler understands -arch host])
	   CC="$CC_BACKUP -arch host"
	   AC_LINK_IFELSE(
	     [AC_LANG_SOURCE([int main() { return 0; }])],
	     [AC_MSG_RESULT(yes)]
	     [CPU_BEST_FLAGS="-arch host $CPU_BEST_FLAGS"],
	     [AC_MSG_RESULT(no)]
	   )
	  ]
	)
       ]
     )
    ]
  )
  CC="$CC_BACKUP"
fi

AC_MSG_CHECKING([for 32/64 bit])
AC_LINK_IFELSE(
   [AC_LANG_SOURCE(
      [extern void exit(int);
      int main() {
      #if defined(_LP64) || defined(__LP64__) || defined(_LLP64) || defined(__LLP64__) || \
        defined(__x86_64) || defined(__x86_64__) || defined(__amd64) || defined(__amd64__) || \
        defined(_M_AMD64) || defined(_M_X64) || defined(WIN64) || \
        defined(__IA64__) || defined(__ia64) || defined(_M_IA64) || \
        defined(__aarch64__) || defined(__ppc64__)
          exit(0);}
      #else
          BORK!
      #endif
      ]
   )]
  ,[CPU_BITS="-m64"]
   [CPU_BIT_STR="64"]
   [AC_MSG_RESULT([64-bit])]
  ,[CPU_BITS="-m32"]
   [CPU_BIT_STR="32"]
   [AC_MSG_RESULT([32-bit])]
)

# At this point we know the arch and CPU width so we can pick details. Most
# "special stuff" from old fat Makefile should go here.
case "$host_cpu" in
   x86_64)
      if test "x$with_icc_asm" = "xyes"; then
         [CFLAGS+=" -DUSING_ICC_S_FILE"]
         [CC_ASM_OBJS="x86-64.o sse-intrinsics-64.o"]
      else
         [CC_ASM_OBJS="x86-64.o sse-intrinsics.o"]
      fi
   ;;
   i?86)
      if test "y$ARCH_LINK" = "yx86-any.h"; then
        [CC_ASM_OBJS="x86.o"]
      elif test "x$with_icc_asm" = "xyes"; then
        [CFLAGS+=" -DUSING_ICC_S_FILE"]
        [CC_ASM_OBJS="x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics-32.o"]
      else
        [CC_ASM_OBJS="x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o"]
      fi
   ;;
   alpha*dec*)
      [CC_ASM_OBJS="digipaq-alpha.o"]
      ;;
   alpha*)
      [CC_ASM_OBJS="alpha.o"]
      ;;
esac

#############################################################################
# ASM_MAGIC code.  Here we add certain 'magic' values. Things like
#  -DUNDERSCORES -DBSD -DALIGN_LOG   (for macosx-x86-*)
#  -DUNDERSCORES -DALIGN_LOG for (dos-djgpp-x86-*)
#  -DUNDERSCORES for cygwin / MinGW / VC
#############################################################################
EXTRA_AS_FLAGS=
AC_MSG_CHECKING([for extra ASFLAGS])
CC="$CC_BACKUP"
CFLAGS_BACKUP=$CFLAGS
CFLAGS="$CFLAGS -O0"
AS_IF([echo "int long_ident;" > conftest.c && ${CC} -c conftest.c && strings - conftest.${OBJEXT} | ${GREP} _long_ident > conftest.out],
      [EXTRA_AS_FLAGS+=" -DUNDERSCORES"])

AC_LINK_IFELSE([AC_LANG_SOURCE(
	[[extern void exit(int);
	int main() {
	#if defined(__APPLE__) && defined(__MACH__)
        exit(0);
    #else
        BORK!
	#endif
	}]])]
  ,[EXTRA_AS_FLAGS+=" -DBSD -DALIGN_LOG"])
AC_MSG_RESULT([$EXTRA_AS_FLAGS])

CC="$CC_BACKUP"
CFLAGS="$CFLAGS_BACKUP"
])
