#!/bin/sh
gcc -v 2>&1 | tail -1
echo ---------------------------------------
for i in 1 2 3 4 5; do
	CPPFLAGS="-DSIMD_PARA_MD4=$i -DSIMD_PARA_MD5=$i -DSIMD_PARA_SHA1=$i -DSIMD_PARA_SHA256=$i -DSIMD_PARA_SHA512=$i -DOMP_SCALE=1"
	./configure CPPFLAGS="$CPPFLAGS" --disable-cuda --disable-opencl >/dev/null || break
	make -s clean || break
	make -sj4 || break
	echo
	echo "===== Speeds for ${i}x interleaving: ====="
	for j in nt md5crypt pbkdf2-hmac-sha1 pbkdf2-hmac-sha256 pbkdf2-hmac-sha512
	do
		../run/john -test -form:$j || break
	done
done
