export CXX=~/Desktop/tools/android-ndk-r25c/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang++
export CC=~/Desktop/tools/android-ndk-r25c/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang

export OBJCOPY=~/Desktop/tools/android-ndk-r25c/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy
export STRIP=~/Desktop/tools/android-ndk-r25c/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy

$CC TouchLab.c -o TouchLab.so -w -O3 -shared -fPIC
$STRIP --strip-all TouchLab.so
$OBJCOPY --remove-section .eh_frame TouchLab.so

python trans2Char.py TouchLab.so > binso.hpp

$CXX Injector.cpp KDrv.cpp KDrvImpl.cpp $INCS $LIBS $LIB -static-libstdc++ -std=c++17 -w -O3 -o Injector.elf


