#!/bin/bash

export ARCH=arm64
export ALLOW_UNSAFE_WARNINGS=1
mkdir out

BUILD_CROSS_COMPILE=$(pwd)/toolchain/bin/aarch64-linux-android-
KERNEL_MAKE_ENV="DTC_EXT=$(pwd)/tools/dtc CONFIG_BUILD_ARM64_DT_OVERLAY=y"

make -j16 -C $(pwd) O=$(pwd)/out $KERNEL_MAKE_ENV ARCH=arm64 CROSS_COMPILE=$BUILD_CROSS_COMPILE a02q_defconfig
make -j16 -C $(pwd) O=$(pwd)/out $KERNEL_MAKE_ENV ARCH=arm64 CROSS_COMPILE=$BUILD_CROSS_COMPILE
 
cp out/arch/arm64/boot/Image $(pwd)/arch/arm64/boot/Image
