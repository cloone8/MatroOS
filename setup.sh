#!/bin/sh

if [[ "$OSTYPE" == *"darwin"* ]]; then
    echo "Detected MacOS"
    VERSION=x86_64-elf-7.3.0-Darwin-x86_64
else
    echo "Detected Linux OS"
    VERSION=x86_64-elf-7.3.0-Linux-x86_64
fi

tar xf ${VERSION}.tar.xz

echo export PATH=$(pwd)/${VERSION}/bin/:$PATH >> .settings
echo export CROSS_COMPILE=x86_64-elf- >> .settings
