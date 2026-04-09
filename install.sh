#!/bin/bash

# bpftool
pushd . > /dev/null
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
sudo make install
sudo cp /usr/local/sbin/bpftool /usr/local/bin/
popd > /dev/null
rm -rf bpftool/

# llvm-17
wget https://apt.llvm.org/llvm.sh
chmod u+x llvm.sh
sudo ./llvm.sh 17
sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-17 100
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-17 100
sudo update-alternatives --install /usr/bin/llc llc /usr/bin/llc-17 100
