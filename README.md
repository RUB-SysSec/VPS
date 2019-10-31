# VTable Pointer Separation (VPS)

This is the repository for the paper [VPS: Excavating High-Level C++ Constructs from Low-Level Binaries to Protect Dynamic Dispatching](https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2019/10/02/ACSAC19-VPS.pdf) published at the Annual Computer Security Applications Conference (ACSAC) 2019.


# Evaluation Data

The data used to evaluate VPS is available at [zenodo.org](https://zenodo.org/record/3523939).


# Artifact VM

A VM with the installed analysis tool is available at [https://file.syssec.rub.de/acsac2019/vps_acsac2019_artifact.ova](https://file.syssec.rub.de/acsac2019/vps_acsac2019_artifact.ova). On the Desktop of the user, there is the file `README.md` with a more detailed explanation of the content of the VM. The user name for this VM is `guy` and if the password is necessary it is `guy`, too.


# IDA Export + SSA

The code for the SSA generation and export of the relevant data to use for the static analysis is available in the `ida_export` directory. However, since it uses `readelf` on the command line, it only works for IDA on Linux. Just execute the `ida_export.py` file inside your IDA instance.


# Static Analysis

The code of the static analysis part as described in Section 4 of the paper is available in the `static_analysis` directory. In the following the installation of the tool is explained (already installed inside the artifact VM). It is built atop of the [Marx](https://github.com/RUB-SysSec/Marx) framework with the analysis passes provided by Marx disabled.


## Installation

If you want to install the tool yourself you can do it with the following steps:

Install requirements.

```bash
guy@vps:~/vps/static_analysis$ sudo apt install cmake libboost-dev libboost-filesystem-dev git automake clang
```

Install and patch VEX.

```bash
guy@vps:~/vps/static_analysis$ git clone git://sourceware.org/git/valgrind.git --single-branch --branch svn/VALGRIND_3_13_BRANCH

guy@vps:~/vps/static_analysis$ cd valgrind/

guy@vps:~/vps/static_analysis/valgrind$ patch -p1 < ../patch/heap_allocation_patch.diff

guy@vps:~/vps/static_analysis/valgrind$ ./autogen.sh

guy@vps:~/vps/static_analysis/valgrind$ ./configure

guy@vps:~/vps/static_analysis/valgrind$ cd VEX/

guy@vps:~/vps/static_analysis/valgrind/VEX$ make

guy@vps:~/vps/static_analysis/valgrind/VEX$ sudo make install
```

Make sure file `/usr/local/lib/valgrind/libvex-amd64-linux.a` exists.

Install protopuf.

```bash
root@vps:~/Desktop# apt install libprotoc10 libprotoc-dev libprotobuf10 libprotobuf-dev protobuf-compiler
```

Compile protobuf file.

```bash
guy@vps:~/vps/static_analysis$ protoc -I=./include/ --cpp_out=./src/ ./include/ssa_export.proto
guy@vps:~/vps/static_analysis$ mv src/ssa_export.pb.h include/
```

Build static analysis.

```bash
guy@vps:~/vps/static_analysis$ mkdir build && cd build
guy@vps:~/vps/static_analysis/build$ cmake ..
guy@vps:~/vps/static_analysis/build$ make
```

Binary should now be available under `/home/guy/vps/static_analysis/build`. Please take a look at the artifact VM to see a more detailed description of the usage.


# Dynamic Analysis

The code for the dynamic analysis as described in Section 4 of the paper is available in the `dynamic_analysis` directory. It is a Pin Tool that can verify virtual callsite candidates. A compiled version is available in the artifact VM.