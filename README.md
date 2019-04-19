SaBRe is a modular selective binary rewriter.
It is able to rewrite system calls, vDSO and named functions.
We currently support two architectures: `x86_64` and `RISC-V`.
We provide three plugins:
* *sbr-id*: intercepts system calls but does not do any processing -- mainly aimed at testing
* *sbr-trace*: a fast system-call tracer that mimics the original `strace` output
* *sbr-scfuzzer*: a parametric fault injector to fuzz system calls

# Building SaBRe

## Quick start and requirements

SaBRe execution does not rely on any third-party library.
However, SaBRe requires `cmake`, `make` and `gcc` for building.
To quickly get started, run:

```bash
git clone https://github.com/srg-imperial/SaBRe
cd SaBRe
mkdir build
cd build 
cmake ..
make
```

The executable will be located at `./sabre` assuming you are in the build
directory you just created.
The compiled plugins will lie in separate subfolders under `plugins/`.
For instance, to run the `ls` command under the `sbr-trace` plugin:

```bash
./sabre plugins/sbr-trace/libsbr-trace.so -- /bin/ls
```

___


## Compiling SaBRe executable

`gcc` is recommended for compiling SaBRe.
Also the build system uses `cmake` and `make`. 
So if you do not have them installed, use your package manager, e.g. for Debian/Ubuntu:

```bash
sudo apt install cmake make gcc
```

You can [download a sapshot of the repository](https://github.com/srg-imperial/SaBRe/archive/master.zip) or clone it if you have `git` installed:

```bash
git clone https://github.com/srg-imperial/SaBRe
```

The following build instructions assume that you are currently in the top level directory
of your copy of the SaBRe repository:

```bash
cd SaBRe
mkdir build
cd build
cmake ..
make
```

The sequel assumes the working directory is still `build/`.
If everything goes well, the executable will be located at `./sabre`.

## Running SaBRe

The general syntax to invoke SaBRe is:

```
SaBRe <PLUGIN> [<PLUGIN_OPTIONS>] <CLIENT> [<CLIENT_OPTIONS>]
```

Both `PLUGIN` and `CLIENT` denote full paths to, respectively, the plugin library and the client program to be run under SaBRe.
Once built, plugin libraries are located in separate subfolders under `plugins/`.
For instance, the path to the `sbr-trace` library is: `plugins/sbr-trace/libsbr-trace.so`.
As a full working example, if you want to execute the `ls` command under the `sbr-trace` plugin, just run:

```bash
./sabre plugins/sbr-trace/libsbr-trace.so -- /bin/ls
```
___


