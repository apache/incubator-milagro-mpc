# Python wrapper

This directory contains the C code wrapper for Python.

## Tests

### Automatic run

The simplest way to run the wrapper tests is using the Makefile
in the build directory or in the python build directory

```sh
make test
```

### Manual run

Individual tests can be executed after installation using

```sh
./test_mta.py
```

To run individual tests manually before installation add
the build `src` directory to your system dynamic library path.

e.g. for Linux

```sh
export LD_LIBRARY_PATH=<build_dir>/src/:$LD_LIBRARY_PATH
```

## Benchmark and examples

Individual benchmarks or examples can be executed after
installation using

```sh
./example_ecdsa.py
```

To run individual benchmarks and examples manually before
installation add the build `src` directory to your system
dynamic library path.

e.g. for Linux

```sh
export LD_LIBRARY_PATH=<build_dir>/src/:$LD_LIBRARY_PATH
```
