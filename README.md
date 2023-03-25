# Cuckoo Hash Table in eBPF
Simple implementation of a cuckoo hash table in eBPF

## Requirements
- Linux kernel 5.17 or newer (needed for the `bpf_loop` helper)
- clang 12 or newer (tested with Clang 16)
- libbpf (and its dependencies)
- bpftool (and its dependencies)

## Build
First, you need to make sure that you cloned the repository with the `--recursive` flag, otherwise you need to run `git submodule update --init --recursive` to fetch the libbpf submodule.

Then, you can build the project with:
```
# cd src
# make
```

## Library structure
The library is in a single header file, `cuckoo_hash.h`, which you can include in your project.
You need to copy the entire lib folder in your project to use the library, since we rely on other headers files in the lib folder.

The source code of the cuckoo hash is in [`src/ebpf/lib/cuckoo_hash.c`](./src/ebpf/lib/cuckoo_hash.h).

## Usage
After including the header file, you need to define the `cuckoo` hash table using the following macro:

`BPF_CUCKOO_HASH(_name, _key_type, _leaf_type, _max_entries)`

You can check the [example](./src/ebpf/cuckoo_test.bpf.c) for reference.

After defining the hash table, you can use the following functions to interact with it:

- `_name##_cuckoo_insert` to insert a new entry in the table
- `_name##_cuckoo_lookup` to lookup an entry in the table
- `_name##_cuckoo_delete` to delete an entry from the table

## Additional information
The cuckoo hash table is implemented using a single struct of type `struct cuckoo_hash_map` (defined in the header file), which contains two additional arrays of `struct cuckoo_hash_table` (also defined in the header file).
You can use your custom key type and value type in the table.

*Note*: please use a table size that is a power of two, otherwise the code will not work properly.

## Run tests
You can check if the library works by running the tests:
```
# cd src
# make test
```

This will run the `cuckoo_test` program, which will try different operations on the table and it will report the results.

## License
This project is licensed under the Apache License 2.0 - see the [LICENSE](./LICENSE) file for details.