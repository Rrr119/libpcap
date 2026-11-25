# Filter validation acceptance test

`valid.tsv` contains 50 expressions that must compile successfully.
`invalid.tsv` contains 50 expressions that must fail in `pcap_compile(3PCAP)`.
Each line is tab-separated:

```
name	DLT	snaplen	optimize	expression
```

The special expression value `@empty@` means an empty filter expression.

`valid.golden` is the baseline output: one tab-separated line per valid case
containing the case name and an architecture-independent hexadecimal
encoding of every field of the generated `struct bpf_insn` array.  The test
decodes that representation and compares the result with the generated
program using `memcmp()`, so a passing run also proves that no valid filter
program changed by even one byte.  The golden file was generated from the
libpcap revision before the validation changes.

Run the test from the top-level build directory:

```
testprogs/filtervalidationtest \
    tests/filter-validation/valid.tsv \
    tests/filter-validation/invalid.tsv \
    tests/filter-validation/valid.golden
```

The program is also part of `make check`.  To regenerate the golden file from
a known-good build, run:

```
testprogs/filtervalidationtest -g tests/filter-validation/valid.tsv
```
