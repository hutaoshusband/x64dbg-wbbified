# issue3803

Regression test for x64dbg issue #3803.

This test now covers the cleaned-up setter split:

- scalar assignment APIs reject raw whole-register destinations such as `_K0` and `_ZMM0` instead of treating integers as pointers;
- raw whole-register writes still work through `DbgValSetBuffer` with exact-size buffers;
- expression/command paths like `_K0=5`, `_ZMM0=5`, `mov _K0, 5`, and `mov _ZMM0, 5` fail cleanly instead of creating variables or crashing.

The assertions are implemented in `plugin.cpp`, which exercises both the command layer and the new bridge setter APIs on x64 and x86. The ZMM verification checks the low lane through `vmovdqu`, which keeps the test reliable on hosts without AVX-512 hardware where only the AVX subset is preserved.

The separate `registers` scenario retains that original regression and adds an executed register reference. The source-built MASM target loads known general/flag/MXCSR and XMM values, optionally full YMM values after CPUID/XCR0 admission, and stores them itself after the exported stop. It preserves the caller's nonvolatile registers and original floating-point context. The x64 frame includes unwind metadata for saved nonvolatile general and XMM registers.

Four fresh sessions in the same native script check available SIMD and SSE only, each before and after actual debugger mutations. The target validates the stored results and exits 69 for baseline or 70 for mutation. Its child-only normal mode prints the actual stored values for the shared independent checker. The default mode retains its original short sleep and zero exit. This establishes general/arithmetic flag/MXCSR/SSE/AVX references on the current host; x87/MMX, AVX-512/opmask and remaining register validity gates are still open.
