SHELL:=$(shell /usr/bin/env which bash)
RS_CHECK_TOOLCHAIN:=nightly-2025-06-28
CARGO_RS_CHECK_TOOLCHAIN:=+$(RS_CHECK_TOOLCHAIN)
BENCH_OP_FLAVOR?=DEFAULT
# This is done to avoid forgetting it, we still precise the RUSTFLAGS in the commands to be able to
# copy paste the command in the terminal and change them if required without forgetting the flags
export RUSTFLAGS?=-C target-cpu=native

.PHONY: install_rs_check_toolchain # Install the toolchain used for checks
install_rs_check_toolchain:
	@rustup toolchain list | grep -q "$(RS_CHECK_TOOLCHAIN)" || \
	rustup toolchain install --profile default "$(RS_CHECK_TOOLCHAIN)" || \
	( echo "Unable to install $(RS_CHECK_TOOLCHAIN) toolchain, check your rustup installation. \
	Rustup can be downloaded at https://rustup.rs/" && exit 1 )

.PHONY: bench_fixed # Run benchmarks for unsigned fixed-point numbers
bench_fixed: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench fixed-bench \

.PHONY: bench_fixed_signed # Run benchmarks for signed fixed-point numbers
bench_fixed_signed: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench fixed-bench-signed \