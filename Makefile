# RefineID Unix Makefile

CARGO ?= cargo

.PHONY: default help build check clean distclean package-deb install-deb

default: build

help:
	@echo "RefineID for Unix."
	@echo "  make build        -> release build of the whole workspace"
	@echo "  make check        -> build + test + clippy + fmt gate"
	@echo "  make package-deb  -> build Debian/Ubuntu (.deb) packages"
	@echo "  make install-deb  -> package and install .deb via native package manager"
	@echo "  make clean        -> remove build artifacts"
	@echo "  make distclean    -> remove build artifacts and distribution archives"
	@echo ""
	@echo "NixOS users: see doc/install-nixos.md (nix build / NixOS module)."

build:
	$(CARGO) build --release --workspace
	@echo ""
	@echo "built:"
	@echo "  target/release/refineid                 (CLI)"
	@echo "  target/release/refineid-gui             (GUI)"
	@echo "  target/release/librefineid_pkcs11.so    (Firefox/NSS card login)"

package-deb:
	./script/package-deb.sh

install-deb:
	./script/package-deb.sh --install

check:
	./script/check.sh

clean:
	-$(CARGO) clean
	rm -rf target result result-*

distclean: clean
	rm -rf refineid-*.tar*

