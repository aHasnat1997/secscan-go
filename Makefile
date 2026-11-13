PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DISTDIR ?= dist

.PHONY: all build install test clean uninstall

all: build

build:
	mkdir -p $(DISTDIR)
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(DISTDIR)/secscan .

test:
	go test -v ./...

install: build
	sudo install -m755 $(DISTDIR)/secscan $(BINDIR)/secscan
	@echo "✓ Successfully installed secscan to $(BINDIR)/secscan"
	@secscan --version

uninstall:
	sudo rm -f $(BINDIR)/secscan
	@echo "✓ Removed $(BINDIR)/secscan"

clean:
	rm -rf $(DISTDIR) secscan
