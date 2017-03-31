.PHONY: test

PACKAGES ?= $(shell go list ./... | grep -v /vendor/)

install:
	@hash govendor > /dev/null 2>&1; if [ $$? -ne 0 ]; then \
		go get -u github.com/kardianos/govendor; \
	fi
	govendor sync

embedmd:
	@hash embedmd > /dev/null 2>&1; if [ $$? -ne 0 ]; then \
		go get -u github.com/campoy/embedmd; \
	fi
	embedmd -d *.md

fmt:
	find . -name "*.go" -type f -not -path "./vendor/*" | xargs gofmt -s -w

.PHONY: fmt-check
fmt-check:
	@if git diff --quiet --exit-code; then \
		$(MAKE) fmt && git diff --exit-code || { \
			git checkout .; \
			echo; \
			echo "Please run 'make fmt' and commit the result"; \
			echo; \
			false; } >&2; \
	else { \
		echo; \
		echo "'make fmt-check' cannot be run with unstaged changes"; \
		echo; \
		false; } >&2; \
	fi

test: fmt-check
	for PKG in $(PACKAGES); do go test -v -cover -coverprofile $$GOPATH/src/$$PKG/coverage.txt $$PKG || exit 1; done;

html:
	go tool cover -html=.cover/coverage.txt

vet:
	go vet $(PACKAGES)

errcheck:
	@which errcheck > /dev/null; if [ $$? -ne 0 ]; then \
		go get -u github.com/kisielk/errcheck; \
	fi
	errcheck $(PACKAGES)

lint:
	@which golint > /dev/null; if [ $$? -ne 0 ]; then \
		go get -u github.com/golang/lint/golint; \
	fi
	for PKG in $(PACKAGES); do golint -set_exit_status $$PKG || exit 1; done;

unconvert:
	@which unconvert > /dev/null; if [ $$? -ne 0 ]; then \
		go get -u github.com/mdempsky/unconvert; \
	fi
	for PKG in $(PACKAGES); do unconvert -v $$PKG || exit 1; done;

coverage:
	curl -s https://codecov.io/bash > .codecov && \
	chmod +x .codecov && \
	./.codecov -f .cover/coverage.txt

clean:
	rm -rf .cover
	find . -name "coverage.txt"
