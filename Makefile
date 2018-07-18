BINARY := usb
CMD    := ./cmd/ubuntu-ssh-bootstrap

clean:
	rm -rf $(BINARY)

build:
	dep ensure --vendor-only
	go build -o $(BINARY) $(CMD)

install: build
	$(shell cp ./$(BINARY) /usr/local/bin/ubuntu-ssh-bootstrap)
