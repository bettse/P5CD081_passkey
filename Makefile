.PHONY: build test install reinstall uninstall info harness clean

# CAP conversion needs Java 8; the simulator tests need 18+.
JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home
TEST_JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-18.jdk/Contents/Home
READER=ACS ACR1555 1S CL Reader(1)
GP=$(HOME)/bin/gp --reader "$(READER)"

build:
	JAVA_HOME="$(JAVA_HOME)" ant -q

test:
	JAVA_HOME="$(TEST_JAVA_HOME)" ./gradlew test

install: build
	$(GP) --install build/passkey.cap

# gp --install refuses when the package is already loaded, so replace it.
reinstall: build
	-$(GP) --uninstall build/passkey.cap
	$(GP) --install build/passkey.cap

uninstall:
	$(GP) --uninstall build/passkey.cap

info:
	$(GP) -i -l

harness:
	$(MAKE) -C harness

clean:
	JAVA_HOME="$(JAVA_HOME)" ant -q clean
