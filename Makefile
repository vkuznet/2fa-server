VERSION=`git rev-parse --short HEAD`
flags=-ldflags="-s -w -X main.gitVersion=${VERSION}"
odir=`cat ${PKG_CONFIG_PATH}/oci8.pc | grep "libdir=" | sed -e "s,libdir=,,"`

all: build

vet:
	go vet .

build:
	go clean; rm -rf pkg 2fa-server*; go build ${flags}

build_all: build build_osx build_linux build_power8 build_arm64

build_osx:
	go clean; rm -rf pkg 2fa-server_osx; GOOS=darwin go build ${flags}
	mv 2fa-server 2fa-server_osx

build_linux:
	go clean; rm -rf pkg 2fa-server_linux; GOOS=linux go build ${flags}
	mv 2fa-server 2fa-server_linux

build_power8:
	go clean; rm -rf pkg 2fa-server_power8; GOARCH=ppc64le GOOS=linux go build ${flags}
	mv 2fa-server 2fa-server_power8

build_arm64:
	go clean; rm -rf pkg 2fa-server_arm64; GOARCH=arm64 GOOS=linux go build ${flags}
	mv 2fa-server 2fa-server_arm64

install:
	go install

clean:
	go clean; rm -rf pkg
