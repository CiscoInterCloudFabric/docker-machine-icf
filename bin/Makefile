
all: 
	go get -v ./...
	go build -o docker-machine-driver-icf
	cp docker-machine-driver-icf $(dirname `which docker-machine`)
