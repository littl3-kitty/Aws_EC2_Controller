.PHONY: build build-windows build-linux clean deps jenkins-build

build:
	@mkdir -p dist
	go build -ldflags="-s -w" -o dist/aws_control ./cmd/aws-ec2-controller

build-windows:
	@mkdir -p dist
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/aws_control.exe ./cmd/aws-ec2-controller
	@echo "✅ Windows .exe built"

build-linux:
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/aws_control ./cmd/aws-ec2-controller
	@echo "✅ Linux binary built"

clean:
	rm -rf dist/
	rm -f aws_control.exe
	go clean

deps:
	go mod download
	go mod tidy

jenkins-build:
	@mkdir -p dist
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/aws_control.exe ./cmd/aws-ec2-controller
	@ls -lh dist/
