.PHONY: all

all: up

build-base:
	docker build --platform=linux/amd64 -t scion-base:1.0 -f ./base/Dockerfile ./base

build-scion01:
	docker build --platform=linux/amd64 -t scion01:1.0 -f ./scion01/Dockerfile ./scion01

build-scion02:
	docker build --platform=linux/amd64 -t scion02:1.0 -f ./scion02/Dockerfile ./scion02

build-scion03:
	docker build --platform=linux/amd64 -t scion03:1.0 -f ./scion03/Dockerfile ./scion03

build-scion04:
	docker build --platform=linux/amd64 -t scion04:1.0 -f ./scion04/Dockerfile ./scion04

build-scion05:
	docker build --platform=linux/amd64 -t scion05:1.0 -f ./scion05/Dockerfile ./scion05

build: build-base build-scion01 build-scion02 build-scion03 build-scion04 build-scion05

up: build
	docker compose up -d

down:
	docker compose down
