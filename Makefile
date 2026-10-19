.PHONY: all bootstrap up down test e2e demo

all: test

bootstrap:
	./dev/bootstrap.sh

up:
	docker compose -f deploy/compose.yaml up -d

down:
	docker compose -f deploy/compose.yaml down

test:
	cargo test --manifest-path signer/Cargo.toml
	cargo test --manifest-path tools/pe-sim/Cargo.toml --offline
	cd api && go test ./...
	python3 dev/crosscheck_jcs.py
	python3 dev/crosscheck_derive.py

e2e:
	./dev/demo.sh

demo:
	./dev/demo.sh


