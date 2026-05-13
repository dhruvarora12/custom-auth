run:
	go run ./cmd/server

build:
	go build -o bin/auth-service ./cmd/server

test:
	go test ./...

lint:
	golangci-lint run

docker-up:
	docker compose up --build

docker-down:
	docker compose down -v
