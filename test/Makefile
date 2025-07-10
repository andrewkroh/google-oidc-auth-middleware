.PHONY: test test-unit start stop clean

# Default target
test: test-unit

# Run unit integration tests (no browser required)
test-unit:
	@echo "Running unit integration tests..."
	@if [ ! -f .env ]; then echo "❌ Please create .env file from .env.example"; exit 1; fi
	@docker compose up -d
	@echo "Waiting for services to be ready..."
	@sleep 10
	@INTEG_TEST=1 go test -v -count=1 ./...
	@docker compose down

# Start services for manual testing
start:
	@echo "Starting services for manual testing..."
	@docker compose up -d
	@echo "✅ Services started:"
	@echo "  Protected app: http://localhost/protected"
	@echo "  Unprotected app: http://localhost"
	@echo "  Traefik dashboard: http://localhost:18080"
	@echo ""
	@echo "Run 'make stop' to stop services"

# Stop services
stop:
	@docker compose down

# Clean up everything
clean:
	@docker compose down -v --remove-orphans
	@docker system prune -f
