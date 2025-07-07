mypy: 
	uv run mypy pyrad2 $(ARGS)

test:
	uv run pytest --cov=pyrad2 --cov-report=term tests/ $(ARGS)

test_server:
	PYTHONPATH=. uv run examples/server.py

test_server_async:
	PYTHONPATH=. uv run examples/server_async.py

make test_auth:
	PYTHONPATH=. uv run examples/auth_async.py