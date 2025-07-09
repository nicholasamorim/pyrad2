.PHONY: all call-submake

ARGS ?=

mypy: 
	uv run mypy pyrad2 $(ARGS)

test:
	uv run pytest --cov=pyrad2 --cov-report=term tests/ $(ARGS)


serve_docs:
	uv run mkdocs serve
	
deploy_docs:
	uv run mkdocs gh-deploy

status:
	PYTHONPATH=. uv run examples/status.py

server:
	PYTHONPATH=. uv run examples/server.py

server_async:
	PYTHONPATH=. uv run examples/server_async.py

server_radsec:
	PYTHONPATH=. uv run examples/server_radsec.py

server_coa:
	PYTHONPATH=. uv run examples/server_coa.py 3799

#
# RADIUS Client 
#
auth:
	PYTHONPATH=. uv run examples/auth.py

auth_radsec:
	PYTHONPATH=. uv run examples/auth_radsec.py

auth_async:
	PYTHONPATH=. uv run examples/auth_async.py

acct:
	PYTHONPATH=. uv run examples/acct.py

acct_radsec:
	PYTHONPATH=. uv run examples/acct_radsec.py

coa:
	PYTHONPATH=. uv run examples/client_coa.py coa daemon-1234


