# Zero Trust Auth Gateway

A defensive reference implementation for short-lived signed tokens, route scopes, replay protection, rate limits and audit events.

## Run

```bash
python gateway.py
python -m unittest
```

Uses the Python standard library. This is a learning prototype; production deployments need a reviewed identity provider and key management.
