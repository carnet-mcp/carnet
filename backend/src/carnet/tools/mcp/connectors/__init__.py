"""Vetting manifests, one module per MCP server.

Each exports a `CONNECTOR`. This is the connector-admin surface and it is deliberately
not self-serve: adding a server is a reviewed code change, while creating an agent
that uses one is a form.
"""
