"""
API Security Testing Module

Comprehensive API security assessment tools based on OWASP API Security Top 10.
Includes REST API fuzzing, GraphQL security testing, and authentication testing.

MITRE ATT&CK Mapping:
- T1190: Exploit Public-Facing Application
- T1212: Exploitation for Credential Access
- T1110: Brute Force

Modules:
- api_fuzzer: OWASP API Security Top 10 testing (BOLA, Broken Auth, SSRF, etc.)
- graphql_scanner: GraphQL-specific security testing (introspection, depth attacks)
"""

from .api_fuzzer import APIFuzzer
from .graphql_scanner import GraphQLScanner

__all__ = ["APIFuzzer", "GraphQLScanner"]
