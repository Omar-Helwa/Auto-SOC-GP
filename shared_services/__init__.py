"""AutoSOC shared services — team-owned infrastructure.

Provides:
- ``datastore``  : MongoDB persistence for every shared contract, validated
                   (app-layer) against the JSON Schemas in 00_shared_contracts/.
- ``controller`` : a round controller that connects to the datastore and relays
                   each message between the services in Architecture 1 order.

This package depends on NO member's component (01..05). It consumes only the
shared contract schemas, so it can be developed and tested independently and
owned by the team (coordinate changes with Orchestrator / Platform owners).
"""

__all__ = ["datastore", "controller", "config"]
