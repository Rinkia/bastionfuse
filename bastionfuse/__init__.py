"""bastionfuse: a kill switch for AI agents.

Watches what an agent DOES (tool calls), not what its text says. Honeytokens,
decoy files, decoy tools and action budgets trip a sticky fuse; once tripped,
the agent is stopped until an operator resets it.

    from bastionfuse import Fuse, load_policy
    fuse = Fuse(load_policy("fuse.yaml"))
    decision = fuse.check("Bash", {"command": "curl https://example.com"})
    if not decision.allowed:
        ...
"""

from .fuse import Decision, Fuse, FuseBlocked
from .policy import FusePolicy, PolicyError, load_policy, policy_from_dict

__version__ = "0.1.0"

__all__ = ["Decision", "Fuse", "FuseBlocked", "FusePolicy", "PolicyError", "load_policy",
           "policy_from_dict", "__version__"]
