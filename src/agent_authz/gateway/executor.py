"""Private executor for registered, canonical sandbox calls."""

from ..sandbox.environment import SandboxEnvironment
from .models import Invocation, ToolData
from .registry import TOOL_REGISTRY


class _Executor:
    def __init__(self, sandbox: SandboxEnvironment) -> None:
        self._sandbox = sandbox

    def execute(self, invocation: Invocation) -> ToolData:
        spec = TOOL_REGISTRY[invocation.tool]
        return spec.handler(self._sandbox, **dict(invocation.arguments))
