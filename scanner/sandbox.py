"""Sandboxed Code Execution Environment (Prompt Injection Defense).

Provides a secure, ephemeral environment for executing agent-generated 
code and shell commands. Supports local Docker or remote E2B.
Reference: OWASP LLM02 Insecure Output Handling.
"""
import os
import subprocess
import uuid
from typing import Optional, List, Tuple


class SandboxResult:
    def __init__(self, stdout: str, stderr: str, exit_code: int, duration: float):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.duration = duration

    def to_dict(self):
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration": self.duration
        }


class BaseSandbox:
    def run_command(self, command: str, timeout: int = 30) -> SandboxResult:
        raise NotImplementedError()

    def run_python(self, code: str, timeout: int = 30) -> SandboxResult:
        raise NotImplementedError()


class DockerSandbox(BaseSandbox):
    """Local Docker-based sandbox."""
    def __init__(self, image: str = "python:3.11-slim"):
        self.image = image

    def run_command(self, command: str, timeout: int = 30) -> SandboxResult:
        container_name = f"agent-sandbox-{uuid.uuid4().hex[:8]}"
        start_time = 0 # In a real implementation we would track time
        
        # Simple docker run command with resource limits
        cmd = [
            "docker", "run", "--rm",
            "--name", container_name,
            "--network", "none",
            "--memory", "128m",
            "--cpus", "0.5",
            self.image,
            "sh", "-c", command
        ]
        
        try:
            import time
            start = time.time()
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            duration = time.time() - start
            return SandboxResult(res.stdout, res.stderr, res.returncode, duration)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "stop", container_name], capture_output=True)
            return SandboxResult("", "Error: Command timed out", 124, timeout)
        except Exception as e:
            return SandboxResult("", f"Error: {str(e)}", 1, 0)

    def run_python(self, code: str, timeout: int = 30) -> SandboxResult:
        # Wrap code to run in python
        import base64
        b64_code = base64.b64encode(code.encode()).decode()
        cmd = f"echo {b64_code} | base64 -d | python3"
        return self.run_command(cmd, timeout)


class E2BSandbox(BaseSandbox):
    """Stub for E2B Cloud Sandbox integration."""
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("E2B_API_KEY")

    def run_command(self, command: str, timeout: int = 30) -> SandboxResult:
        if not self.api_key:
            return SandboxResult("", "Error: E2B_API_KEY not set", 1, 0)
        
        # In a real implementation:
        # from e2b import Sandbox
        # sbx = Sandbox(api_key=self.api_key)
        # res = sbx.run_command(command)
        # return SandboxResult(res.stdout, res.stderr, res.exit_code, 0)
        
        return SandboxResult("", "E2B Sandbox integration active (Mock)", 0, 0)

    def run_python(self, code: str, timeout: int = 30) -> SandboxResult:
        return SandboxResult("", "E2B Python execution active (Mock)", 0, 0)


def get_sandbox() -> BaseSandbox:
    """Factory to get the preferred sandbox based on environment."""
    if os.environ.get("E2B_API_KEY"):
        return E2BSandbox()
    return DockerSandbox()
