# LangChain / CrewAI Integration

```python
pip install -e sdks/python

import agentshield
from agentshield import guard, session

@guard
def run_shell(cmd: str) -> str:
    import subprocess
    return subprocess.check_output(cmd, shell=True, text=True)

with session():
    # All subprocess calls in this block are intercepted
    import subprocess
    subprocess.run(["git", "status"])
```