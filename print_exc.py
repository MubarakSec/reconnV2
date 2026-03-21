from recon_cli.tools.executor import CommandError
exc = CommandError("command timed out", returncode=1)
print(repr(exc))
print(str(exc))
