from recon_cli.cli import app
from typer.testing import CliRunner

runner = CliRunner()
result = runner.invoke(app, ["doctor", "--no-exit-on-fail"])
print(f"EXIT CODE: {result.exit_code}")
print(f"OUTPUT: {repr(result.stdout)}")
if result.exception:
    print(f"EXCEPTION: {repr(result.exception)}")
    import traceback
    traceback.print_exception(type(result.exception), result.exception, result.exception.__traceback__)
