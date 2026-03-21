import sys
from recon_cli.cli import app
from typer.testing import CliRunner

runner = CliRunner()
try:
    result = runner.invoke(app, ["doctor"])
    print("EXIT CODE:", result.exit_code)
    print("OUTPUT:", repr(result.output))
    if result.exception:
        print("EXCEPTION:", repr(result.exception))
        import traceback
        traceback.print_exception(type(result.exception), result.exception, result.exception.__traceback__)
except Exception as e:
    import traceback
    traceback.print_exc()
