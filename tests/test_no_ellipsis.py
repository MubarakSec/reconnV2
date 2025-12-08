import io
import pathlib
import tokenize

def test_no_literal_ellipsis():
    root = pathlib.Path(__file__).resolve().parents[1] / 'recon_cli'
    offending = []
    for path in root.rglob('*.py'):
        text = path.read_text(encoding='utf-8')
        stream = io.StringIO(text)
        for token in tokenize.generate_tokens(stream.readline):
            if token.type == tokenize.OP and token.string == '...':
                offending.append(f"{path}:{token.start[0]}")
    assert not offending, 'Ellipsis operator found in source files: ' + ', '.join(offending)
