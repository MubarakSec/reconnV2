from recon_cli.secrets.detector import SecretsDetector


def test_secrets_detector_hashes_values():
    detector = SecretsDetector(timeout=1)
    text = "aws_secret=AKIA1234567890123456"
    matches = detector.scan_text(text)
    assert matches, "expected a secret to be detected"
    match = matches[0]
    assert hasattr(match, "value_hash")
    assert not hasattr(match, "value")
    assert match.length == len("AKIA1234567890123456")
