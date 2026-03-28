from __future__ import annotations

from recon_cli.pipeline.stages.vuln.stage_vuln_scan import VulnScanStage


def test_dalfox_confirmed_from_json_pocs():
    output = '{"pocs":[{"type":"xss","param":"q"}]}'
    assert VulnScanStage._dalfox_confirmed(output)


def test_dalfox_confirmed_from_json_list():
    output = '[{"type":"xss"}]'
    assert VulnScanStage._dalfox_confirmed(output)
