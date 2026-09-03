"""Exit code contract: 0 clean, 1 findings, 2 malformed input or usage."""
import json
import os

from hooklint.cli import main


def test_exit_0_on_clean(clean_root, capsys):
    code = main([clean_root])
    assert code == 0


def test_exit_1_on_findings(planted_root, capsys):
    code = main([os.path.join(planted_root, "dead_matcher")])
    assert code == 1


def test_exit_2_on_malformed_json(tmp_path, capsys):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{not valid json", encoding="utf-8")
    code = main([str(tmp_path)])
    assert code == 2
    captured = capsys.readouterr()
    assert "ERROR" in captured.out


def test_exit_2_on_nonexistent_path(capsys):
    code = main(["/definitely/does/not/exist/anywhere"])
    assert code == 2


def test_json_output_is_valid_json(planted_root, capsys):
    code = main(["--json", os.path.join(planted_root, "dead_matcher")])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["findings"]
    assert code == 1


def test_json_output_findings_have_all_contract_fields(planted_root, capsys):
    main(["--json", os.path.join(planted_root, "dead_matcher")])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    for f in payload["findings"]:
        assert set(f.keys()) == {"rule_id", "severity", "file", "json_pointer", "evidence", "message"}
