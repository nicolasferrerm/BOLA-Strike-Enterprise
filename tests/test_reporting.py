from app.core.cef_exporter import export_cef
from app.core.pdf_report import generate_pdf_report


def test_pdf_report_writes_escaped_html(tmp_path):
    output = tmp_path / "report.html"
    result = {
        "diagnosis": "VULNERABLE <script>alert(1)</script>",
        "severity": "HIGH",
        "method": "GET",
        "path": "/users/42",
        "remediation": "Enforce object ownership checks.",
    }

    generated = generate_pdf_report([result], "https://api.example.test", str(output))
    content = output.read_text(encoding="utf-8")

    assert generated == str(output)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
    assert "<script>alert(1)</script>" not in content


def test_cef_export_omits_non_findings(tmp_path):
    output = tmp_path / "findings.cef"
    results = [
        {"diagnosis": "SECURE", "path": "/health", "method": "GET"},
        {
            "diagnosis": "VULNERABLE: BOLA",
            "severity": "HIGH",
            "path": "/users/42",
            "method": "GET",
            "remediation": "Check ownership",
        },
    ]

    export_cef(results, str(output), scan_id="unit-test")
    lines = output.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 1
    assert "unit-test" in lines[0]
    assert "/users/42" in lines[0]
