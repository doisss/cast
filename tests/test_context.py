from cast.context import ScanContext, normalize_name


def test_normalize_name_pep503():
    assert normalize_name("Typing_Extensions") == "typing-extensions"
    assert normalize_name("zope.interface") == "zope-interface"


def test_requirements_parsing_skips_options_urls_and_comments(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "# комментарий\n"
        "requests==2.25.0  # inline comment\n"
        "Flask>=1.1\n"
        "-r other.txt\n"
        "-e .\n"
        "git+https://github.com/x/y.git#egg=y\n"
        "uvicorn[standard]==0.30\n"
        "\n",
        encoding="utf-8",
    )
    ctx = ScanContext.from_requirements_file(req)
    assert ctx.used_packages == {"requests", "flask", "uvicorn"}
    assert ctx.is_used("Requests")
    assert not ctx.is_used("pyyaml")
