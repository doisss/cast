from sarbar.checks import check_dockerfile, check_fs_secrets, check_inspect


def test_dockerfile_root_and_latest(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:latest\nRUN apt-get install -y curl\n")
    ids = {f.check_id for f in check_dockerfile(str(df), "t")}
    assert "CAST-DOCKER-002" in ids  # latest
    assert "CAST-DOCKER-003" in ids  # no USER


def test_secret_scan(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n')
    out = check_fs_secrets(str(tmp_path), "t")
    assert any(x.check_id == "CAST-SECRET-001" for x in out)


def test_privileged_inspect():
    insp = {"Config": {"User": ""}, "HostConfig": {"Privileged": True, "Binds": []}}
    ids = {f.check_id for f in check_inspect(insp, "c")}
    assert "CAST-RT-001" in ids
    assert "CAST-RT-002" in ids
