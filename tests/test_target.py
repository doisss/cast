from sarbar.target import detect_target, TargetKind


def test_image():
    assert detect_target("alpine:3.19").kind == TargetKind.IMAGE
    assert detect_target("nginx:latest").kind == TargetKind.IMAGE


def test_container_id():
    assert detect_target("abc123def456").kind == TargetKind.CONTAINER
    assert detect_target("a" * 64).kind == TargetKind.CONTAINER
    assert detect_target("abc123def456", {"abc123def456"}).kind == TargetKind.CONTAINER


def test_fs_and_dockerfile(tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    (d / "main.py").write_text("x=1")
    assert detect_target(str(d)).kind == TargetKind.FS
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:3.19\n")
    assert detect_target(str(df)).kind == TargetKind.DOCKERFILE
