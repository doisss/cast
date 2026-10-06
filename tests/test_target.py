"""Target detection: filesystem intent wins, container shape, image fallback."""
from sarbar.target import TargetKind, detect_target


def test_image_references():
    assert detect_target("alpine:3.19").kind == TargetKind.IMAGE
    assert detect_target("nginx:latest").kind == TargetKind.IMAGE
    assert detect_target("ghcr.io/org/app:v1").kind == TargetKind.IMAGE
    assert detect_target("alpine").kind == TargetKind.IMAGE


def test_container_id_shape():
    assert detect_target("abc123def456").kind == TargetKind.CONTAINER
    assert detect_target("a" * 64).kind == TargetKind.CONTAINER


def test_container_confirmed_by_docker_wins_over_shape():
    t = detect_target("myapp", {"myapp", "abc123def456"})
    assert t.kind == TargetKind.CONTAINER
    assert t.detail == "matches a running container"


def test_fs_directory(tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    (d / "main.py").write_text("x=1")
    t = detect_target(str(d))
    assert t.kind == TargetKind.FS
    assert t.detail == "directory"


def test_dockerfile_and_containerfile(tmp_path):
    for name in ("Dockerfile", "dockerfile", "Containerfile", "Dockerfile.dev"):
        f = tmp_path / name
        f.write_text("FROM alpine:3.19\n")
        assert detect_target(str(f)).kind == TargetKind.DOCKERFILE, name


def test_image_archive_is_an_image(tmp_path):
    tgz = tmp_path / "image.tar"
    tgz.write_bytes(b"x")
    t = detect_target(str(tgz))
    assert t.kind == TargetKind.IMAGE
    assert t.detail == "image archive"


def test_missing_explicit_path_is_still_a_path(tmp_path):
    """I-5: a typo must not be reinterpreted as an image reference."""
    t = detect_target("./does-not-exist")
    assert t.kind == TargetKind.FS
    assert "does not exist" in t.detail


def test_missing_dockerfile_name_is_dockerfile_kind():
    t = detect_target("./Dockerfile")
    assert t.kind == TargetKind.DOCKERFILE
    assert "not found" in t.detail


def test_empty_target():
    assert detect_target("  ").kind == TargetKind.IMAGE
