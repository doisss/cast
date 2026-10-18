import subprocess

import pytest

from cast import targets
from cast.targets import TargetError, resolve_target


class FakeDocker:
    """Подмена docker CLI: images — известные локальные образы, containers — {полный_id: (имя, образ, id_образа)}."""

    def __init__(self, images=(), containers=None):
        self.images = set(images)
        self.containers = containers or {}

    def __call__(self, *args):
        def done(code, out="", err=""):
            return subprocess.CompletedProcess(["docker", *args], code, out, err)

        if args[:2] == ("image", "inspect"):
            return done(0, "sha256:x") if args[-1] in self.images else done(1, "", "No such image")
        if args[0] == "ps":
            return done(0, "\n".join(self.containers))
        if args[:2] == ("inspect", "--type"):
            ref = args[-1]
            for cid, (name, image, image_id) in self.containers.items():
                if cid.startswith(ref) or name == ref:
                    return done(0, f"/{name}|{image}|{image_id}\n")
            return done(1, "", "No such container")
        return done(1)


CID = "12b1e6c27fd6" + "0" * 52


@pytest.fixture
def docker(monkeypatch):
    fake = FakeDocker(
        images={"alpine:3.19"},
        containers={CID: ("hello", "hello-fedora:1.0", "sha256:abc")},
    )
    monkeypatch.setattr(targets, "run_docker", fake)
    return fake


def test_plain_name_is_always_image(docker, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "nginx").mkdir()          # папка с таким именем рядом — всё равно образ
    t = resolve_target(["nginx"])
    assert t.kind == "image" and t.value == "nginx"
    assert any("./nginx" in n for n in t.notes)    # но подсказка про папку есть


def test_missing_local_image_gets_note(docker):
    t = resolve_target(["nginx:latest"])
    assert t.kind == "image"
    assert any("нет на этой машине" in n for n in t.notes)
    assert resolve_target(["alpine:3.19"]).notes == []


def test_running_container_id_is_container(docker):
    t = resolve_target(["12b1e6c27fd6"])
    assert t.kind == "container"
    assert t.container_name == "hello"
    assert t.image_name == "hello-fedora:1.0" and t.image_ref == "sha256:abc"


def test_unknown_hex_id_falls_back_to_image(docker):
    assert resolve_target(["ffffffffffff"]).kind == "image"


@pytest.mark.parametrize("token", [".", "..", "./app", "../app", "/tmp", "~"])
def test_path_like_tokens_are_folders(docker, token, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path))
    t = resolve_target([token]) if token not in ("../app",) else resolve_target(["./app"])
    assert t.kind == "fs"


def test_missing_path_is_an_error(docker):
    with pytest.raises(TargetError, match="не найден"):
        resolve_target(["./nope"])


@pytest.mark.parametrize("name", ["Dockerfile", "Dockerfile.dev", "app.Dockerfile", "Containerfile"])
def test_dockerfile_names_are_recognised(docker, tmp_path, monkeypatch, name):
    monkeypatch.chdir(tmp_path)
    (tmp_path / name).write_text("FROM alpine")
    assert resolve_target([name]).kind == "dockerfile"


def test_other_file_needs_explicit_form(docker, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "build.txt").write_text("FROM alpine")
    with pytest.raises(TargetError, match="cast scan dockerfile build.txt"):
        resolve_target(["build.txt"])
    assert resolve_target(["dockerfile", "build.txt"]).kind == "dockerfile"


def test_host_is_reserved_and_takes_no_argument(docker):
    assert resolve_target(["host"]).kind == "host"
    with pytest.raises(TargetError):
        resolve_target(["host", "x"])


def test_explicit_image_form_allows_reserved_looking_names(docker):
    assert resolve_target(["image", "host"]).value == "host"


def test_explicit_container_by_name(docker):
    t = resolve_target(["container", "hello"])
    assert t.kind == "container" and t.container_name == "hello"
    with pytest.raises(TargetError, match="не найден"):
        resolve_target(["container", "ghost"])


def test_reserved_word_without_value_is_an_error(docker):
    with pytest.raises(TargetError):
        resolve_target(["image"])


def test_no_target_and_extra_arguments(docker):
    with pytest.raises(TargetError):
        resolve_target([])
    with pytest.raises(TargetError, match="лишний"):
        resolve_target(["alpine:3.19", "oops"])
