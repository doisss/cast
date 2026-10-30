"""Цели, которые проверяет Trivy своими командами: архив образа, конфигурация,
корневая ФС, репозиторий, SBOM, образ ВМ, кластер Kubernetes."""

import io
import json
import tarfile
from io import StringIO

import pytest
from rich.console import Console

from cast import targets
from cast.pipeline import run_scan
from cast.report import console as console_report
from cast.report import json_report
from cast.report.sections import section_title
from cast.scanners.trivy import TrivyScanner, _explain_failure
from cast.targets import Target, TargetError, resolve_target
from tests.test_targets import FakeDocker


@pytest.fixture(autouse=True)
def docker(monkeypatch):
    fake = FakeDocker(images={"alpine:3.19"})
    monkeypatch.setattr(targets, "run_docker", fake)
    return fake


@pytest.fixture
def here(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _tar(path, members):
    with tarfile.open(path, "w:gz" if path.name.endswith(("gz", "tgz")) else "w") as tar:
        for name in members:
            data = b"{}"
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


K8S = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"


# --- определение цели -------------------------------------------------------

@pytest.mark.parametrize("name, member", [
    ("alpine.tar", "manifest.json"), ("img.tar.gz", "index.json"), ("img.tgz", "manifest.json"),
])
def test_image_archive_is_recognised_by_manifest(here, name, member):
    _tar(here / name, [member, "blobs/sha256/x"])
    t = resolve_target([name])
    assert t.kind == "archive" and t.value == name


def test_tar_without_manifest_explains_what_cast_thought(here):
    _tar(here / "backup.tar", ["etc/passwd"])
    with pytest.raises(TargetError, match="tar-архив, но не образ.*cast scan archive backup.tar"):
        resolve_target(["backup.tar"])


@pytest.mark.parametrize("name, content, subtype", [
    ("deploy.yaml", K8S, "Kubernetes"),
    ("pod.json", json.dumps({"apiVersion": "v1", "kind": "Pod"}), "Kubernetes"),
    ("main.tf", 'resource "aws_s3_bucket" "b" {}', "Terraform"),
    ("main.tf.json", "{}", "Terraform"),
    ("stack.yaml", 'AWSTemplateFormatVersion: "2010-09-09"\nResources: {}\n', "CloudFormation"),
    ("stack.yml", "Resources:\n  B:\n    Type: AWS::S3::Bucket\n", "CloudFormation"),
    ("stack.json", json.dumps({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}), "CloudFormation"),
    ("docker-compose.yml", "services: {}\n", "docker-compose"),
    ("compose.prod.yaml", "services: {}\n", "docker-compose"),
])
def test_config_files_are_recognised(here, name, content, subtype):
    (here / name).write_text(content)
    t = resolve_target([name])
    assert (t.kind, t.subtype) == ("config", subtype)


def test_compose_gets_honest_note_about_empty_report(here):
    (here / "docker-compose.yml").write_text("services: {}\n")
    assert any("docker-compose" in n and "пуст" in n for n in resolve_target(["docker-compose.yml"]).notes)


def test_helm_chart_file_and_folder_are_config(here):
    chart = here / "chart"
    chart.mkdir()
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: demo\nversion: 0.1.0\n")
    by_file = resolve_target(["chart/Chart.yaml"])
    assert (by_file.kind, by_file.subtype, by_file.value) == ("config", "Helm", "chart")
    by_dir = resolve_target(["./chart"])
    assert (by_dir.kind, by_dir.subtype) == ("config", "Helm")


def test_folder_with_os_release_is_rootfs_and_plain_folder_stays_fs(here):
    root = here / "rootfs"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "os-release").write_text("ID=alpine\n")
    (here / "app").mkdir()
    assert resolve_target(["./rootfs"]).kind == "rootfs"
    assert resolve_target(["./app"]).kind == "fs"
    assert resolve_target(["fs", "./rootfs"]).kind == "fs"     # явная форма сильнее


def test_root_of_this_machine_is_rootfs(monkeypatch):
    real = targets.Path.is_file
    monkeypatch.setattr(targets.Path, "is_file",
                        lambda self: str(self) == "/etc/os-release" or real(self))
    assert resolve_target(["/"]).kind == "rootfs"


@pytest.mark.parametrize("url", [
    "https://github.com/aquasecurity/trivy-ci-test", "http://git.local/x.git", "git@github.com:a/b.git",
])
def test_urls_are_repositories(url):
    t = resolve_target([url])
    assert (t.kind, t.value) == ("repo", url)


@pytest.mark.parametrize("name, content, subtype", [
    ("bom.json", json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"}), "CycloneDX"),
    ("x.spdx.json", json.dumps({"spdxVersion": "SPDX-2.3"}), "SPDX"),
    ("x.spdx", "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n", "SPDX"),
])
def test_sbom_is_recognised_by_content(here, name, content, subtype):
    (here / name).write_text(content)
    t = resolve_target([name])
    assert (t.kind, t.subtype) == ("sbom", subtype)


@pytest.mark.parametrize("name", ["disk.vmdk", "disk.qcow2", "d.vhd", "d.vhdx", "d.img", "d.raw"])
def test_vm_disk_images_by_extension(here, name):
    (here / name).write_bytes(b"\0" * 16)
    assert resolve_target([name]).kind == "vm"


def test_cluster_is_reserved_and_takes_no_argument():
    assert resolve_target(["cluster"]).kind == "cluster"
    with pytest.raises(TargetError, match="ничего указывать не нужно"):
        resolve_target(["cluster", "x"])


def test_unknown_file_says_how_to_be_explicit(here):
    (here / "notes.json").write_text('{"a": 1}')
    with pytest.raises(TargetError) as exc:
        resolve_target(["notes.json"])
    msg = str(exc.value)
    for word in ("dockerfile", "config", "sbom", "archive", "vm"):
        assert f"cast scan {word} notes.json" in msg


def test_explicit_forms_for_new_kinds(here):
    (here / "anything.yaml").write_text("foo: bar\n")
    (here / "bom.json").write_text(json.dumps({"bomFormat": "CycloneDX"}))
    (here / "disk.bin").write_bytes(b"\0")
    (here / "root").mkdir()
    assert resolve_target(["config", "anything.yaml"]).kind == "config"
    assert resolve_target(["sbom", "bom.json"]).subtype == "CycloneDX"
    assert resolve_target(["vm", "disk.bin"]).kind == "vm"
    assert resolve_target(["archive", "disk.bin"]).kind == "archive"
    assert resolve_target(["rootfs", "root"]).kind == "rootfs"
    assert resolve_target(["repo", "https://x/y"]).kind == "repo"
    with pytest.raises(TargetError, match="не найден"):
        resolve_target(["sbom", "nope.json"])
    with pytest.raises(TargetError, match="cast scan vm disk.qcow2"):
        resolve_target(["vm"])


def test_image_names_still_images(here):
    assert resolve_target(["alpine:3.19"]).kind == "image"
    assert resolve_target(["ghcr.io/aquasecurity/trivy:0.50"]).kind == "image"


# --- команды Trivy ----------------------------------------------------------

@pytest.fixture
def trivy_cmds(monkeypatch):
    monkeypatch.setattr("cast.scanners.trivy.find_binary", lambda *a, **k: "/usr/bin/trivy")
    monkeypatch.setattr("cast.scanners.trivy._db_needs_update", lambda: False)
    monkeypatch.delenv("CAST_CACHE_DIR", raising=False)
    monkeypatch.setattr("cast.scanners.trivy.cache_dir", lambda: None)
    cmds = []

    def fake_exec(cmd, on_line=None):
        cmds.append(cmd)
        return 0, '{"Results": []}', ""

    monkeypatch.setattr("cast.scanners.trivy._exec", fake_exec)
    return cmds


@pytest.mark.parametrize("kind, value, expected", [
    ("archive", "alpine.tar",
     ["/usr/bin/trivy", "image", "--format", "json", "--skip-db-update", "--input", "alpine.tar"]),
    ("rootfs", "/", ["/usr/bin/trivy", "rootfs", "--format", "json", "--skip-db-update", "--timeout", "30m", "/"]),
    ("repo", "https://github.com/aquasecurity/trivy-ci-test",
     ["/usr/bin/trivy", "repository", "--format", "json", "--skip-db-update", "--timeout", "30m",
      "https://github.com/aquasecurity/trivy-ci-test"]),
    ("sbom", "bom.json", ["/usr/bin/trivy", "sbom", "--format", "json", "--skip-db-update", "bom.json"]),
    ("vm", "disk.qcow2", ["/usr/bin/trivy", "vm", "--format", "json", "--skip-db-update", "--timeout", "30m", "disk.qcow2"]),
    ("cluster", "cluster", ["/usr/bin/trivy", "kubernetes", "--format", "json", "--skip-db-update", "--timeout", "30m"]),
    ("config", "deploy.yaml", ["/usr/bin/trivy", "config", "--quiet", "--format", "json", "deploy.yaml"]),
])
def test_trivy_command_per_new_kind(trivy_cmds, kind, value, expected):
    TrivyScanner().scan_target(Target(kind, value))
    assert trivy_cmds == [expected]


def test_config_does_not_need_vulnerability_db(trivy_cmds, monkeypatch):
    def boom():
        raise AssertionError("база для config не нужна")
    monkeypatch.setattr("cast.scanners.trivy._db_needs_update", boom)
    TrivyScanner().scan_target(Target("config", "main.tf", subtype="Terraform"))


def test_trivy_runs_by_default_for_all_new_kinds():
    scanner = TrivyScanner()
    for kind in ("archive", "config", "rootfs", "repo", "sbom", "vm", "cluster"):
        assert kind in scanner.targets and kind in scanner.default_targets


def test_kubernetes_resources_are_parsed_with_resource_location():
    raw = json.dumps({"ClusterName": "kind", "Resources": [{
        "Namespace": "default", "Kind": "Deployment", "Name": "web",
        "Results": [
            {"Target": "Deployment/web", "Class": "config",
             "Misconfigurations": [{"ID": "KSV-0017", "Title": "Privileged", "Severity": "HIGH",
                                    "Status": "FAIL"}]},
            {"Target": "nginx:1.25 (debian 12.4)", "Type": "debian",
             "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "zlib",
                                  "Severity": "CRITICAL"}]},
        ]}]})
    findings = TrivyScanner()._parse(raw)
    assert [f.check_id for f in findings] == ["KSV-0017", "CVE-1"]
    assert findings[1].location == "default/Deployment/web: nginx:1.25 (debian 12.4)"


def test_cluster_without_kubeconfig_is_explained_with_trivys_own_words():
    msg = _explain_failure(1, "FATAL Fatal error\tinit error: kubeconfig not found: stat /root/.kube/config")
    assert "Kubernetes" in msg and "kubeconfig not found" in msg


# --- отчёт ------------------------------------------------------------------

@pytest.mark.parametrize("target, title", [
    (Target("archive", "alpine.tar"), "Уязвимости образа из архива alpine.tar"),
    (Target("config", "deploy.yaml", subtype="Kubernetes"), "Ошибки конфигурации Kubernetes deploy.yaml"),
    (Target("rootfs", "/"), "Проблемы в корневой ФС /"),
    (Target("repo", "https://x/y"), "Проблемы в репозитории https://x/y"),
    (Target("sbom", "bom.json", subtype="CycloneDX"), "Уязвимости пакетов из SBOM bom.json (CycloneDX)"),
    (Target("vm", "d.qcow2"), "Уязвимости образа диска ВМ d.qcow2 (в Trivy экспериментально)"),
    (Target("cluster", "cluster"), "Проблемы в кластере Kubernetes (в Trivy экспериментально)"),
])
def test_section_titles_for_new_kinds(target, title):
    from tests.test_engines_and_cli import FakeTrivy

    class AllKinds(FakeTrivy):
        targets = TrivyScanner.targets
        default_targets = TrivyScanner.default_targets

    result = run_scan(target, scanners=[AllKinds()])
    assert section_title(result, "trivy", "image") == title
    buf = StringIO()
    console_report.render(result, console=Console(file=buf, width=200, force_terminal=False))
    assert title in buf.getvalue()
    assert json_report.to_dict(result)["target"]["kind"] == target.kind


def test_failed_cluster_scan_is_honest(monkeypatch, tmp_path, capsys):
    from cast import cli, pipeline, state
    from cast.scanners.base import ScannerError

    class NoCluster(TrivyScanner):
        def is_available(self):
            return True

        def scan_target(self, target):
            raise ScannerError("нет доступа к кластеру Kubernetes")

    monkeypatch.setenv("CAST_STATE_DIR", str(tmp_path / "st"))
    state.mark_host_checked()
    monkeypatch.setattr(pipeline, "ALL_SCANNERS", [NoCluster])
    assert cli.main(["scan", "cluster"]) == 2
    out = capsys.readouterr().out
    assert "НЕ выполнена" in out and "нет доступа к кластеру" in out


def test_engines_lists_new_kinds(capsys):
    from cast import cli
    cli.main(["engines"])
    out = capsys.readouterr().out
    for word in ("архив образа", "SBOM", "git-репозиторий", "корневая ФС", "кластер Kubernetes"):
        assert word in out


def test_empty_compose_report_does_not_claim_no_problems():
    from cast.report import html_report
    from tests.test_engines_and_cli import FakeTrivy

    class Empty(FakeTrivy):
        targets = TrivyScanner.targets
        default_targets = TrivyScanner.default_targets

        def scan_target(self, target):
            return []

    result = run_scan(Target("config", "docker-compose.yml", subtype="docker-compose"), scanners=[Empty()])
    buf = StringIO()
    console_report.render(result, console=Console(file=buf, width=200, force_terminal=False))
    out = buf.getvalue()
    assert "Проблем не найдено" not in out and "проверок для docker-compose" in out
    html = html_report.render_html(result)
    assert "Проблем не найдено" not in html and "docker-compose" in html


def test_oci_archive_without_manifest_is_unpacked_for_trivy(trivy_cmds, here):
    _tar(here / "oci.tar", ["oci-layout", "index.json", "blobs/sha256/x"])
    _tar(here / "saved.tar", ["manifest.json", "index.json"])
    TrivyScanner().scan_target(Target("archive", "oci.tar"))
    TrivyScanner().scan_target(Target("archive", "saved.tar"))
    assert trivy_cmds[0][-2] == "--input" and trivy_cmds[0][-1] != "oci.tar"   # временная папка
    assert trivy_cmds[1][-2:] == ["--input", "saved.tar"]                       # docker save — как есть


@pytest.mark.parametrize("token", ["alpine.tar", "deploy.yaml", "sbom.cdx.json", "disk.qcow2"])
def test_missing_file_with_known_extension_is_not_an_image(here, token):
    with pytest.raises(TargetError, match=f"файл «{token}» не найден.*cast scan image {token}"):
        resolve_target([token])


def test_no_space_in_tmp_points_to_tmpdir(monkeypatch):
    monkeypatch.delenv("TMPDIR", raising=False)
    msg = _explain_failure(1, "FATAL write /tmp/trivy-123/layer.tar: no space left on device")
    assert "/tmp" in msg and "TMPDIR=" in msg
    assert "базу уязвимостей" in _explain_failure(1, "write /var/cache/x: no space left on device")


def test_slow_targets_wait_longer_than_trivys_own_timeout():
    from cast.scanners.trivy import _wait_limit
    assert _wait_limit(["trivy", "rootfs", "--timeout", "30m", "/"]) == 35 * 60
    assert _wait_limit(["trivy", "image", "alpine"]) == 600


def test_same_cve_in_two_files_is_two_rows_with_where_column():
    from cast.models import Finding, Severity
    from tests.test_engines_and_cli import FakeTrivy

    class TwoFiles(FakeTrivy):
        targets = TrivyScanner.targets
        default_targets = TrivyScanner.default_targets

        def scan_target(self, target):
            return [Finding("trivy", "CVE-1", "t", Severity.HIGH, package="stdlib", location=w)
                    for w in ("usr/bin/a", "usr/bin/b")]

    result = run_scan(Target("image", "x:1"), scanners=[TwoFiles()])
    assert len(result.findings) == 2
    buf = StringIO()
    console_report.render(result, console=Console(file=buf, width=250, force_terminal=False))
    out = " ".join(buf.getvalue().split())
    assert ": 2" in out and "usr/bin/a" in out and "usr/bin/b" in out and "Где" in out
    assert "вернул записей" not in out
