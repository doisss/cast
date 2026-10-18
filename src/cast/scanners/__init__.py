"""
Реестр сканеров. Pipeline берёт список отсюда и не знает, сколько их
и как они устроены — хочешь добавить Grype, допиши класс
в этом пакете и добавь его в ALL_SCANNERS, больше нигде менять не придётся.
"""

from cast.scanners.base import ProgressUI, Scanner, ScannerError
from cast.scanners.docker_bench import DockerBenchScanner
from cast.scanners.trivy import TrivyScanner

ALL_SCANNERS: list[type[Scanner]] = [
    TrivyScanner,
    DockerBenchScanner,
]

__all__ = ["ProgressUI", "Scanner", "ScannerError", "ALL_SCANNERS", "TrivyScanner", "DockerBenchScanner"]
