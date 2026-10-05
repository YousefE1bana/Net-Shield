"""Package the supported console, keeping retired control modules in source only."""

from setuptools import setup
from setuptools.command.build_py import build_py
from tempfile import TemporaryDirectory


class SupportedConsole(build_py):
    def find_package_modules(self, package, package_dir):
        modules = super().find_package_modules(package, package_dir)
        if package == "dashboard":
            modules = [m for m in modules if m[1] in {"__init__", "app"}]
        return modules


# bdist_wheel copies every file in build_lib, including stale modules from a
# previous V1 build. Use a fresh build tree rather than deleting user artifacts.
with TemporaryDirectory(prefix="netshield-package-") as build_directory:
    setup(cmdclass={"build_py": SupportedConsole}, options={"build": {"build_base": build_directory}})
