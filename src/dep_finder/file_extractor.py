import os
import multiprocessing
from pathlib import Path
from enum import Enum
import logging
from functools import reduce
from typing import List

from utils.adb import Adb
from utils.log import get_logger
from .command import *
from .file_type import *

logger = get_logger('depFinderLogger')

MP = True
SKIP_DIR = [
    "/acct",
    "/cache",
    "/sdcard",
    "/sys",
    "/dev",
    "/proc",
    "/debug_ramdisk",
    "/mnt",
    "/lost+found"
]
FILTERS = [
    "/data/local/tmp",
    ".magisk",
    "/data/dalvik-cache",
]

class FileType(Enum):
    FILE = 1
    DIRECTORY = 0


class FileExtractor(object):

    _thread_count = multiprocessing.cpu_count()

    def __init__(self, work_dir, adb: Adb):
        self.work_dir = work_dir
        self._adb = adb
        self.logger = logger if logger != None else logging.getLogger(__name__)

    def collect_files(self, func, files_list: List[Executable]):
        if MP:
            with multiprocessing.Pool(FileExtractor._thread_count) as p:
                p.map(func, files_list)
        else:
            for f in files_list:
                func(f)

    def _pull_files(self, file: Executable):
        work_dir_path = Path(self.work_dir)
        work_dir_path.mkdir(parents=True, exist_ok=True)

        if file.path.startswith("/"):
            file_path = work_dir_path / file.path[1:]
        else:
            file_path = work_dir_path / file.path

        if not file_path.exists():
            file_path.parent.mkdir(parents=True, exist_ok=True)
            self._adb.adb_pull_privileged(str(file.path), str(file_path)) 

    def get_type(self, path) -> FileType:
        out = self._adb.call_privileged_adb_shell([f'stat {path}']).split("\n")
        if len(out) > 2:
            if "directory" in out[1]:
                return FileType.DIRECTORY
            else:
                return FileType.FILE
        assert False, f'Error: `stat` returned {out}'

    def get_apks_list(self) -> List[Apk]:
        result: List[Apk] = []
        # 1. Get all apks installed
        get_names_cmd = "pm list packages | tr -d '\r' | sed 's/package://g'"
        package_names = self._adb.call_privileged_adb_shell([get_names_cmd])
        package_name_list = package_names.splitlines()
        for name in package_name_list:
            get_path_cmd = "pm path {} | tr -d '\r' | sed 's/package://g'".format(name.strip())
            path = self._adb.call_adb_shell([get_path_cmd]).strip()
            result.append(Apk.parse_package_name(name, path, self.work_dir))

        return result

    def get_vdexs_list(self) -> List[Vdex]:
        directories = self._adb.adb_ls_privileged("/")
        allowed_list = [i for i in directories if i not in set(SKIP_DIR)]
        allowed_list = [i for i in allowed_list if self.get_type(i) == FileType.DIRECTORY]
        start_value: list[Elf] = []
        new_vdexs = []
        if MP:
            with multiprocessing.Pool(FileExtractor._thread_count) as p:
                new_vdexs = list(p.map(
                    self._get_vdex_from_directory, allowed_list))
        else:
            for d in allowed_list:
                __vdexs = self._get_vdex_from_directory(d)
                new_vdexs.extend(__vdexs)
        return reduce(lambda a, b: a + b, new_vdexs, start_value)


    def _get_vdex_from_directory(self, path) -> List[Vdex]:
        def check_filter(vdex: Vdex):
            for fp in FILTERS:
                if fp in vdex.path:
                    return False
            return True
        cmd = f'find {path} -type f -iname "*.?dex"'
        out = self._adb.call_privileged_adb_shell([cmd])
        temp_list = list(map(lambda l: Vdex.parse_from_string(l, self.work_dir), out.splitlines()))
        return list(filter(check_filter, temp_list))

    def get_elfs_list(self) -> List[Elf]:
        directories = self._adb.adb_ls_privileged("/")
        allowed_list = [i for i in directories if i not in set(SKIP_DIR)]
        allowed_list = [i for i in allowed_list if self.get_type(i) == FileType.DIRECTORY]
        start_value: list[Elf] = []
        new_elfs = []
        if MP:
            with multiprocessing.Pool(FileExtractor._thread_count) as p:
                new_elfs = list(p.map(
                    self._get_elf_from_directory, allowed_list))
        else:
            for d in allowed_list:
                __elfs = self._get_elf_from_directory(d)
                new_elfs.extend(__elfs)
        return reduce(lambda a, b: a + b, new_elfs, start_value)

    def _get_elf_from_directory(self, path) -> List[Elf]:
        cmd = f"for node in `find {path} -type f`; do echo -n \"$node: \"; dd if=$node bs=1 count=4 2>/dev/null | grep -q 'ELF'; echo $?; done"
        files = self._adb.call_privileged_adb_shell([cmd])
        elf_paths = [f.split(": ")[0] for f in files.splitlines() if ": " in f and f.split(": ")[1] == "0"]
        elf_paths = [elf_path for elf_path in elf_paths if ".magisk" not in elf_path]
        return list(map(lambda l: Elf.parse_elf(l, self.work_dir), elf_paths))

    @staticmethod
    def convert_vdex_to_dex(vdex: Vdex, output_dir: str):
        output_path = Path(output_dir)
        if output_path.is_dir() and any(output_path.iterdir()):
            return 1
        if vdex.path.endswith(".vdex"):
            input_dir = os.path.join(vdex.work_path, vdex.path)
            command = " ".join(["vdexExtractor", f"--input={input_dir}",
                                f"--output={output_dir}", "--deps", "--dis"])
            out = execute_command(command).splitlines()
            for l in out.splitlines():
                if l.startswith("[ERROR]"):
                    return -1
            return 1 # endif
        return 0
    
    @staticmethod
    def convert_dex_to_java(dex_path, output_dir: str):
        output_path = Path(output_dir)
        if output_path.is_dir() and any(output_path.iterdir()):
            return 
        if not os.path.exists(output_dir):
            command = " ".join(["jadx", "-Pdex-input.verify-checksum=no", "--no-res",
                        "--excape-unicode", "--show-bad-code", "-ds", output_dir,
                        dex_path])
            _ = execute_command(command).splitlines
    
    @staticmethod
    def convert_apk_to_java(apk: Apk, output_dir: str):
        output_path = Path(output_dir)
        if output_path.is_dir() and any(output_path.iterdir()):
            return
        if not os.path.exists(output_dir):
            command = " ".join(["jadx", "-Pdex-input.verify-checksum=no", "--no-res",
                        "--excape-unicode", "--show-bad-code", "-ds", output_dir,
                        os.path.join(apk.work_path, apk.path)])
            _ = execute_command(command).splitlines
