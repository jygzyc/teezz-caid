import subprocess
import os
from dataclasses import dataclass, asdict, field
import json
from typing import List, Optional, Tuple

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.dynamic import DynamicSection


@dataclass
class Executable:
    name: str
    path: str
    work_path: str
    
    def contains_string(self, path, s):
        """Returns `True` if file `path` contains string `s`,
        `False` otherwise."""
        cmd = "strings {} | grep {}".format(path, s)
        p = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, _ = p.communicate()
        if out:
            return True
        return False

    @classmethod
    def get_name(cls):
        return cls.__name__
    
    def get_instance_name(self):
        return self.__class__.__name__


@dataclass
class Elf(Executable):

    arch: Optional[Tuple] = field(default_factory=None, repr=False, init=False)

    def __init__(self, name: str, path: str, work_path: str, arch: Optional[Tuple] = None):
        super().__init__(name, path, work_path) 
        self.arch = arch

    @staticmethod
    def parse_elf(path: str, work_path: str):
        name = path.split("/")[-1]
        path = path if path[0] != "/" else path[1:]
        return Elf(name, path, work_path, arch=None)

    def get_needed_libraries(self) -> List | str:
        try:
            with open(os.path.join(self.work_path, self.path), "rb") as f:
                elffile = ELFFile(f)
                dynamic = elffile.get_section_by_name(".dynamic")
                if not dynamic or not isinstance(dynamic, DynamicSection):
                    return []
                deps = [tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == 'DT_NEEDED']
                return deps
        except Exception as e:
            return f"{self.name} get_needed_libraries error {e}"

    def _load_symbol_set(self):
        with open(os.path.join(self.work_path, self.path), "rb") as f:
            elffile = ELFFile(f)
            dynsym = elffile.get_section_by_name(".dynsym")
            if not dynsym or not isinstance(dynsym, SymbolTableSection):
                return set()
            result = {symbol.name for symbol in dynsym.iter_symbols()}
            return result

    def contains_dynamic_symbol(self, symbol_name: str) -> bool:
        """Returns `True` if `symbol_name` is part of the `.dynsym` symbol
        table of `ELF` file under `path`,  `False` otherwise."""
        symbol_set = self._load_symbol_set()
        return symbol_name in symbol_set
    
    def get_arch(self):
        """Returns (machine_arch: str, file arch: int)"""
        if self.arch is None:
            with open(os.path.join(self.work_path, self.path), "rb") as f:
                elffile = ELFFile(f)
                elf_class = elffile.elfclass
                machine_arch = elffile.get_machine_arch()
                self.arch = (machine_arch, elf_class)
        return self.arch


@dataclass
class Vdex(Executable):
    @staticmethod
    def parse_from_string(path: str, work_path: str):
        path = path if path[0] != "/" else path[1:]
        name = path.split("/")[-1]
        return Vdex(name, path, work_path)


@dataclass
class Apk(Executable):
    @staticmethod
    def parse_package_name(package_name:str, path: str, work_path:str):
        name = package_name
        path = path if path[0] != "/" else path[1:]
        return Apk(name, path, work_path)
    
def export_executables_to_json(executable_list: List[Executable], filepath) -> None:
    with open(filepath, 'w') as f:
        json.dump([asdict(executable) for executable in executable_list], f, ensure_ascii=False, indent=4)


def import_executables_from_json(filepath, executable_cls: Executable) -> List[Executable]:
    with open(filepath, 'r') as f:
        data = json.load(f)
        return [executable_cls(**item) for item in data]