from collections import defaultdict, deque
from pathlib import Path
import logging
import os
import logging
import tempfile
import multiprocessing
import tracemalloc
from typing import List, Dict, Tuple, Union

from elftools.common.exceptions import ELFError
import cxxfilt

from utils.adb import Adb
from utils.log import get_logger
from .command import *
from .file_type import *
from .file_extractor import FileExtractor


logger = get_logger('depFinderLogger')


class DependencyFinder(object):

    _thread_count = multiprocessing.cpu_count()

    def __init__(self, work_dir, target_lib: str, device_id=None):
        self.work_dir = work_dir
        self.target_lib = target_lib[1:] if target_lib.startswith("/") else target_lib
        self.device_id = None
        self.source_dir = os.path.join(self.work_dir, "jadx_source")
        if device_id is not None:
            self.device_id = device_id
        if logger is not None:
            self.logger = logger
        else:
            self.logger = logging.Logger(__name__)

    ################################################################################
    # ELF files
    ################################################################################

    def _get_needed_libraries(self, elf: Elf) -> List[str] | str:
        """Returns a list of libraries required by the given ELF file."""
        return elf.get_needed_libraries()

    def _check_for_dynamic_symbols(self, elf: Elf):
        """Checks if specific dynamic symbols exist in an ELF file."""
        hw_get_mod = elf.contains_dynamic_symbol("hw_get_module")
        dlopen = elf.contains_dynamic_symbol("dlopen")
        return hw_get_mod, dlopen

    def _find_dependencies_from_strings(self, elf: Elf, elf_files: List[Elf], deps: List[str]) -> None:
        """Finds additional ELF dependencies based on strings."""
        to_check = [d for d in elf_files if d.name not in deps and d.name != elf.name]
        hw_get_mod, dlopen = self._check_for_dynamic_symbols(elf)
        if dlopen or hw_get_mod:
            for file in to_check:
                names = []
                if (hw_get_mod and f".{self.platform}.so" in file.path) or \
                    (hw_get_mod and f"{self.brand}" in file.path and file.name.endswith(".so")):
                    names.append(file.name)
                if dlopen and file.name.endswith(".so"):
                    names.append(file.name)
                for name in names:
                    if elf.contains_string(elf.work_path, name):
                        deps.append(name)
            # self.logger.debug(f"find_dependencies_from_strings {elf.name} {deps}")

    def _find_dependencies_by_symbol(self, elf: Elf, deps: List[str], elf_files: List[Elf]) -> None:
        """Finds dependencies by symbol name."""
        try:
            with open(os.path.join(elf.work_path, elf.path.lstrip("/")), "rb") as f:
                elffile = ELFFile(f)
                dynsym = elffile.get_section_by_name(".dynsym")
                if dynsym:
                    for symbol in dynsym.iter_symbols():
                        if "getService" in symbol.name and symbol['st_info']['bind'] == 'STB_GLOBAL':
                            func_name = symbol.name if type(symbol.name) == str else symbol.name.decode('utf-8')
                            demangled = cxxfilt.demangle(func_name, external_only=False)
                            if demangled: # TODO: handle exception for _demangle_symbol
                                self._find_service_dependencies(demangled, deps, elf_files)
        except Exception as e:
            self.logger.error(f"find_dependencies_by_symbol error {elf.name}: {str(e)}")

    def _find_service_dependencies(self, demangled: str, deps: List[str], elf_files: List[Elf]) -> None:
        """Finds service dependencies and updates the deps list."""
        splitted = demangled.split("::")
        base_name, version = self._extract_service_data(splitted)
        if base_name and version:
            candidates = self._find_matching_elf_files(base_name, version, elf_files)
            if len(candidates) == 1 and candidates[0].path not in set(deps):
                deps.insert(0, candidates[0].path)

    def _extract_service_data(self, splitted: List[str]):
        """Extracts service data, such as the base name and version number."""
        for i in range(len(splitted)):
            if splitted[i].startswith("I"):
                return splitted[i - 2], splitted[i - 1][1:].replace("_", ".")
        return None, None

    def _find_matching_elf_files(self, base_name: str, version: str, elf_files: List[Elf]) -> List[Elf]:
        """Finds matching ELF files."""
        ver_string = version + "-impl.so"
        candidates = [c for c in elf_files if base_name in c.path and ver_string in c.path]
        if len(candidates) > 1:
            try:
                candidates = [c for c in candidates if (c.get_arch()[1]) == 64]  
                system_path_candidates = [c for c in candidates if c.path.startswith("system")]
                if system_path_candidates:
                    candidates = system_path_candidates
                else:
                    candidates = candidates[:1]
            except (FileNotFoundError, ELFError) as e:
                self.logger.error(f"Error reading ELF file: {str(e)}")                
        return candidates   

    def _build_dependency_graph_helper_elf(self, elf: Elf, elf_files: List[Elf]):
        """
        Refactored function to assist in determining the list of 
        dependencies for a given ELF.
        """
        if elf.get_arch()[1] != 64:
            return []
        deps = self._get_needed_libraries(elf)
        if type(deps) is str:
            self.logger.error(deps)
            return []
        self._find_dependencies_from_strings(elf, elf_files, deps)
        self._find_dependencies_by_symbol(elf, deps, elf_files)
        self.logger.debug(f"build elf {elf.name} {deps}")
        return deps

    ################################################################################
    # JAR files
    ################################################################################
    
    # TODO: update java jar dependencies

    ################################################################################
    # VDEX files
    ################################################################################

    def _find_hw_service_dependencies(self, output_path, services):
        deps = []
        cmd_dep = get_find_dep_command(
            "grep -R", output_path, "HwServiceFactory.getHw"
        )
        out = execute_command_binary(cmd_dep)
        for line in out.splitlines():
            if b"HwServiceFactory.getHw" in line:
                print(line.decode())
                sp = line.split(b"HwServiceFactory.getHw")
                for s in sp:
                    if b"Service()" in s:
                        base = s.split(b"Service()")[0].lower()
                        candidates = [
                            c for c in services if base.decode() in c.path]
                        if len(candidates) == 1:
                            deps.append(candidates[0].path)
        return deps

    def _find_jni_library_dependencies(self, output_path, jni_libs, vdex_path):
        deps = []
        cmd_dep = get_find_dep_command(
            "grep -R", output_path, "System.loadLibrary("
        )
        out = execute_command(cmd_dep)
        for line in out.splitlines():
            if 'System.loadLibrary("' in line:
                sp = line.split('System.loadLibrary("')
                sp = sp[1].split('")')[0]
                candidates = [c for c in jni_libs if sp in c.path]
                deps.extend(self._filter_candidates(candidates, vdex_path))
        return deps

    def _filter_candidates(self, candidates, vdex_path):
        if len(candidates) > 1:
            candidates = [c for c in candidates if "64" in c.path] \
                if "arm64" in vdex_path else \
                [c for c in candidates if not "64" in c.path]
            system_candidates = [c for c in candidates if c.path.startswith("system")]
            candidates = system_candidates[:1] if system_candidates else candidates[:1]
        return candidates

    def _build_dependency_graph_helper_vdex(self, vdex: Vdex, elf_files:List[Elf]):
        """Return list of ELF binaries needed by the given VDEX."""
        deps = []
        if vdex.name == "base.vdex" or vdex.name == "base.odex":
            return []
        if not vdex.path.endswith(".vdex"):
            dex_path = f"{self.work_dir}/vdex2dex/{vdex.path[:-5]}/classes.dex"
            # Extraction failed
        else:
            temp_dex_path = Path(f"{self.work_dir}/vdex2dex/{vdex.path[:-5]}")
            temp_dex_path.mkdir(parents=True, exist_ok=True)
            FileExtractor.convert_vdex_to_dex(vdex, temp_dex_path)
            if temp_dex_path is None:
                return []
            dex_path = f"{temp_dex_path}/classes.dex" # Assume .dex file is provided directly

        output_path = os.path.join(self.source_dir, f"{vdex.path[:-5]}")
        FileExtractor.convert_dex_to_java(dex_path, output_path)
        if os.path.exists(output_path):
            services = [s for s in elf_files if s.path.endswith("-service")]
            deps = self._find_hw_service_dependencies(output_path, services)

            jni_libs = [l for l in elf_files if l.path.endswith(".so")]
            deps.extend(self._find_jni_library_dependencies(output_path, jni_libs, vdex.path))
        return deps
    
    ################################################################################
    # main graph builder
    ################################################################################

    def _collect_elf_dependencies(self, elf_files: List[Elf]) -> List[Tuple[str, List[str]]]:
        """
        Collect the dependencies for each ELF file in a list of ELF files using parallel processing.

        Args:
            elf_files (List[Elf]): A list of Elf objects that represent ELF files.

        Returns:
            dep_list (List[Tuple[str, List[str]]]): A list of tuples, where each 
            tuple consists of an ELF file path and a list of its dependencies' file paths.
        """
        logger.info("ELF dep graph")
        with multiprocessing.Pool(self._thread_count) as pool:
            tasks = []
            for elf in elf_files:
                task = pool.apply_async(self._build_dependency_graph_helper_elf,
                                        args=(elf, elf_files))
                tasks.append((elf, task))
            pool.close()
            pool.join()
            
        results = [(elf.path, task.get()) for elf, task in tasks]
        return results
    
    def _collect_vdex_dependencies(self, vdex_files: List[Vdex], elf_files: List[Elf]):
        logger.info("Vdex dep graph")
        with multiprocessing.Pool(self._thread_count) as pool:
            tasks = []
            for vdex in vdex_files:
                task = pool.apply_async(self._build_dependency_graph_helper_vdex,
                                        args=(vdex, elf_files))
                tasks.append((vdex, task))
            pool.close()
            pool.join()
            
        results = [(vdex.path, task.get()) for vdex, task in tasks]
        return results


    def build_dependency_graph(
        self, 
        elf_list: List[Elf], 
        vdex_list: List[Vdex] | None, 
        apk_list: List[Apk] | None,
        dep_root: str
    ) -> Dict[str, list[str]]:
        """
        Collect dependencies for `dep_root`.
        """
        self.logger.info("Building dependency graph")

        dependencies_full = {}

        elf_results = self._collect_elf_dependencies(elf_list)
        if vdex_list != None:
            vdex_results = self._collect_vdex_dependencies(vdex_list)
            results = elf_results + vdex_results
        else:
            results = elf_results
        self.logger.info("Accumulating results 1")
        for elf_path, deps in results:
            # add `Elf` if it does not exist yet
            if not elf_path in dependencies_full.keys():
                dependencies_full[elf_path] = {"to": [], "from": []}

            for dep in deps:
                # find lib in elf_files
                candidates = [c for c in elf_list if dep in c.path]
                if len(candidates) == 0:
                    continue
                elif len(candidates) > 1:
                    # only 64 bit elfs
                    candidates = [c for c in candidates if c.get_arch()[1] == 64]
                    candidates_tmp = [
                        c for c in candidates if c.path.startswith("system/")
                    ]

                    if len(candidates_tmp) == 0:
                        candidates = candidates[:1]
                    else:
                        candidates = candidates_tmp

                dep_path = candidates[0].path

                # add dep in both entries
                dependencies_full[elf_path]["to"].append(dep_path)
                if dep_path not in dependencies_full.keys():
                    dependencies_full[dep_path] = {"to": [], "from": []}
                dependencies_full[dep_path]["from"].append(elf_path)

        self.logger.info(f"Accumulting results 2 {len(dependencies_full)}")
        dependencies = {}
        queue = [dep_root]

        self.logger.info(f"len of queue={len(queue)}")
        while len(queue) > 0:
            cur_node = queue.pop(0)
            if "libc.so" in cur_node:
                self.logger.debug("found libc...NOPE")
                continue
            
            dependencies[cur_node] = dependencies_full[cur_node]
            for neighbor in dependencies[cur_node]["from"]:
                if neighbor not in dependencies.keys():
                    queue.append(neighbor)

        self.logger.info("Cleanup refs")
        # cleanup to references
        for key in dependencies.keys():
            to_remove = []
            for dep in dependencies[key]["to"]:
                if dep not in dependencies.keys():
                    to_remove.append(dep)
            for rem in to_remove:
                dependencies[key]["to"].remove(rem)

        # visualization only needs from
        deps_for_vis = {}
        for key in dependencies.keys():
            deps_for_vis[key] = dependencies[key]["from"]
        return deps_for_vis
    
    def create_visualization(self, out_dir: str, dependencies):
        """Create a visualization of the dependency graph."""

        self.logger.info("Creating human readable output")
        out = "digraph DependencyTree {\n"
        for key in dependencies:
            for dep in dependencies[key]:
                out += '  "{}" -> "{}";\n'.format(dep, key)
        out += "}"

        deps_dot = os.path.join(out_dir, "deps.dot")
        with open(deps_dot, "w+") as f:
            f.write(out)

        deps_flat_dot = os.path.join(out_dir, "deps_flat.dot")
        unflatten = subprocess.Popen(
            f"unflatten -l 30 -f -o {deps_flat_dot} {deps_dot}",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
        )

        deps_png = os.path.join(out_dir, "deps.png")
        stdout, stderr = unflatten.communicate()
        dot = subprocess.Popen(
            ["dot", "-Tpng", deps_flat_dot, f"-o{deps_png}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = dot.communicate()
        dot.wait()
        if stdout != b"" or stderr != b"":
            self.logger.error("Creating graph failed:\n{}\n{}".format(stdout, stderr))

    ################################################################################
    # Environment Init
    ################################################################################

    def _init_adb_env(self):
        self.logger.info("Adb environment initializing")
        if self.device_id != None:
            self.adb = Adb(device=self.device_id, logger=logger)
        else:
            self.adb = Adb(logger=logger)
        self.platform = self.adb.call_privileged_adb_shell(["getprop", "ro.hardware"])
        self.brand = self.adb.call_privileged_adb_shell(["getprop", "ro.product.brand"])
        self.fingerprint = self.adb.call_privileged_adb_shell(["getprop", "ro.build.fingerprint"])

    def _end_adb_env(self):
        if self.adb is not None:
            self.adb.kill_all_adb_process()

    def _init_work_dir(self):
        self.logger.info("Working directory initializing")
        if self.work_dir is None:
            self.work_dir = tempfile.mkdtemp(prefix="teezz_")
        if self.adb is None:
            return False
        self.elf_work_dir = os.path.join(self.work_dir, "Elf")
        self.vdex_work_dir = os.path.join(self.work_dir, "Vdex")
        self.apk_work_dir = os.path.join(self.work_dir, "Apk")

    def _init_file_list(self, fe: FileExtractor, flag: Executable) -> List[Executable] | None:
        """Init file list by FileExtractor"""
        self.logger.info(f"Executable {flag.get_name()} initializing")
        Path(self.work_dir).mkdir(parents=True, exist_ok=True)
        target_file_list_path = os.path.join(self.work_dir, f"{flag.get_name()}.json")
        if os.path.exists(target_file_list_path) and os.path.getsize(target_file_list_path) > 0:
            return import_executables_from_json(target_file_list_path, flag)
        method_name = f"get_{flag.get_name().lower()}s_list"
        if hasattr(fe, method_name):
            file_list = getattr(fe, method_name)()
            export_executables_to_json(file_list, target_file_list_path)
            return file_list
        else:
            return None

    def _init_source_file(self, fe: FileExtractor, file_list: List[Executable] | None) -> bool | None:
        if file_list is None:
            return False
        self.logger.info(f"Pull source file {file_list[0].get_instance_name()}s")
        fe.collect_files(fe._pull_files, file_list)

    ################################################################################
    # run function
    ################################################################################
        
    def run(self):
        tracemalloc.start()
        self._init_adb_env()
        if self._init_work_dir() is False:
            self._end_adb_env()
            return False
        if self._init_work_dir() is False:
            self._end_adb_env()
            return False
        elf_file_extractor = FileExtractor(self.elf_work_dir, self.adb)
        vdex_file_extractor = FileExtractor(self.vdex_work_dir, self.adb)
        apk_file_extractor = FileExtractor(self.apk_work_dir, self.adb)

        elf_list = self._init_file_list(elf_file_extractor, Elf)
        vdex_list = self._init_file_list(vdex_file_extractor, Vdex)
        apk_list = self._init_file_list(apk_file_extractor, Apk)

        if self._init_source_file(elf_file_extractor, elf_list) or \
            self._init_source_file(vdex_file_extractor, vdex_list) or \
            self._init_source_file(apk_file_extractor, apk_list):
            self._end_adb_env()
            self.logger.error("Pull source file error")

        if elf_list is not None:
            dependencies = self.build_dependency_graph(
                elf_list=elf_list,
                vdex_list=None, # Not completed
                apk_list=None,
                dep_root=self.target_lib
            )
            self.create_visualization(self.work_dir, dependencies)



        


            
            
    
        