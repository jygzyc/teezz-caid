import unittest
import os

from utils.log import init_ini_log
from dep_finder.file_type import *
from dep_finder.dependency_finder import DependencyFinder


class TestDependencyFinderModule(unittest.TestCase):
    
    def setUp(self) -> None:
        log_directory = "logs"
        if not os.path.exists(log_directory):
            os.makedirs(log_directory) 
        init_ini_log("./log.ini")
        self.work_dir = "inout"
        self.dfm = DependencyFinder(work_dir="inout",
                                    target_lib="/vendor/lib64/libMcClient.so",
                                    device_id="AAAAAAAAAAAAA")
        return super().setUp()
    
    def test_run(self):
        self.dfm.run()
    
    @unittest.skip  
    def test_build_dependency_graph_helper_elf(self):
        self.elf_work_dir = os.path.join(self.work_dir, "Elf")
        target_file_list_path = os.path.join(self.work_dir, "Elf.json")
        self.elf_list = import_executables_from_json(target_file_list_path, Elf)
        elf = Elf.parse_elf("vendor/lib64/vendor.vivo.hardware.trust@1.0.so", self.elf_work_dir)
        # self.assertEqual(self.dfm._build_dependency_graph_helper_elf(elf, self.elf_list), RESULT)
   
    @unittest.skip
    def test_build_denpendency_graph_helper_vdex(self):
        self.elf_work_dir = os.path.join(self.work_dir, "Elf")
        self.vdex_work_dir = os.path.join(self.work_dir, "Vdex")
        elf_list_path = os.path.join(self.work_dir, "Elf.json")
        vdex_list_path = os.path.join(self.work_dir, "Vdex.json")
        self.elf_list = import_executables_from_json(elf_list_path, Elf)
        self.vdex_list = import_executables_from_json(vdex_list_path, Vdex)

        vdex = Vdex.parse_from_string("system/app/xxxx.vdex", self.vdex_work_dir)
        res = self.dfm._build_dependency_graph_helper_vdex(vdex, self.elf_list)
        print(res)



