import unittest
import os

from utils.adb import Adb
from utils.log import get_logger, init_ini_log
from dep_finder.file_extractor import FileExtractor, FileType
from dep_finder.file_type import *
from dep_finder.dependency_finder import DependencyFinder

EXPECTED_ADB_TEST_RESULT = {
    "adb_ls_privileged": ['/system/addon.d', '/system/apex', 
                          '/system/app', '/system/bin', 
                          '/system/build.prop', '/system/etc', 
                          '/system/fonts', '/system/framework', 
                          '/system/lib', '/system/lib64', 
                          '/system/priv-app', '/system/product', 
                          '/system/system_dlkm', '/system/system_ext', 
                          '/system/usr', '/system/vendor']
}

class TestAdbModule(unittest.TestCase):

    # def setUp(self) -> None:
    #     log_directory = "logs"
    #     if not os.path.exists(log_directory):
    #         os.makedirs(log_directory) 
    #     init_ini_log("./log.ini")
    #     self.logger = get_logger('depFinderLogger')
    #     self.adb = Adb(logger=self.logger)
    #     return super().setUp()
    
    @unittest.skip
    def test_adb_ls_privileged(self):
        out = self.adb.adb_ls_privileged("/system")
        # self.assertEqual(out, EXPECTED_ADB_TEST_RESULT.get("adb_ls_privileged"))


class TestLogModule(unittest.TestCase):

    def setUp(self) -> None:
        log_directory = "logs"
        if not os.path.exists(log_directory):
            os.makedirs(log_directory) 
        init_ini_log("./log.ini")
        self.logger = get_logger('depFinderLogger')
        return super().setUp()
    
    @unittest.skip
    def test_init_log(self):
        self.logger.error("This is an ERROR message test!")


class TestFileExtractorModule(unittest.TestCase):
    
    def setUp(self) -> None:
        self.adb = Adb()
        self.file_extractor = FileExtractor("test_dir", self.adb)
        return super().setUp()
    
    @unittest.skip
    def test_get_elfs(self):
        out = self.file_extractor.get_elfs_list()
        self.assertIsNotNone(out)

    @unittest.skip
    def test_get_apks(self):
        out = self.file_extractor.get_apks_list()
        self.assertIsNotNone(out)

    @unittest.skip
    def test_get_vdexs_list(self):
        out = self.file_extractor.get_vdexs_list()
        self.assertIsNotNone(out)

    @unittest.skip
    def test_pull_files(self):
        out = self.file_extractor.get_elfs_list()
        self.file_extractor.collect_files(self.file_extractor._pull_files, out)
    
    @unittest.skip
    def test_get_type(self):
        out = self.file_extractor.get_type("/init.environ.rc")
        self.assertEqual(out, FileType.FILE)

    @unittest.skip
    def test_file_get_name(self):
        apk_test = Apk.parse_package_name("com.test", "/data/app/com.test.apk", "/var/apks")
        self.assertEqual(apk_test.get_name(), "Apk")

class TestDependencyFinderModule(unittest.TestCase):
    
    def setUp(self) -> None:
        log_directory = "logs"
        if not os.path.exists(log_directory):
            os.makedirs(log_directory) 
        init_ini_log("./log.ini")
        self.dfm = DependencyFinder(work_dir="test_dir", target_lib="/vendor/lib64/libQSEEComAPI.so")
        return super().setUp()
    
    def test_run(self):
        self.dfm.run()

    

class TestElfHelper(unittest.TestCase):

    def setUp(self) -> None:
        return super().setUp()
    
    
class TestFileType(unittest.TestCase):
    
    def setUp(self) -> None:
        return super().setUp()
    
    @unittest.skip
    def test_elf_file(self):
        elf = Elf.parse_elf("/vendor/lib64/vendor-xxxx.so", "test_dir")
        res = elf.get_needed_libraries()
        print(res)



if __name__ == '__main__':
    unittest.main()