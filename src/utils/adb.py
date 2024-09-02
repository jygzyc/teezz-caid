import subprocess
import os
import string
import random


class Adb(object):

    def __init__(self, adb_path="adb", device=None, logger=None, listen=None):
        self.process = []
        self.logger = logger
        self.adb_path = adb_path
        self.device_id = device
        self.run_with_su = False
        if self._system_adb_exist():
            self.adb_path = "adb"
        self.adb_prefix: list = [self.adb_path]
        if device is not None:
            self.adb_prefix = self.adb_prefix + ["-s", device]
        if self._has_su_cmd() and not self.adb_is_root():
            self.used_su = True
        else:
            self.used_su = False

    def _run_cmd(self, args: list) -> str:
        out = ''
        try:
            proc = subprocess.Popen(args, 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE)
            self.process.append(proc)
            out, err = proc.communicate()
            for local_proc in self.process:
                if local_proc is proc:
                    self.process.remove(proc)
            if proc.returncode != 0:
                return err.decode('utf-8', 'ignore')
        except OSError as e:
            if self.logger is not None:
                self.logger.info("error result: %s", str(e))
            return str(e)
        return out.decode("utf8", "ignore")

    def _system_adb_exist(self):
        text = self._run_cmd(['adb'])
        if "找不到" in text or "not found" in text:
            return False
        return True

    def call_adb(self, args: list) -> str:
        return self._run_cmd(self.adb_prefix + args) 

    def call_adb_shell(self, args: list) -> str:
        return self.call_adb(['shell'] + args)

    def call_privileged_adb_shell(self, args: list) -> str:
        if self.logger is not None:
            self.logger.debug("Privileged call: %s", ' '.join(self.adb_prefix + args))
        if self.adb_is_root():
            return self.call_adb_shell(args)
        elif not self.adb_is_root() and self.used_su:
            return self.call_adb_shell(["su", "-c"] + args)
        elif not self.adb_is_root() and not self.used_su:
            # Run oem self-defined command 
            self.call_adb(["root"]) 
            return self.call_adb_shell(args)


    def adb_is_root(self):
        out = self.call_adb_shell(["whoami"])
        if "root" in out:
            return True
        return False

    def _has_su_cmd(self):
        text = self.call_adb_shell(['su', '-c'])
        if text.find('/system/bin/sh: su:') != -1:
            return False
        return True

    def adb_forward(self, lport, dport):
        out = self.call_adb(["forward", "tcp:{}".format(lport), "tcp:{}".format(dport)])
        return out
    
    def adb_list_devices(self):
        out = self.call_adb(["devices"])
        return out
    
    def adb_reboot(self):
        out = self.call_adb_shell(["reboot"])
        return out

    def adb_reboot_recovery(self):
        out = self.call_adb_shell(["reboot", "recovery"])
        return out

    def adb_push(self, what, where):
        out = self.call_adb(["push", what, where])
        return out
    
    def adb_pull(self, what, where):
        out = self.call_adb(["pull", what, where])
        return out

    def adb_pull_privileged(self, what, where):
        """ Pull from the device by root"""
        workdir = "/data/local/tmp/" + "".join(
            random.choices(string.ascii_letters, k=10)
        )
        # rand_str = list(string.ascii_letters)
        # random.shuffle(rand_str)
        # workdir = os.path.join("/data/local/tmp", "".join(rand_str[:10]))

        what_file = os.path.basename(what)
        workdir_file = os.path.join(workdir, what_file)

        self.call_privileged_adb_shell(["mkdir", "-p", workdir])
        self.call_privileged_adb_shell(["cp", "-f", what, workdir])
        self.call_privileged_adb_shell(
            ["chown", "shell:shell", workdir_file])
        out = self.adb_pull(workdir_file, where)
        self.call_privileged_adb_shell(["rm", "-rf", workdir])

        return out
    
    def adb_program_exists(self, program_name):
        out = self.call_adb_shell(["which", program_name])
        return out

    def adb_pkill(self, process_name):
        if self.adb_program_exists("pkill"):
            self.call_privileged_adb_shell(["pkill", process_name])
        else:
            return -1
        
    def adb_kill(self, pid):
        if self.adb_program_exists("kill"):
            self.call_privileged_adb_shell(["kill", "-9", pid])
        else:
            return -1
        
    def adb_pidof(self, process_name):
        out = ""
        if self.adb_program_exists("pidof"):
            tmp = self.call_privileged_adb_shell(["pidof", process_name])
            out += tmp
        return out
    
    def adb_install_apk(self, apk_path):
        out = self.call_adb(["install", apk_path])
        return out
    

    def _detect_delimiter(self, input_string):
        delimiter_candidates = ['\r\n', '\n', '\r', '\t']
        delimiter = max(delimiter_candidates, key=lambda d: input_string.count(d))
        return delimiter if input_string.count(delimiter) > 0 else ' '

    def adb_ls_privileged(self, path):
        dirs = self.call_privileged_adb_shell(["ls", path])
        delimiter = self._detect_delimiter(dirs)
        split_list = dirs.strip().split(delimiter)
        new_path = path + "/" if path[-1] != "/" else path
        return [new_path + element for element in split_list if element]

    def kill_all_adb_process(self):
        for proc in self.process:
            proc.kill()






    


