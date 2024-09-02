from enum import Enum
import subprocess

class Tools(Enum):
    GREP = 0
    GREP_R = 1
    READELF = 2

def get_find_dep_command(tool: Tools, path, dep):
    if tool == Tools.GREP:
        return 'grep -a "{}" {}'.format(dep, path)
    elif tool == Tools.GREP_R:
        return 'grep -r "{}" {}'.format(dep, path)
    assert False, "Your soul is lost."


def execute_command(cmd: str):
    out = ''
    try:
        proc = subprocess.Popen(cmd, 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE)
        out, err = proc.communicate()
        if proc.returncode != 0:
            return err.decode('utf-8', 'ignore')
    except subprocess.CalledProcessError as e:
        return str(e)
    return out.decode("utf8", "ignore")

def execute_command_binary(cmd: str) -> bytes:
    proc = subprocess.Popen(cmd, 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        return err
    return out