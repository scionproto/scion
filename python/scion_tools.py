import contextlib
import json
import subprocess
import time
from path import Path

import hurry.filesize
import psutil


_PRINT_COMMANDS = False
_working_dir = Path("/home/sgyger/scion")


@contextlib.contextmanager
def printing_commands():
    """
    use as
    ```
    with printing_commands():
        xyz()
    ```
    to output commands to the terminal
    """
    global _PRINT_COMMANDS
    _PRINT_COMMANDS = True
    try:
        yield
    except Exception as e:
        _PRINT_COMMANDS = False
        raise e



def stop_jupyter():
    """
    Stop Juptyer Execution without traceback
    """
    class StopExecution(Exception):
        def _render_traceback_():
            pass
    raise StopExecution

def sleep(s):
    print(f"Sleeping for {s} seconds...")
    time.sleep(s)



def run(command, stop_on_error=True) -> str:
    """
    Run a command and return the output.

    If the command returns non-zero, cell execution is stopped and the command output printed to the terimnal.  

    To get the command output anyway, set `stop_on_error` to `False`.
    """
    try:
        if _PRINT_COMMANDS:
            print(f"$ cwd {_working_dir}")
            print(f"$ {command}")
        with _working_dir:
            return subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode('utf-8')
    except subprocess.CalledProcessError as e:
        if stop_on_error:
            print(f"Error running command: '{command}'")
            print("\nOutput:\n")
            print(e.output.decode('utf-8'))
            stop_jupyter()
        else:
            return e.output.decode('utf-8')

sciond_ips = {}


def load_sciond_ips():
    with (_working_dir / "gen" / "sciond_addresses.json").open() as f:
        global sciond_ips
        sciond_ips = json.load(f)

def generate_topology(topo_name="tiny"):
    print(f"Generating topology: {topo_name}...")
    run(f'./scion.sh topology --topo-config topology/{topo_name}.topo')
    load_sciond_ips()

def get_sciond_addr(ia):
    return f"[{sciond_ips[ia]}]:30255"

def match(start=None, end=None):
    for ia in sciond_ips:
        if start is None or ia.startswith(f"{start}-"):
            if end is None or ia.endswith(f":{end}"):
                return ia

def start():
    if not is_running():
        print("Starting scion...")
        run("./scion.sh start")

    else:
        print("Scion already running.")

def is_running():
    return "" == run("./scion.sh status", False)

def stop():
    print("Stopping scion...")
    run("./scion.sh stop")

def clean_logs():
    print("Removing logs...")
    run("rm -rf logs/*")

def clean():
    clean_logs()
    clean_prometheus()
    clean_gen()

def clean_prometheus():
    print("Wiping prometheus data...")
    run("./prom.sh wipe")

def reload_prometheus_configs():
    print("Reloading prometheus configs...")
    run("./prom.sh reload")

def get_ias():
    return list(sciond_ips.keys())

def get_paths(from_ia, to_ia):
    addr = get_sciond_addr(from_ia)
    output = run(f"scion showpaths --sciond {addr} {to_ia} -e -j")
    return json.loads(output)

def print_all_to_all_paths():
    ias = get_ias()
    for a in ias:
        for b in ias:
            if a != b:
                print(f"{a} -> {b}:")
                paths = get_paths(a, b)
                for path in paths['paths']:
                    latency = sum(path['latency']) / 1000000
                    print(
                        f"\thops: {len(path['hops'])}, latency: {latency}ms")
                print()

def get_branch():
    return run("git rev-parse --abbrev-ref HEAD")

def switch_branch(branch):
    if get_branch() != branch:
        print(f"Switching scion branch to {branch}...")
        run(f"git checkout {branch}")

def clean_gen():
    print("Removing gen directories...")
    run("rm -rf gen*")

def get_cs_resource_usage():
    config_dirs = [str(dirname) for dirname in Path("gen/").dirs(lambda d: d.startswith("AS"))]
    ia_p = {}
    for dirname in config_dirs:
        with (_working_dir / "gen" / dirname / "topology.json").open() as f:
            topo = json.load(f)

        for p in psutil.process_iter():
            if "bin/cs" in p.cmdline() and dirname in "".join(p.cmdline()):
                ia_p[topo["isd_as"]] = p
    return ia_p

def measure_cpu_memory_usage(interval=0.1, timeframe=10):
    cpu_usage = {ia: [] for ia in get_ias()}
    mem_usage = {ia: [] for ia in get_ias()}
    print(f"Running for {timeframe} seconds with interval {interval}...")
    for i in range(int(timeframe / interval)):
        for ia, p in get_cs_resource_usage().items():
            cpu_usage[ia].append(p.cpu_percent())
            mem_usage[ia].append(p.memory_full_info().uss)
        time.sleep(interval)
    
    return cpu_usage, mem_usage
    

def print_ia_p(ia_p):
    for ia, p in ia_p.items():
        with p.oneshot():
            cpu_pct = p.cpu_percent()
            mem = p.memory_info().vms

        print(f"{ia}: CPU: {cpu_pct}%, Memory: {hurry.filesize.size(mem)}")


try:
    load_sciond_ips()
except FileNotFoundError:
    pass
