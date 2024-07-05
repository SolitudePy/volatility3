# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from typing import List

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist, psscan


class PsxView(interfaces.plugins.PluginInterface):
    """Finds hidden processes with various process listings."""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="psscan", plugin=psscan.PsScan, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pids",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            )
        ]


    def _get_pslist(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pids", None))
        tasks = pslist.PsList.list_tasks(
            self.context, self.config["kernel"], filter_func=filter_func
        )
        return tasks
    

    def _get_psscan(self):
        vmlinux_module_name = self.config["kernel"]
        vmlinux = self.context.modules[vmlinux_module_name]
        tasks = psscan.PsScan.scan_tasks(
            self.context, vmlinux_module_name, vmlinux.layer_name
        )
        return tasks


    def _generator(self):
        """Compares processes in memory from various sources."""

        # Define tasks list of all sources dictionary
        task_sources = {}
        task_sources["psscan"] = self._get_psscan()
        task_sources["pslist"] = self._get_pslist()

        # Define lists for comparison
        pslist_pids = [int(task.pid) for task in self._get_pslist()]
        psscan_pids = [int(task.pid) for task in self._get_psscan()]

        task_dict = {}

        # walk all of tasks list sources
        for _, value in task_sources.items():
            for task in value:
                pid = int(task.pid)
                task_dict[pid] = {
                    'name' : utility.array_to_string(task.comm),
                    "pslist" : pid in pslist_pids,
                    "psscan" : pid in psscan_pids,
                    }

        for pid in task_dict:
            yield (
                0,
                (
                    pid, 
                    task_dict[pid]['name'],
                    task_dict[pid]['pslist'],
                    task_dict[pid]['psscan']
                ),
            )
            

    def run(self):
        headers = [
            ("PID", int),
            ("COMM", str),
            ("PsList", bool),
            ("PsScan", bool)
        ]
        return renderers.TreeGrid(
            headers,
            self._generator()
        )