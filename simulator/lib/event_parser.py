# Copyright 2015 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`event_parser` --- Event Parser for Simulator
==================================================
"""
# Stdlib
import logging


class EventParser(object):
    """
    Command parser for the events conf file
    """
    def __init__(self, simulator):
        """
        Initialize the Event Parser.

        :param simulator: Instance of simulator class.
        :type simulator: Simulator
        """
        self.simulator = simulator

    def parse(self, command):
        """
        Parses the command and adds an event.

        :param command: The command
        :type command: str
        """
        items = command.split()
        router_name = items[0]
        event_time = float(items[2])
        if items[1] == "start":
            self.start_router(router_name, event_time)
        elif items[1] == "stop":
            self.stop_router(router_name, event_time)
        else:
            logging.error("Command not recognized: %s", items[1])

    def start_router(self, router, time):
        """
        Start the router at specified time.

        :param router: The name of the router(E.g., er1-19er1-16)
        :type router: str
        :param time: Time at which router is to be started
        :type time: float
        """
        self.simulator.add_event(time, cb=self.simulator.start_element,
                                 args=(router,))

    def stop_router(self, router, time):
        """
        Stop the router at specified time.

        :param router: The name of the router(E.g., er1-19er1-16)
        :type router: str
        :param time: Time at which router is to be started
        :type time: float
        """
        self.simulator.add_event(time, cb=self.simulator.stop_element,
                                 args=(router,))
