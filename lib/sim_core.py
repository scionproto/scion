"""
sim_core.py

Copyright 2015 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from itertools import count
from queue import PriorityQueue
import logging

class Event:
    """
    Description of Events that will be simulated
    """

    def __init__(self, event_id, event_time, cb, args):
        """
        :param event_id: unique ID to identify the event
        :type event_id: int
        :param cb: function to be executed
        :type cb: callback function
        :param args: arguments to be passed onto the callback function
        :type args: tuple
        """
        self.eid = event_id;
        self.event_time = event_time;
        self.cb = cb
        self.args = args

    def __lt__(self, other):
        return self.event_time < other.event_time

    def get_eid(self):
        """
        :returns: event id
        :rtype: int
        """
        return self.eid

    def get_event_time(self):
        """
        :returns: event time
        :rtype: float
        """
        return self.event_time

    def run(self):
        """
        Executes the event
        """
        self.cb(*self.args)

class Simulator:
    def __init__(self):
        """
        Create a Simulator instance.

        :returns: the newly-created Simulator instance
        :rtype: Simulator
        """
        self.element_list={}
        self.event_pq = PriorityQueue()
        self.curr_time = 0
        self.stop_time = 0
        self.event_id = count()	# unique sequence count
        self.removed = []	# list of removed (not expired or executed) events

    def add_element (self, addr, element):
        self.element_list[addr] = element

    def add_event (self, time, **kwargs):
        """
        Schedule a Event 
        Event can be described either by
        1. Providing a Callback function to be summoned
        2. Specifying the IP address of the Object to be called
            (Implicitly assumes that the Function to be called is sim_recv())
        

        :param time: relative time that the event would be executed (sec)
        :type time: double
        :param cb: callback function to be executed
        :type kwargs: arguments as a dictionary
        :param kwargs: dictionary

        :returns: event id
        :rtype: int
        """
        if time < 0:
            return -1

        event_time = self.curr_time + time

        if 'args' in kwargs:
            args = kwargs['args']
        else:
            args = ()

        if not isinstance(args, tuple):
            return -1

        if 'dst' in kwargs:
            dst = kwargs['dst']
            try:
                o = self.element_list[dst]
            except KeyError:
                logging.warning('no object mapped to %s', dst)
                return -1

            o = self.element_list[dst]
            try:
                cb = getattr(o, 'sim_recv')
            except AttributeError:
                logging.warning('could not find sim_recv()')
                return -1
            if len(args) != 3:
                logging.warning('arg should be (pkt, src, dst)')
                return -1

        elif 'cb' in kwargs:
            cb = kwargs['cb']
        else:
            logging.warning('invalid description of the event')
            return -1

        eid = next(self.event_id)

        self.event_pq.put(Event(eid, event_time, cb, args))

        return eid   

    def remove_event (self, event_id):
        """
        Remove Event specified by event_id
        """
        self.removed.append(event_id)

    def set_stop_time(self, time):
        """
        Set time at which the simulator will stop

        :param time: time at which the simulator will terminate (sec)
        :type time: double
        """
        self.stop_time = time;

    def get_curr_time(self):
        """
        Get Virtual Time
        """
        return self.curr_time

    def run(self):
        """
        Start the simulation. Simulation will terminate if 
        no event is scheduled or if stop time is reached.
        """

        for k in self.element_list:
            self.element_list[k].run()

        while not self.event_pq.empty():
            event = self.event_pq.get()
            event_time = event.get_event_time()
            if self.stop_time != 0 and self.stop_time < event_time:
                break
            elif event.get_eid() not in self.removed:
                self.curr_time = event_time
                event.run()

        self.clean()

    def terminate(self):
        """
        Immediately stop the simulation
        """
        while not self.event_pq.empty():
            self.event_pq.get()

    def clean(self):
        """
        Clean all instances
        """
        for k in self.element_list:
            try:
                do_clean = getattr(self.element_list[k], 'clean')
            except AttributeError:
                continue
            do_clean()
