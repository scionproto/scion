'Supervisor' allows to manage processes easily, both individually and in groups.

0. Install dependencies (Python 2.7 is required for now)

  sudo apt-get install python-pip
  sudo pip2 install supervisor==3.1.3 && sudo pip2 install supervisor-quick

1. Create 'supervisor' configuration files (among others)

  ./scion.sh topology

2. Check status

  ./supervisor/supervisor.sh status

3. Manage processes

  \# start all processes
  ./supervisor/supervisor.sh start all

  \# stop all processes
  ./supervisor/supervisor.sh stop all

  \# restart all processes in AS1-11
  ./supervisor/supervisor.sh restart as1-11:*

### Caveat 1

The current version of 'supervisor' (3.1.3) supports only Python 2.7, the planned 4.0 version will support both Python branches (2.x and 3.x).

### Caveat 2

Start/stop/restart operations might be a bit slow if the number of processes is large. This will be fixed in the version 4.0, but for now you may want to try the same commands with the 'quick-' prefix ('quickstart', 'quickstop', 'quickrestart'). These are not included in the core 'supervisor' package, but they make it fast ignoring the callback stack.


