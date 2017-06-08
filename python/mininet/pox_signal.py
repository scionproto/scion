import signal

from pox.core import core

# Create a logger for this component
log = core.getLogger()


def launch():
    signal.signal(signal.SIGTERM, _term)


def _term(signum, _):
    log.info("Got signal, quitting")
    core.quit()
