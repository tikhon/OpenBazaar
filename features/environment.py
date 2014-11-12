# pylint: disable=import-error
from distutils.util import strtobool as _bool
# pylint: enable=import-error
import os

from zmq.eventloop import ioloop

from test_util import remove_peers_from_db

BEHAVE_DEBUG_ON_ERROR = _bool(os.environ.get("BEHAVE_DEBUG_ON_ERROR", "no"))


def after_step(context, step):
    if BEHAVE_DEBUG_ON_ERROR and step.status == "failed":
        # -- ENTER DEBUGGER: Zoom in on failure location.
        # NOTE: Use IPython debugger, same for pdb (basic python debugger).
        import pdb
        pdb.post_mortem(step.exc_traceback)


def before_all(context):
    # -- SET LOG LEVEL: behave --logging-level=ERROR ...
    # on behave command-line or in "behave.ini".
    context.config.setup_logging()


def before_scenario(context, scenario):
    cur = ioloop.IOLoop.current()
    ioloop.IOLoop.clear_current()
    cur.close(all_fds=True)
    newloop = ioloop.IOLoop()
    newloop.make_current()


def after_scenario(context, scenario):
    if context.feature.name == 'CryptoTransportLayer':
        # reset database peers
        for layer in context.layers:
            layer.db.deleteEntries('peers')
    elif context.feature.name == 'Websocket Client Interface':
        # reset database peers
        for i in range(len(context.app)):
            remove_peers_from_db(i)
