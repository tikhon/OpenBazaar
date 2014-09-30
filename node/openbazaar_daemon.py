import logging
import json
import multiprocessing
import os
import signal
import time

import tornado.web
from zmq.eventloop import ioloop

from db_store import Obdb
from market import Market
from network_util import get_random_free_tcp_port
from transport import CryptoTransportLayer
import upnp
from util import open_default_webbrowser, is_mac
from ws import WebSocketHandler

if is_mac():
    from util import osx_check_dyld_library_path
    osx_check_dyld_library_path()

ioloop.install()


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.redirect("/html/index.html")


class OpenBazaarStaticHandler(tornado.web.StaticFileHandler):
    def set_extra_headers(self, path):
        self.set_header("X-Frame-Options", "DENY")
        self.set_header("X-Content-Type-Options", "nosniff")


class OpenBazaarContext(object):
    """
    This Object holds all of the runtime parameters
    necessary to start an OpenBazaar instance.

    This object is convenient to pass on method interfaces,
    and reduces issues of API inconsistencies (as in the order
    in which parameters are passed, which can cause bugs)
    """
    def __init__(self,
                 nat_status,
                 my_market_ip,
                 my_market_port,
                 http_ip,
                 http_port,
                 db_path,
                 log_path,
                 log_level,
                 market_id,
                 bm_user,
                 bm_pass,
                 bm_port,
                 seed_peers,
                 seed_mode,
                 dev_mode,
                 dev_nodes,
                 disable_upnp,
                 disable_stun_check,
                 disable_open_browser,
                 disable_sqlite_crypt,
                 enable_ip_checker):
        self.nat_status = nat_status
        self.my_market_ip = my_market_ip
        self.my_market_port = my_market_port
        self.http_ip = http_ip
        self.http_port = http_port
        self.db_path = db_path
        self.log_path = log_path
        self.log_level = log_level
        self.market_id = market_id
        self.bm_user = bm_user
        self.bm_pass = bm_pass
        self.bm_port = bm_port
        self.seed_peers = seed_peers
        self.seed_mode = seed_mode
        self.dev_mode = dev_mode
        self.dev_nodes = dev_nodes
        self.disable_upnp = disable_upnp
        self.disable_stun_check = disable_stun_check
        self.disable_open_browser = disable_open_browser
        self.disable_sqlite_crypt = disable_sqlite_crypt
        self.enable_ip_checker = enable_ip_checker

        # to deduct up-time, and (TODO) average up-time
        # time stamp in (non-local) Coordinated Universal Time format.
        self.started_utc_timestamp = long(time.time())

    def __repr__(self):
        r = {"nat_status.nat_type": self.nat_status['nat_type'] if self.nat_status is not None else None,
             "nat_status.external_ip": self.nat_status['external_ip'] if self.nat_status is not None else None,
             "nat_status.external_port": self.nat_status['external_port'] if self.nat_status is not None else None,
             "my_market_ip": self.my_market_ip,
             "my_market_port": self.my_market_port,
             "http_ip": self.http_ip,
             "http_port": self.http_port,
             "log_path": self.log_path,
             "market_id": self.market_id,
             "bm_user": self.bm_user,
             "bm_pass": self.bm_pass,
             "bm_port": self.bm_port,
             "seed_peers": self.seed_peers,
             "seed_mode": self.seed_mode,
             "dev_mode": self.dev_mode,
             "dev_nodes": self.dev_nodes,
             "log_level": self.log_level,
             "db_path": self.db_path,
             "disable_upnp": self.disable_upnp,
             "disable_open_browser": self.disable_open_browser,
             "disable_sqlite_crypt": self.disable_sqlite_crypt,
             "enable_ip_checker": self.enable_ip_checker,
             "started_utc_timestamp": self.started_utc_timestamp,
             "uptime_in_secs": long(time.time()) - long(self.started_utc_timestamp)
             }

        return json.dumps(r).replace(", ", ",\n  ")


class MarketApplication(tornado.web.Application):
    def __init__(self, ob_ctx):

        db = Obdb(ob_ctx.db_path, ob_ctx.disable_sqlite_crypt)

        self.transport = CryptoTransportLayer(ob_ctx, db)

        self.market = Market(self.transport, db)

        peers = ob_ctx.seed_peers if not ob_ctx.seed_mode else []
        self.transport.join_network(peers)

        handlers = [
            (r"/", MainHandler),
            (r"/main", MainHandler),
            (r"/html/(.*)", OpenBazaarStaticHandler, {'path': './html'}),
            (r"/ws", WebSocketHandler,
                dict(transport=self.transport, market_application=self, db=db))
        ]

        # TODO: Move debug settings to configuration location
        settings = dict(debug=True)
        tornado.web.Application.__init__(self, handlers, **settings)

    def get_transport(self):
        return self.transport

    def setup_upnp_port_mappings(self, http_port, p2p_port):
        upnp.PortMapper.DEBUG = False
        print "Setting up UPnP Port Map Entry..."
        self.upnp_mapper = upnp.PortMapper()

        # for now let's always clean mappings every time.
        self.upnp_mapper.clean_my_mappings(p2p_port)

        result_tcp_p2p_mapping = self.upnp_mapper.add_port_mapping(p2p_port,
                                                                   p2p_port)
        print ("UPnP TCP P2P Port Map configuration done (%s -> %s) => %s" %
               (str(p2p_port), str(p2p_port), str(result_tcp_p2p_mapping)))

        result_udp_p2p_mapping = self.upnp_mapper.add_port_mapping(p2p_port,
                                                                   p2p_port,
                                                                   'UDP')
        print ("UPnP UDP P2P Port Map configuration done (%s -> %s) => %s" %
               (str(p2p_port), str(p2p_port), str(result_udp_p2p_mapping)))

        result = result_tcp_p2p_mapping and result_udp_p2p_mapping
        if not result:
            print "Warning: UPnP was not setup correctly. Try doing a port forward on %s and start the node again with -j" % p2p_port

        return result

    def cleanup_upnp_port_mapping(self):
        try:
            if self.upnp_mapper is not None:
                print "Cleaning UPnP Port Mapping -> ", \
                    self.upnp_mapper.clean_my_mappings(self.transport.port)
        except AttributeError:
            print "[openbazaar] MarketApplication.clean_upnp_port_mapping() failed!"

    def shutdown(self, x=None, y=None):
        print "MarketApplication.shutdown!"
        locallogger = logging.getLogger(
            '[%s] %s' % (self.market.market_id, 'root')
        )
        locallogger.info("Received TERMINATE, exiting...")

        # application.get_transport().broadcast_goodbye()
        self.cleanup_upnp_port_mapping()
        tornado.ioloop.IOLoop.instance().stop()

        self.transport.shutdown()
        os._exit(0)


def start_io_loop():
    if not tornado.ioloop.IOLoop.instance():
        ioloop.install()

    try:
        tornado.ioloop.IOLoop.instance().start()
    except Exception as e:
        print "openbazaar::start_io_loop Exception:", e
        raise e


def node_starter(ob_ctxs):
    # This is the target for the the Process which
    # will spawn the children processes that spawn
    # the actual OpenBazaar instances.

    for ob_ctx in ob_ctxs:
        p = multiprocessing.Process(target=start_node, args=(ob_ctx,), name="Process::openbazaar_daemon::target(start_node)")
        p.daemon = False   # python has to wait for this user thread to end.
        p.start()


def start_node(ob_ctx):
    print "Start Node!"
    try:
        logging.basicConfig(
            level=int(ob_ctx.log_level),
            format=u'%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename=ob_ctx.log_path
        )
        logging._defaultFormatter = logging.Formatter(u'%(message)s')
        locallogger = logging.getLogger('[%s] %s' % (ob_ctx.market_id, 'root'))

        handler = logging.handlers.RotatingFileHandler(
            ob_ctx.log_path,
            encoding='utf-8',
            maxBytes=50000000,
            backupCount=1
        )
        locallogger.addHandler(handler)
    except Exception as e:
        print "Could not setup logger, continuing: ", e.message

    application = MarketApplication(ob_ctx)

    error = True
    p2p_port = ob_ctx.my_market_port

    if ob_ctx.http_port == -1:
        ob_ctx.http_port = get_random_free_tcp_port(8889, 8988)

    while error:
        try:
            application.listen(ob_ctx.http_port, ob_ctx.http_ip)
            error = False
        except Exception:
            ob_ctx.http_port += 1

    if not ob_ctx.disable_upnp:
        application.setup_upnp_port_mappings(ob_ctx.http_port, p2p_port)
    else:
        print "Disabling upnp setup"

    locallogger.info("Started OpenBazaar Web App at http://%s:%s" %
                     (ob_ctx.http_ip, ob_ctx.http_port))

    print "Started OpenBazaar Web App at http://%s:%s" % (ob_ctx.http_ip, ob_ctx.http_port)

    if not ob_ctx.disable_open_browser:
        open_default_webbrowser('http://%s:%s' % (ob_ctx.http_ip, ob_ctx.http_port))

    try:
        signal.signal(signal.SIGTERM, application.shutdown)
    except ValueError:
        # not the main thread
        pass

    start_io_loop()
