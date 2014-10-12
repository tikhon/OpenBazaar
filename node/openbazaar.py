#!./env/bin/python
# OpenBazaar's launcher script.
# Authors: Angel Leon (@gubatron)

import os
import sys
import argparse
import multiprocessing
import psutil
from openbazaar_daemon import node_starter
from openbazaar_daemon import OpenBazaarContext
from setup_db import setup_db
from network_util import init_aditional_STUN_servers, check_NAT_status
from threading import Thread


def get_defaults():
    return {'MARKET_ID': 1,
            'SERVER_IP': '127.0.0.1',
            'SERVER_PORT': 12345,
            'LOG_DIR': 'logs',
            'LOG_FILE': 'production.log',
            'DB_DIR': 'db',
            'DB_FILE': 'ob.db',
            'DEV_DB_FILE': 'ob-dev-{0}.db',
            'DEVELOPMENT': False,
            'DEV_NODES': 3,
            'SEED_MODE': False,
            'SEED_HOSTNAMES': ['seed.openbazaar.org',
                               'seed2.openbazaar.org',
                               'seed.openlabs.co',
                               'us.seed.bizarre.company',
                               'eu.seed.bizarre.company'],
            'DISABLE_UPNP': False,
            'DISABLE_STUN_CHECK': False,
            'DISABLE_OPEN_DEFAULT_WEBBROWSER': False,
            'DISABLE_SQLITE_CRYPT': False,
            # CRITICAL=50, ERROR=40, WARNING=30, DEBUG=10, NOTSET=0
            'LOG_LEVEL': 10,
            'NODES': 3,
            'HTTP_IP': '127.0.0.1',
            'HTTP_PORT': None,
            'BITMESSAGE_USER': None,
            'BITMESSAGE_PASS': None,
            'BITMESSAGE_PORT': -1,
            'ENABLE_IP_CHECKER': False,
            'CONFIG_FILE': None
            }


def create_argument_parser():
    defaults = get_defaults()

    parser = argparse.ArgumentParser(usage=usage(),
                                     add_help=False)

    parser.add_argument('-i', '--server-public-ip',
                        default=defaults['SERVER_IP'])

    parser.add_argument('-p', '--server-public-port',
                        default=defaults['SERVER_PORT'],
                        type=int)

    parser.add_argument('-k', '--http-ip',
                        default=defaults['HTTP_IP'])

    parser.add_argument('-q', '--http-port',
                        type=int, default=defaults['HTTP_PORT'])

    default_log_path = os.path.join(defaults['LOG_DIR'], defaults['LOG_FILE'])
    parser.add_argument('-l', '--log',
                        default=default_log_path)

    parser.add_argument('--log-level',
                        default=defaults['LOG_LEVEL'])

    parser.add_argument('-d', '--development-mode',
                        action='store_true',
                        default=defaults['DEVELOPMENT'])

    default_db_path = os.path.join(defaults['DB_DIR'], defaults['DB_FILE'])
    parser.add_argument("--db-path",
                        default=default_db_path)

    parser.add_argument('-n', '--dev-nodes',
                        type=int,
                        default=-1)

    parser.add_argument('--bitmessage-user', '--bmuser',
                        default=defaults['BITMESSAGE_USER'])

    parser.add_argument('--bitmessage-pass', '--bmpass',
                        default=defaults['BITMESSAGE_PASS'])

    parser.add_argument('--bitmessage-port', '--bmport',
                        type=int,
                        default=defaults['BITMESSAGE_PORT'])

    parser.add_argument('-u', '--market-id',
                        default=defaults['MARKET_ID'])

    parser.add_argument('-j', '--disable-upnp',
                        action='store_true',
                        default=defaults['DISABLE_UPNP'])

    parser.add_argument('--disable-stun-check',
                        action='store_true',
                        default=defaults['DISABLE_STUN_CHECK'])

    parser.add_argument('-S', '--seed-mode',
                        action='store_true',
                        default=defaults['SEED_MODE'])

    parser.add_argument('-s', '--seeds',
                        nargs='*',
                        default=defaults['SEED_HOSTNAMES'])

    parser.add_argument('--disable-open-browser',
                        action='store_true',
                        default=defaults['DISABLE_OPEN_DEFAULT_WEBBROWSER'])

    parser.add_argument('--disable-sqlite-crypt',
                        action='store_true',
                        default=defaults['DISABLE_SQLITE_CRYPT'])

    parser.add_argument('--config-file',
                        default=defaults['CONFIG_FILE'])

    parser.add_argument('--enable-ip-checker',
                        action='store_true',
                        default=defaults['ENABLE_IP_CHECKER'])

    parser.add_argument('command')
    return parser


def usage():
    return """
openbazaar [options] <command>

    COMMANDS
        start            Start OpenBazaar
        stop             Stop OpenBazaar

    EXAMPLES
        openbazaar start
        openbazaar --disable-upnp --seed-mode start
        openbazaar --enable-ip-checker start
        openbazaar -d --dev-nodes 4 -j --disable-stun-check start
        openbazaar --development-mode -n 4 --disable-upnp start

    OPTIONS
    -i, --server-public-ip <ip address>
        Server public IP

    -p, --server-public-port <port number>
        Server public (P2P) port (default 12345)

    -k, --http-ip <ip address>
        Web interface IP (default 127.0.0.1; use 0.0.0.0 for any)

    -q, --http-port <port number>
        Web interface port (-1 = random by default)

    -l, --log <file path>
        Log file path (default 'logs/production.log')

    --log-level <level>
        Log verbosity level (default: 10 - DEBUG)
        Expected <level> values are:
           0 - NOT SET
          10 - DEBUG
          20 - INFO
          30 - WARNING
          40 - ERROR
          50 - CRITICAL

    -d, --development-mode
        Enable development mode

    -n, --dev-nodes
        Number of dev nodes to start up

    --db-path
        Database file path. (default 'db/od.db')

    --disable-sqlite-crypt
        Disable encryption on sqlite database

    --bitmessage-user, --bmuser
        Bitmessage API username

    --bitmessage-pass, --bmpass
        Bitmessage API password

    --bitmessage-port, --bmport
        Bitmessage API port

    -u, --market-id
        Market ID

    -j, --disable-upnp
        Disable automatic UPnP port mappings

    --disable-stun-check
        Disable automatic port setting via STUN servers (NAT Punching attempt)

    -S, --seed-mode
        Enable seed mode

    --disable-open-browser
        Don't open preferred web browser automatically on start

    --config-file
        Disk path to an OpenBazaar configuration file

    --enable-ip-checker
        Enable periodic IP address checking.
        Useful in case you expect your IP to change rapidly.

"""


def create_openbazaar_contexts(arguments, nat_status):
    """
    Returns List<OpenBazaarContext>.

    If we are on production mode, the list will contain a
    single OpenBazaarContext object based on the arguments passed.

    If a configuration file is passed, settings from the configuration
    file will be read first, and whatever other parameters have been
    passed via the command line will override the settings on the
    configuration file.
    """
    defaults = get_defaults()

    server_public_ip = defaults['SERVER_IP']
    if server_public_ip != arguments.server_public_ip:
        server_public_ip = arguments.server_public_ip
    elif nat_status is not None:
        print nat_status
        server_public_ip = nat_status['external_ip']

    # "I'll purposefully leave these seemingly useless Schlemiel-styled
    # comments as visual separators to denote the beginning and end of
    # these ifs statements. They're actually nice to have when maintaining
    # so many ifs blocks. Feel free to remove post merge if they truly
    # annoy you." -Gubatron :)

    # market port
    server_public_port = defaults['SERVER_PORT']
    if arguments.server_public_port is not None and\
       arguments.server_public_port != server_public_port:
        server_public_port = arguments.server_public_port
    elif nat_status is not None:
        # override the port for p2p communications with the one
        # obtained from the STUN server.
        server_public_port = nat_status['external_port']

    # http ip
    http_ip = defaults['HTTP_IP']
    if arguments.http_ip is not None:
        http_ip = arguments.http_ip

    # http port
    http_port = defaults['HTTP_PORT']
    if arguments.http_port is not None and arguments.http_port != http_port:
        http_port = arguments.http_port

    # log path (requires LOG_DIR to exist)
    if not os.path.exists(defaults['LOG_DIR']):
        os.makedirs(defaults['LOG_DIR'], 0755)

    log_path = os.path.join(defaults['LOG_DIR'], defaults['LOG_FILE'])
    if arguments.log is not None and arguments.log != log_path:
        log_path = arguments.log

    # log level
    log_level = defaults['LOG_LEVEL']
    if arguments.log_level is not None and\
       arguments.log_level != log_level:
        log_level = arguments.log_level

    # market id
    market_id = None
    if arguments.market_id is not None:
        market_id = arguments.market_id

    # bm user
    bm_user = defaults['BITMESSAGE_USER']
    if arguments.bitmessage_user is not None and\
       arguments.bitmessage_user != bm_user:
        bm_user = arguments.bitmessage_user

    # bm pass
    bm_pass = defaults['BITMESSAGE_PASS']
    if arguments.bitmessage_pass is not None and\
       arguments.bitmessage_pass != bm_pass:
        bm_pass = arguments.bitmessage_pass

    # bm port
    bm_port = defaults['BITMESSAGE_PORT']
    if arguments.bitmessage_port is not None and\
       arguments.bitmessage_port != bm_port:
        bm_port = arguments.bitmessage_port

    # seed_peers
    seed_peers = defaults['SEED_HOSTNAMES']
    if len(arguments.seeds) > 0:
        seed_peers = seed_peers + arguments.seeds

    # seed_mode
    seed_mode = arguments.seed_mode

    # dev_mode
    dev_mode = defaults['DEVELOPMENT']
    if arguments.development_mode != dev_mode:
        dev_mode = arguments.development_mode

    # dev nodes
    dev_nodes = -1
    if arguments.development_mode:
        dev_nodes = defaults['DEV_NODES']
        if arguments.dev_nodes != dev_nodes:
            dev_nodes = arguments.dev_nodes

    # db path
    if not os.path.exists(defaults['DB_DIR']):
        os.makedirs(defaults['DB_DIR'], 0755)

    db_path = os.path.join(defaults['DB_DIR'], defaults['DB_FILE'])
    if arguments.db_path != db_path:
        db_path = arguments.db_path

    # disable upnp
    disable_upnp = defaults['DISABLE_UPNP'] or arguments.disable_upnp

    # disable stun check
    disable_stun_check = defaults['DISABLE_STUN_CHECK']
    if arguments.disable_stun_check:
        disable_stun_check = True

    # disable open browser
    disable_open_browser = defaults['DISABLE_OPEN_DEFAULT_WEBBROWSER']
    if arguments.disable_open_browser:
        disable_open_browser = True

    # disable sqlite crypt
    disable_sqlite_crypt = defaults['DISABLE_SQLITE_CRYPT']
    if arguments.disable_sqlite_crypt != disable_sqlite_crypt:
        disable_sqlite_crypt = True

    # enable ip checker
    enable_ip_checker = defaults['ENABLE_IP_CHECKER']
    if arguments.enable_ip_checker:
        enable_ip_checker = True

    ob_ctxs = []

    if not dev_mode:
        # we return a list of a single element, a production node.
        ob_ctxs.append(OpenBazaarContext(nat_status,
                                         server_public_ip,
                                         server_public_port,
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
                                         enable_ip_checker))
    elif dev_nodes > 0:
        # create OpenBazaarContext objects for each development node.
        i = 1
        db_path = os.path.join(defaults['DB_DIR'], 'this_will_be_ignored')
        db_dirname = os.path.dirname(db_path)
        while i <= dev_nodes:
            db_dev_filename = defaults['DEV_DB_FILE'].format(i)
            db_path = os.path.join(db_dirname, db_dev_filename)
            ob_ctxs.append(OpenBazaarContext(nat_status,
                                             server_public_ip,
                                             server_public_port + i - 1,
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
                                             enable_ip_checker))
            i = i + 1

    return ob_ctxs


def ensure_database_setup(ob_ctx, defaults):
    db_path = ob_ctx.db_path
    default_db_path = os.path.join(defaults['DB_DIR'], defaults['DB_FILE'])
    default_dev_db_path = os.path.join(defaults['DB_DIR'],
                                       defaults['DEV_DB_FILE'])

    if ob_ctx.dev_mode and db_path == default_db_path:
        # override default db_path to developer database path.
        db_path = default_dev_db_path

    # make sure the folder exists wherever it is
    db_dirname = os.path.dirname(db_path)
    if not os.path.exists(db_dirname):
        os.makedirs(db_dirname, 0755)

    if not os.path.exists(db_path):
        # setup the database if file not there.
        print "[openbazaar] bootstrapping database ", os.path.basename(db_path)
        setup_db(db_path)
        print "[openbazaar] database setup completed\n"


def start(arguments):
    defaults = get_defaults()
    init_aditional_STUN_servers()

    # Turn off checks that don't make sense in development mode
    if arguments.development_mode:
        print "DEVELOPMENT MODE! (Disable STUN check and UPnP mappings)"
        arguments.disable_stun_check = True
        arguments.disable_upnp = True

    # Try to get NAT escape UDP port
    nat_status = None
    if not arguments.disable_stun_check:
        print "Checking NAT Status..."
        nat_status = check_NAT_status()
    else:
        assert arguments.server_public_ip is not None

    ob_ctxs = create_openbazaar_contexts(arguments, nat_status)
    for ob_ctx in ob_ctxs:
        ensure_database_setup(ob_ctx, defaults)

    p = multiprocessing.Process(target=node_starter,
                                args=(ob_ctxs,))
    p.start()


def terminate_or_kill_process(process):
    try:
        process.terminate()  # in POSIX, sends SIGTERM.
        process.wait(5)
    except psutil.TimeoutExpired:
        _, alive = psutil.wait_procs([process], None, None)
        if process in alive:
            process.kill()  # sends KILL signal.


def stop():
    my_pid = os.getpid()  # don't kill the killer.
    for process in psutil.process_iter():
        try:
            pdict = process.as_dict()
            if my_pid != int(pdict['pid']) and pdict['cmdline'] is not None:
                cmd = ' '.join(pdict['cmdline'])
                if cmd.find('openbazaar') > -1 and cmd.find('start') > -1:
                    Thread(target=terminate_or_kill_process,
                           args=(process,)).start()
        except psutil.NoSuchProcess:
            pass


def load_config_file_arguments(parser):
    """Loads config file's flags into sys.argv for further argument parsing."""
    parsed_arguments = parser.parse_args()
    if parsed_arguments.config_file is not None:
        config_file_lines = []
        with open(parsed_arguments.config_file) as fp:
            try:
                config_file_lines = fp.readlines()
            except Exception as e:
                print "notice: ignored invalid config file: %s" % (
                    parsed_arguments.config_file
                )
                print e
                return

        # in case user entered config flags
        # in multiple lines, we'll keep only
        # those that don't start with '#'
        # also ignore everything after a '#' character
        # for every line.
        valid_config_lines = []
        for line in config_file_lines:
            if line.startswith('#'):
                continue

            normalized_line = line.strip()
            if line.find('#') != -1:
                normalized_line = line[:line.find('#')]

            if len(normalized_line) > 0:
                valid_config_lines.append(normalized_line)

        # 1. join read lines list into a string,
        # 2. re-split it to make it look like sys.argv
        # 3. get rid of possible '' list elements
        # 4. merge the new arguments from the file into sys.argv
        if len(valid_config_lines) > 0:
            config_file_arguments = [x for x in
                                     ' '.join(valid_config_lines).split(' ')
                                     if len(x) > 0]
            sys.argv[1:1] = config_file_arguments


def main():
    parser = create_argument_parser()
    load_config_file_arguments(parser)
    arguments = parser.parse_args()

    print "Command: '" + arguments.command + "'"

    if arguments.command == 'start':
        start(arguments)
    elif arguments.command == 'stop':
        stop()
    elif arguments.command == 'status':
        pass
    else:
        print "\n[openbazaar] Invalid command '" + arguments.command + "'"
        print "[openbazaar] Valid commands are 'start', 'stop'."
        print "\n[openbazaar] Please try again.\n"

if __name__ == '__main__':
    main()
