"""CLI."""

import argparse
import asyncio
import json
import logging
import sys
from contextlib import contextmanager

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from . import __version__ as version
from .api import Broker
from .utils import update_geoip_db, log


def create_parser():
    parser = argparse.ArgumentParser(
        prog='proxybroker',
        add_help=False,
        description='Proxy [Finder | Checker | Server]',
        epilog='''Run '%(prog)s <command> --help'
                  for more information on a command.
                  Suggestions and bug reports are greatly appreciated:
                  https://github.com/constverum/ProxyBroker/issues''',
    )

    subparsers = parser.add_subparsers(
        dest='command',
        title='Commands',
        description='These are common commands used in various situations',
    )
    parser_group = parser.add_argument_group(title='Options')
    add_broker_args(parser_group)
    add_help_arg(parser_group)

    fparser = subparsers.add_parser(
        'find',
        add_help=False,
        help='Find and check proxies',
        description='Find and check proxies with specified parameters',
    )
    fparser_group = fparser.add_argument_group(title='Options')
    add_find_args(fparser_group)
    add_grab_args(fparser_group)
    add_limit_arg(fparser_group)
    add_outfile_arg(fparser_group)
    add_format_arg(fparser_group)
    add_show_stats_arg(fparser_group)
    add_help_arg(fparser_group)

    gparser = subparsers.add_parser(
        'grab',
        add_help=False,
        help='Find proxies without a check',
        description='Find proxies without a check with specified parameters',
    )
    gparser_group = gparser.add_argument_group(title='Options')
    add_grab_args(gparser_group)
    add_limit_arg(gparser_group)
    add_outfile_arg(gparser_group)
    add_format_arg(gparser_group)
    add_show_stats_arg(gparser_group)
    add_help_arg(gparser_group)

    sparser = subparsers.add_parser(
        'serve',
        add_help=False,
        help='Run a local proxy server',
        description='''Run a local proxy server that distributes requests to
                       external proxies, which will be found on the
                       specified parameters''',
    )
    add_serve_args(sparser.add_argument_group(title='Server options'))
    sparser_fgroup = sparser.add_argument_group(title='Find proxies options')
    add_find_args(sparser_fgroup)
    add_grab_args(sparser_fgroup)
    add_limit_arg(
        sparser_fgroup,
        100,
        '''
        When will be found a requested number of working proxies,
        checking of new proxies will be lazily paused.
        See the documentation for more information''',
    )
    add_help_arg(sparser.add_argument_group(title='Common options'))

    uparser = subparsers.add_parser(
        'update-geo',
        add_help=False,
        help='Download and use a detailed GeoIP database',
        description=(
            'Download and use a detailed GeoIP DB to get '
            'additional geolocation information of the proxy '
            '(ISO and name of region, city name).'
        ),
    )
    uparser_group = uparser.add_argument_group(title='Options')
    uparser.set_defaults(func=update_geoip_db)
    add_help_arg(uparser_group)

    return parser


def add_broker_args(group):
    group.add_argument(
        '--max-conn',
        type=int,
        default=200,
        dest='max_conn',
        help='The maximum number of concurrent checks of proxies',
    )
    group.add_argument(
        '--max-tries',
        type=int,
        default=3,
        dest='max_tries',
        help='The maximum number of attempts to check a proxy',
    )
    group.add_argument(
        '--timeout',
        '-t',
        type=int,
        default=8,
        metavar='SECONDS',
        help='''Timeout of a request in seconds.
                The default value is 8 seconds''',
    )
    group.add_argument(
        '--judge',
        action='append',
        dest='judges',
        help='Urls of pages that show HTTP headers and IP address',
    )
    group.add_argument(
        '--provider',
        action='append',
        dest='providers',
        help='Urls of pages where to find proxies',
    )
    group.add_argument(
        '--verify-ssl',
        '-ssl',
        dest='verify_ssl',
        action='store_true',
        help='Flag indicating whether to check the SSL certificates',
    )
    group.add_argument(
        '--log',
        nargs='?',
        default=logging.CRITICAL,
        choices=['NOTSET', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Logging level',
    )
    group.add_argument(
        '--version',
        '-v',
        action='version',
        version='%(prog)s {v}'.format(v=version),
        help='Show program\'s version number and exit',
    )


def add_find_args(group):
    group.add_argument(
        '--types',
        nargs='+',
        type=str.upper,
        required=True,
        choices=['HTTP', 'HTTPS', 'SOCKS4', 'SOCKS5', 'CONNECT:80', 'CONNECT:25'],
        help='Type(s) (protocols) that need to be check on support by proxy',
    )
    group.add_argument(
        '--lvl',
        dest='anon_lvl',
        nargs='+',
        type=str.title,
        choices=['Transparent', 'Anonymous', 'High'],
        help='Level(s) of anonymity (for HTTP only). By default, any level',
    )
    group.add_argument(
        '--data',
        type=argparse.FileType('r'),
        help='''Path to the file with proxies.
                If specified, used instead of providers''',
    )
    group.add_argument('--dnsbl', nargs='+', help='Spam databases for proxy checking')
    group.add_argument(
        '--post',
        action='store_true',
        help='''Flag indicating use POST instead of GET
                for requests when checking proxies''',
    )
    group.add_argument(
        '--strict',
        '-s',
        action='store_true',
        help='''Flag indicating that anonymity levels of the
                types (protocols) supported by a proxy must
                be equal to the requested types and levels of anonymity''',
    )


def add_grab_args(group):
    group.add_argument(
        '--countries',
        '-c',
        nargs='+',
        help='List of ISO country codes where should be located proxies',
    )


def add_serve_args(group):
    group.add_argument(
        '--host',
        type=str,
        default='127.0.0.1',
        help='Host of local proxy server',
    )
    group.add_argument(
        '--port', type=int, default=8888, help='Port of local proxy server'
    )
    group.add_argument(
        '--max-tries',
        type=int,
        dest='srv_max_tries',
        help='''The maximum number of attempts to handle an incoming request.
                If not specified, will be used the value passed to the %(prog)s
                command''',
    )
    group.add_argument(
        '--strategy',
        type=str,
        default='best',
        dest='strategy',
        help='''The strategy used for picking proxy from pool''',
    )
    group.add_argument(
        '--min-queue',
        type=int,
        default=5,
        dest='min_queue',
        help='''The minimum number of proxies to choose from before deciding
                which is the most suitable to use''',
    )
    group.add_argument(
        '--min-req-proxy',
        type=int,
        default=5,
        dest='min_req_proxy',
        help='''The minimum number of processed requests to decide
                whether to use it further or reject''',
    )
    group.add_argument(
        '--max-error-rate',
        type=float,
        default=0.5,
        dest='max_error_rate',
        help='''The maximum percentage of requests that ended
                with an error. For example: 0.5 = 50%%''',
    )
    group.add_argument(
        '--max-resp-time',
        type=int,
        default=8,
        dest='max_resp_time',
        metavar='SECONDS',
        help='''The maximum response time in seconds. If proxy.avg_resp_time exceeds
                this value, proxy will be rejected.
                The default value is 8 seconds''',
    )
    group.add_argument(
        '--prefer-connect',
        action='store_true',
        dest='prefer_connect',
        help='''Flag that indicates whether to use
                the CONNECT method instead of regular requests
                to test HTTPS proxies''',
    )


def add_limit_arg(group, default=0, help=None):
    if help is None:
        help = 'The maximum amount of found proxies'
    group.add_argument(
        '--limit',
        '-l',
        type=int,
        default=default,
        help=help,
    )


def add_outfile_arg(group):
    group.add_argument(
        '--outfile',
        '-o',
        type=argparse.FileType('w'),
        default=sys.stdout,
        help='Path to a result file',
    )


def add_format_arg(group):
    group.add_argument(
        '--format',
        '-f',
        choices=['json', 'txt'],
        default='txt',
        help='The format of the results to output to a file',
    )


def add_show_stats_arg(group):
    group.add_argument(
        '--stats',
        action='store_true',
        dest='show_stats',
        help='Display status of finding and checking in the end',
    )


def add_help_arg(group):
    group.add_argument(
        '--help',
        '-h',
        action='help',
        help='Show this help message and exit',
    )


@contextmanager
def logging_level(level):
    current_level = logging.getLogger().getEffectiveLevel()
    try:
        logging.getLogger().setLevel(level)
        yield
    finally:
        logging.getLogger().setLevel(current_level)


async def run_find(args):
    async def save(proxies):
        async with Broker(proxies) as broker:
            async for proxy in broker:
                if args.format == 'txt':
                    await args.outfile.write(f"{proxy}\n")
                elif args.format == 'json':
                    await args.outfile.write(json.dumps(proxy.as_json()) + '\n')

    broker = Broker(
        max_conn=args.max_conn,
        max_tries=args.max_tries,
        timeout=args.timeout,
        judges=args.judges,
        providers=args.providers,
        verify_ssl=args.verify_ssl,
        loop=asyncio.get_running_loop(),
    )

    tasks = [
        broker.find(
            types=args.types,
            anon_lvl=args.anon_lvl,
            countries=args.countries,
            post=args.post,
            strict=args.strict,
            dnsbl=args.dnsbl,
            limit=args.limit,
            save=save,
        )
    ]

    async with logging_level(args.log):
        await asyncio.gather(*tasks)

    if args.show_stats:
        log(f"\nFound {broker.found_cnt} proxies")
        log(f"Checking completed: {broker.finished_cnt} proxies")
        log(f"Proxies with error: {broker.error_cnt}")


async def run_grab(args):
    async def save(proxies):
        async with Broker(proxies) as broker:
            async for proxy in broker:
                if args.format == 'txt':
                    await args.outfile.write(f"{proxy}\n")
                elif args.format == 'json':
                    await args.outfile.write(json.dumps(proxy.as_json()) + '\n')

    broker = Broker(
        max_conn=args.max_conn,
        max_tries=args.max_tries,
        timeout=args.timeout,
        judges=args.judges,
        providers=args.providers,
        verify_ssl=args.verify_ssl,
        loop=asyncio.get_running_loop(),
    )

    tasks = [
        broker.grab(
            types=args.types,
            countries=args.countries,
            limit=args.limit,
            save=save,
        )
    ]

    async with logging_level(args.log):
        await asyncio.gather(*tasks)

    if args.show_stats:
        log(f"\nGrabbed {broker.found_cnt} proxies")


async def run_serve(args):
    broker = Broker(
        max_conn=args.max_conn,
        max_tries=args.max_tries,
        timeout=args.timeout,
        judges=args.judges,
        providers=args.providers,
        verify_ssl=args.verify_ssl,
        loop=asyncio.get_running_loop(),
    )

    await broker.serve(
        host=args.host,
        port=args.port,
        max_tries=args.srv_max_tries or args.max_tries,
        strategy=args.strategy,
        min_queue=args.min_queue,
        min_req_proxy=args.min_req_proxy,
        max_error_rate=args.max_error_rate,
        max_resp_time=args.max_resp_time,
        prefer_connect=args.prefer_connect,
    )


def main():
    parser = create_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    if args.command == 'find':
        func = run_find
    elif args.command == 'grab':
        func = run_grab
    elif args.command == 'serve':
        func = run_serve
    elif args.command == 'update-geo':
        func = args.func
    else:
        parser.error(f"Unknown command {args.command!r}")

    if asyncio.get_running_loop().is_closed():
        asyncio.set_event_loop(asyncio.new_event_loop())

    try:
        asyncio.run(func(args))
    except KeyboardInterrupt:
        log('\nBye!')


if __name__ == '__main__':
    main()
