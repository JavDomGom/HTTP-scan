import getopt
import json
import logging
import os
import requests
import sys

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urljoin

import settings

log = logging.getLogger(__name__)

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class HTTPscan:
    """ HTTP  scan tool  to test  the  state of  security for  websites  on the
    public internet. """

    def __init__(self):
        """ Class constructor. """

        self.url = 'https://http-observatory.security.mozilla.org'
        self._default_options = {'verify': False, 'proxies': False}

    def _request(
        self, method, endpoint, headers=None, data=None, params=None, **kwargs
    ):
        """ Manage the request before send it.

        Attributes:
            method (str):   HTTP method.
            endpoint (str): End of URI's path i.e /dummy/foo
            headers (dict): A dict with  the headers to be  sent along with the
                            request.
            data (dict):    Dictionary,  list  of  tuples, bytes, or  file-like
                            object to send in the body of the :class:Request.
            params (dict):  Dictionary, list of  tuples or bytes to send in the
                            query string for the :class:Request.
            **kwargs:       Optional arguments that request takes.

        See also:
            https://requests.readthedocs.io/en/master/api/#main-interface
        """

        headers = headers or {}
        options = {**self._default_options, **kwargs}

        func = getattr(requests, method)
        uri = urljoin(self.url, endpoint.lstrip('/'))
        res = func(uri, headers=headers, data=data, params=params, **options)

        log.debug(f'Making request uri: {uri}; method: {method}')
        log.debug(f'Response status: {res.status_code}')

        if res.status_code < 200 or res.status_code > 399:
            log.error(f'Response text: {res.text}')
        elif res.status_code != 204:  # No content
            return res.text

    def read_file(self, file):
        try:
            log.debug(f'Reading websites file "{file}".')

            with open(file, 'r', encoding='utf-8') as f:
                return f.read().splitlines()
        except FileNotFoundError:
            print(f'Websites file "{file}" not found.')
            sys.exit(1)

    def postAnalyze(self, host, hidden=True, rescan=True):
        """ Used  to invoke  a  new scan  of  a website. By  default,  the HTTP
        Observatory  will return  a  cached site  result if  the site  has been
        scanned anytime  in the previous  24 hours. Regardless  of the value of
        rescan, a  site can  not be scanned at  a frequency  greater than every
        three minutes. It will return a single scan object on success.

        Attributes:
            :host (str):    Hostname (required).
            :hidden (str):  Setting  to  "true"  will hide a  scan from  public
                            results returned by getRecentScans.
            :rescan (str):  Setting to "true" forces a rescan of a site.
        """

        headers = {'Accept': 'application/json'}

        return self._request(
            'post',
            '/api/v1/analyze',
            headers=headers,
            params={
                'host': host,
                'hidden': hidden,
                'rescan': rescan
            }
        )

    def getAnalyze(self, host):
        """ This is used to  retrieve the  results  of an existing, ongoing, or
        completed scan. Returns a scan object on success.

        Attributes:
            :host (str):    Hostname (required).
        """

        headers = {'Accept': 'application/json'}

        return self._request(
            'get',
            '/api/v1/analyze',
            headers=headers,
            params={'host': host}
        )

    def getScanResults(self, scan):
        """ Each  scan consists  of a  variety  of subtests, including  Content
        Security Policy, Subresource  Integrity, etc. The results  of all these
        tests can  be retrieved  once the scan's state  has been  placed in the
        FINISHED state. It will return a single tests object.

        Attributes:
            :scan (str):    scan_id number from the scan object.
        """

        headers = {'Accept': 'application/json'}

        return self._request(
            'get',
            '/api/v1/getScanResults',
            headers=headers,
            params={'scan': scan}
        )

    def getHostHistory(self, host):
        """ Retrieve the  ten most recent scans  that fall within a given score
        range. Maps hostnames to scores, returning a host history object.

        Attributes:
            :host (str):    Hostname (required).
        """

        headers = {'Accept': 'application/json'}

        return self._request(
            'get',
            '/api/v1/getHostHistory',
            headers=headers,
            params={'host': host}
        )

    def getScannerStates(self):
        """ This  returns  the  state of  the  scanner. It  can be  useful  for
        determining  how busy the HTTP Observatory is. Returns a  Scanner state
        object.
        """

        headers = {'Accept': 'application/json'}

        return self._request(
            'get',
            '/api/v1/getScannerStates',
            headers=headers
        )


def help():
    print('HELP\n')
    print('\tHTTP scan tool  to test the state of security  for websites on the\n\
\tpublic internet.\n')
    usage()
    print('OPTIONS\n')
    print('\t-f, --file\tPlain text file with list of websites to scan. For ')
    print(
        '\t\t\texample:\n\n\
\t\t\t\twebsite0.com\n\
\t\t\t\twebsite1.org\n\
\t\t\t\twebsite2.info\n\
\t\t\t\t...\n\
\t\t\t\twebsiteN.io'
    )


def usage():
    print(f'USAGE\n\tpython3 {sys.argv[0]} -f file.txt\n')


def main():

    try:
        options, remainder = getopt.gnu_getopt(
            sys.argv[1:],
            'f:',
            ['file=']
        )

        if len(options) == 0:
            help()
            sys.exit(1)

    except getopt.GetoptError as err:
        print('ERROR:', err)
        usage()
        sys.exit(1)

    for opt, arg in options:
        if opt in ('-f', '--file'):
            file = arg

    logging.basicConfig(
        filename=f'{settings.LOG_PATH}/HTTPscan.log',
        level=logging.getLevelName(settings.TRACE_LEVEL),
        format='%(asctime)-15s  [%(levelname)s] %(message)s'
    )

    if not os.path.exists(file):
        log.error(f'File "{file}"')

    httpscan = HTTPscan()
    websites = httpscan.read_file(file)

    for website in websites:
        print(json.loads(httpscan.postAnalyze(website)))


if __name__ == '__main__':
    main()
