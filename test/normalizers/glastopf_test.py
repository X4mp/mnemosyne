# Copyright (C) 2012 Johnny Vestergaard <jkv@unixcluster.dk>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import unittest
from normalizers import glastopf_events
from datetime import datetime


class GlastopfTests(unittest.TestCase):

    def test_channels(self):
        """
        Test that the channel variable exists.
        """
        self.assertTrue(glastopf_events.GlastopfEvents.channels)

    def test_event(self):
        """
        Test if a valid glastopf json message get parsed as expected
        """
        input_string = """{"pattern": "rfi", "request": {"body": "", "parameters": ["a=b"], "url": "/someURL?a=b", "header": {"Accept-Language": "en-US", "Accept-Encoding": "gzip", "Connection": "close", "Accept": "*/*", "User-Agent": "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)", "Host": "www.something.com"}, "version": "HTTP/1.1", "method": "GET"}, "filename": null, "source": ["1.2.3.4", 49111], "time": "2012-12-14 12:22:51", "response": "HTTP/1.1 200 OK\\r\\nConnection: close\\r\\nContent-Type: text/html; charset=UTF-8\\r\\n\\r\\n"}"""

        request = {
            'host': 'www.something.com',
            'header': '{"Accept-Language": "en-US", "Accept-Encoding": "gzip", "Host": "www.something.com", "Accept": "*/*", "User-Agent": "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)", "Connection": "close"}',
            'body': '',
            'verb': 'GET',
            'url': 'http://www.something.com/someURL?a=b', }

        session_http = {'request': request}

        session = {
            'timestamp': datetime(2012, 12, 14, 12, 22, 51),
            'source_ip': '1.2.3.4',
            'source_port': 49111,
            'destination_port': 80,
            'honeypot': 'glastopf',
            'protocol': 'http',
            'session_http': session_http
        }

        expected_output = [{'session': session}]

        sut = glastopf_events.GlastopfEvents()
        actual = sut.normalize(input_string, 'glastopf_events', None)

        #Test number of root items
        self.assertEqual(len(expected_output), len(actual))

        #Test session
        self.assertEqual(expected_output[0]['session'], actual[0]['session'])

        #Test subtype, session_http
        self.assertEqual(expected_output[0]['session']['session_http'], actual[0]['session']['session_http'])
        #Test request
        self.assertEqual(expected_output[0]['session']['session_http']['request'], actual[0]['session']['session_http']['request'])

        #test dork response
        self.assertEqual(1, actual[0]['dork']['count'])
        self.assertEqual('inurl', actual[0]['dork']['type'])
        self.assertEqual('/someURL', actual[0]['dork']['content'])
        self.assertTrue('timestamp' in actual[0]['dork'])

    def test_make_url_actual(self):
        """
        Test if a valid http request can be parsed to a valid URL.
        """

        #Actual request intercepted by glastopf. (Host sanitized!)
        input_dict = {'request':
                     {'body': '', 'parameters': ['/shop.pl/page'], 'url': '/shop.pl/page',
                      'header':
                     {'Accept-Language': 'en-US', 'Accept-Encoding': 'gzip',
                      'Host': 'XXXX09.YYYYYYY.PPPP.org', 'Accept': '*/*', 'User-Agent':
                      'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
                      'Connection': 'close'},
                      'version': 'HTTP/1.1', 'method': 'GET'}}
        expected_url = 'http://XXXX09.YYYYYYY.PPPP.org/shop.pl/page'

        sut = glastopf_events.GlastopfEvents()

        actual = sut.make_url(input_dict)
        self.assertEqual(expected_url, actual)

    def test_make_url_no_host(self):
        """
        Test if a http request without Host header gets parsed to a realative url.
        """

        input_dict = {'request':
                     {'body': '', 'parameters': [], 'url': '/jimboo',
                      'header':
                     {'Accept-Language': 'en-US', 'Accept-Encoding': 'gzip',
                      'Accept': '*/*', 'User-Agent':
                      'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
                      'Connection': 'close'},
                      'version': 'HTTP/1.1', 'method': 'GET'}}
        expected_url = '/jimboo'

        sut = glastopf_events.GlastopfEvents()

        actual = sut.make_url(input_dict)
        self.assertEqual(expected_url, actual)

    def test_make_url_basic_parsing(self):
        """
        Test if url can be parsed into the expected subelements
        """

        input_dict = {'request':
                     {'body': '', 'parameters': [], 'url': '/shop.pl/page;thisisaparam?a=b&c=d',
                      'header':
                     {'Accept-Language': 'en-US', 'Accept-Encoding': 'gzip',
                      'Host': 'a.b.c.d', 'Accept': '*/*', 'User-Agent':
                      'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
                      'Connection': 'close'},
                      'version': 'HTTP/1.1', 'method': 'GET'}}

        sut = glastopf_events.GlastopfEvents()

        actual = sut.make_url(input_dict)

        expected_url = 'http://a.b.c.d/shop.pl/page;thisisaparam?a=b&c=d'
        self.assertEqual(expected_url, actual)

    def test_make_dork(self):

        input_dict =    {'request':
                        {'body': '', 'parameters': [], 'url': '/shop.pl/page;thisisaparam?a=b&c=d',
                         'header':
                        {'Accept-Language': 'en-US', 'Accept-Encoding': 'gzip',
                         'Host': 'a.b.c.d', 'Accept': '*/*', 'User-Agent':
                         'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
                         'Connection': 'close'},
                         'version': 'HTTP/1.1', 'method': 'GET'}}

        #input and expected output
        in_url_out_dork = ( ('http://somesite.pp/nillermanden.php', '/nillermanden.php'),
                            ('http://somesite.com/jinxed', '/jinxed'),
                            ('http://somesite.com/jinxed?a=b&c=d', '/jinxed'),
                            ('/goodbeer', '/goodbeer'))

        sut = glastopf_events.GlastopfEvents()

        for (input_, expected_output) in in_url_out_dork:
            input_dict['request']['url'] = input_
            result = sut.make_dork(input_dict)
            self.assertEqual(result['content'], expected_output)
            self.assertEqual(result['type'], 'inurl')
            self.assertEqual(result['count'], 1)
            self.assertTrue ('timestamp' in result)

if __name__ == '__main__':
    unittest.main()
