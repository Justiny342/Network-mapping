import unittest
from unittest.mock import patch, MagicMock
from main import get_vulnerabilities, scan_host, verify_vulnerabilities

class TestVulnerabilityScanner(unittest.TestCase):

    @patch('main.requests.get')
    def test_get_vulnerabilities_success(self, mock_get):
        # Mock the API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"total": 1, "data": [{"cve_id": "CVE-2021-1234"}]}
        mock_get.return_value = mock_response

        # Test with a valid CPE
        cpe = "cpe:/a:apache:http_server:2.4.7"
        vulnerabilities = get_vulnerabilities(cpe)
        self.assertIsNotNone(vulnerabilities)
        self.assertEqual(vulnerabilities["total"], 1)
        self.assertEqual(vulnerabilities["data"][0]["cve_id"], "CVE-2021-1234")

        # Test CPE formatting
        get_vulnerabilities("cpe:/a:apache:http_server:2.4.7")
        mock_get.assert_called_with("https://cvedb.shodan.io/cves?cpe23=cpe:2.3:a:apache:http_server:2.4.7")

    @patch('main.requests.get')
    def test_get_vulnerabilities_failure(self, mock_get):
        # Mock a failed API response
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = Exception("Test error")
        mock_get.return_value = mock_response

        vulnerabilities = get_vulnerabilities("cpe:/a:some:product:1.0")
        self.assertIsNone(vulnerabilities)

    @patch('main.nmap.PortScanner')
    def test_scan_host_no_verify(self, mock_port_scanner):
        # Mock the nmap scanner
        mock_nm = MagicMock()

        mock_host_obj = MagicMock()
        mock_host_obj.hostname.return_value = 'localhost'
        mock_host_obj.state.return_value = 'up'
        mock_host_obj.__contains__.side_effect = lambda item: item == 'tcp'

        mock_nm.__getitem__.return_value = mock_host_obj
        mock_nm.all_hosts.return_value = ['127.0.0.1']

        mock_tcp_obj = MagicMock()
        mock_tcp_obj.keys.return_value = [22, 80]
        def getitem(name):
            if name == 22:
                return {'state': 'open', 'name': 'ssh', 'product': 'OpenSSH', 'version': '8.2p1', 'cpe': 'cpe:/a:openbsd:openssh:8.2p1'}
            if name == 80:
                return {'state': 'closed'}
        mock_tcp_obj.__getitem__.side_effect = getitem
        mock_host_obj.__getitem__.return_value = mock_tcp_obj

        mock_port_scanner.return_value = mock_nm

        with patch('main.get_vulnerabilities') as mock_get_vulns:
            mock_get_vulns.return_value = {"total": 0, "data": []}
            results = scan_host('127.0.0.1', verify=False)

        self.assertEqual(len(results), 1)
        host_result = results[0]
        self.assertEqual(len(host_result['protocols']), 1)
        tcp_protocol = host_result['protocols'][0]
        self.assertEqual(len(tcp_protocol['ports']), 1)
        ssh_port = tcp_protocol['ports'][0]
        self.assertEqual(ssh_port['name'], 'ssh')
        self.assertNotIn('verification', ssh_port)


    @patch('main.nmap.PortScanner')
    def test_scan_host_with_verify(self, mock_port_scanner):
        # This test is more complex because scan_host calls nmap, and then verify_vulnerabilities also calls nmap
        # We need to mock both calls. We can use side_effect on the mock_port_scanner

        # Mock for the first nmap call in scan_host
        mock_nm_scan = MagicMock()
        mock_nm_scan.all_hosts.return_value = ['127.0.0.1']
        mock_host_obj_scan = MagicMock()
        mock_host_obj_scan.hostname.return_value = 'localhost'
        mock_host_obj_scan.state.return_value = 'up'
        mock_host_obj_scan.__contains__.side_effect = lambda item: item == 'tcp'
        mock_nm_scan.__getitem__.return_value = mock_host_obj_scan
        mock_tcp_obj_scan = MagicMock()
        mock_tcp_obj_scan.keys.return_value = [22]
        mock_tcp_obj_scan.__getitem__.return_value = {'state': 'open', 'name': 'ssh', 'product': 'OpenSSH', 'version': '8.2p1', 'cpe': 'cpe:/a:openbsd:openssh:8.2p1'}
        mock_host_obj_scan.__getitem__.return_value = mock_tcp_obj_scan

        # Mock for the second nmap call in verify_vulnerabilities
        mock_nm_verify = MagicMock()
        mock_nm_verify.__getitem__.return_value = {
            'tcp': {
                22: {
                    'script': {
                        'vulners': 'CVE-2021-1234'
                    }
                }
            }
        }

        # When PortScanner is called, return the first mock, then the second
        mock_port_scanner.side_effect = [mock_nm_scan, mock_nm_verify]

        with patch('main.get_vulnerabilities') as mock_get_vulns:
            mock_get_vulns.return_value = {"total": 0, "data": []}
            results = scan_host('127.0.0.1', verify=True)

        self.assertEqual(len(results), 1)
        host_result = results[0]
        port_info = host_result['protocols'][0]['ports'][0]
        self.assertEqual(port_info['verification'], 'CVE-2021-1234')

    @patch('main.nmap.PortScanner')
    def test_verify_vulnerabilities(self, mock_port_scanner):
        # Mock the nmap scanner for the verification function
        mock_nm = MagicMock()
        mock_nm.__getitem__.return_value = {
            'tcp': {
                80: {
                    'script': {
                        'vulners': 'CVE-2021-1234'
                    }
                }
            }
        }
        mock_port_scanner.return_value = mock_nm

        result = verify_vulnerabilities('127.0.0.1', 80)
        self.assertEqual(result, 'CVE-2021-1234')


if __name__ == '__main__':
    unittest.main()
