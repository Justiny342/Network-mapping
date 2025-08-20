import unittest
from unittest.mock import patch, MagicMock
from main import get_vulnerabilities, scan_host

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
    def test_scan_host(self, mock_port_scanner):
        # Mock the nmap scanner
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ['127.0.0.1']

        mock_host_obj = MagicMock()
        mock_host_obj.hostname.return_value = 'localhost'
        mock_host_obj.state.return_value = 'up'
        mock_host_obj.__contains__.side_effect = lambda item: item == 'tcp'

        # This is how python-nmap structures the data, so we have to mock it this way
        mock_nm.__getitem__.return_value = mock_host_obj
        mock_nm.all_hosts.return_value = ['127.0.0.1']

        # Mocking the protocol access
        mock_host_obj.all_protocols.return_value = ['tcp']
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
            results = scan_host('127.0.0.1')

        self.assertEqual(len(results), 1)
        host_result = results[0]
        self.assertEqual(host_result['host'], '127.0.0.1')
        self.assertEqual(len(host_result['protocols']), 1)
        tcp_protocol = host_result['protocols'][0]
        self.assertEqual(len(tcp_protocol['ports']), 1)
        ssh_port = tcp_protocol['ports'][0]
        self.assertEqual(ssh_port['name'], 'ssh')

if __name__ == '__main__':
    unittest.main()
