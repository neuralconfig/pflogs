"""Tests for the PF log parser module."""

import os
import pytest
from pflogs.core.pf_parser import PFLogParser


class TestPFLogParser:
    """Test cases for the PFLogParser class."""
    
    def test_parse_line(self):
        """Test parsing a single log line."""
        parser = PFLogParser()
        
        # Test with a TCP log line
        tcp_line = "2025-03-17T14:54:08+00:00 john1-rwg.ruckusdemos.net pf[22382] 00:00:05.679886 rule 1.fRXG.48/0(match): block in on igb0: 147.185.132.40.49282 > 70.35.182.103.5984: Flags [S], seq 2792467998, win 1024, options [mss 1460], length 0"
        result = parser.parse_line(tcp_line)
        
        assert result is not None
        assert result['hostname'] == 'john1-rwg.ruckusdemos.net'
        assert result['action'] == 'block'
        assert result['direction'] == 'in'
        assert result['interface'] == 'igb0'
        assert result['src_ip'] == '147.185.132.40'
        assert result['src_port'] == '49282'
        assert result['dst_ip'] == '70.35.182.103'
        assert result['dst_port'] == '5984'
        assert result['protocol'] == 'TCP'
        assert result['tcp_flags'] == 'S'
        assert result['seq'] == 2792467998
        assert result['win'] == 1024
        assert result['length'] == 0
        
        # Test with a UDP log line
        udp_line = "2025-03-17T14:58:10+00:00 john1-rwg.ruckusdemos.net pf[22382] 00:00:00.606036 rule 1.fRXG.48/0(match): block in on igb0: 160.79.104.10.443 > 70.35.182.103.60342: UDP, length 22"
        result = parser.parse_line(udp_line)
        
        assert result is not None
        assert result['hostname'] == 'john1-rwg.ruckusdemos.net'
        assert result['action'] == 'block'
        assert result['direction'] == 'in'
        assert result['interface'] == 'igb0'
        assert result['src_ip'] == '160.79.104.10'
        assert result['src_port'] == '443'
        assert result['dst_ip'] == '70.35.182.103'
        assert result['dst_port'] == '60342'
        assert result['protocol'] == 'UDP'
        assert result['length'] == 22
    
    def test_invalid_line(self):
        """Test parsing an invalid log line."""
        parser = PFLogParser()
        result = parser.parse_line("This is not a valid log line")
        assert result is None


if __name__ == "__main__":
    pytest.main(["-v", __file__])