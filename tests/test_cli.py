import pathlib
import subprocess
import tempfile
import unittest
import os

ROOT = pathlib.Path(__file__).resolve().parents[1]
SUFFIX = ".exe" if os.name == "nt" else ""
EXECUTABLE = ROOT / ("pcap_dump"+SUFFIX)
if not EXECUTABLE.exists():
    EXECUTABLE = ROOT / "build" / ("pcap_dump"+SUFFIX)

def invoke(*arguments, text=None):
    return subprocess.run([str(EXECUTABLE), *map(str,arguments)], input=text, text=True, capture_output=True)

class CliTests(unittest.TestCase):
    def test_help(self):
        result = invoke("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage:", result.stdout)

    def test_port_filter(self):
        capture = ROOT/"sample_capture.pcap"
        self.assertEqual(len(invoke(capture).stdout.splitlines()), 4)
        self.assertEqual(len(invoke(capture, 1, 2).stdout.splitlines()), 1)
        self.assertNotEqual(invoke(capture, 6000, 5000).returncode, 0)

    def test_truncation(self):
        contents = (ROOT/"sample_capture.pcap").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            capture = pathlib.Path(directory)/"truncated.pcap"
            for length in (0, 23, 25, len(contents)-1):
                capture.write_bytes(contents[:length])
                self.assertNotEqual(invoke(capture).returncode, 0)

    def test_big_endian_nanoseconds(self):
        import struct
        contents = (ROOT/"sample_capture.pcap").read_bytes()
        converted = bytearray(struct.pack(">IHHIIII",0xa1b23c4d,2,4,0,0,65535,1))
        offset = 24
        while offset < len(contents):
            seconds, fraction, length, original = struct.unpack_from("<IIII",contents,offset)
            converted += struct.pack(">IIII",seconds,fraction*1000,length,original)
            converted += contents[offset+16:offset+16+length]
            offset += 16+length
        with tempfile.TemporaryDirectory() as directory:
            capture = pathlib.Path(directory)/"big-endian.pcap"
            capture.write_bytes(converted)
            result = invoke(capture)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(len(result.stdout.splitlines()), 4)

if __name__ == "__main__":
    unittest.main()
