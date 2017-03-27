import re


class XboxTitleLog(object):

    version_re = re.compile('EmuMain: Cxbx-Reloaded Version ([0-9a-f]{8}).*\n')
    library_re = re.compile('HLE: \* Searching HLE database for (.*) version 1.0.([0-9]{4})\.\.\. Found\n')
    function_re = re.compile('HLE: 0x([0-9A-F]{8}) -> ([^ ]*)(?: \((.*)\))?\n')

    def __init__(self, krnl_debug_name, xbe_file):
        self.source_file = krnl_debug_name

        self.hle_detection_entry = {
            'cxbx_version': None,
            'title_id': None,
            'certificate_signature': None,
            'xdk_libraries': {},
            'xdk_functions': {}
        }

        # TODO: Parse title info

        self.parse_log()

    def parse_log(self):
        with open(self.source_file) as source_file:
            for line in source_file:

                # TODO: Account for sections, libraries and passes.

                m = self.function_re.match(line)
                if m:
                    address, function, extra = m.groups()
                    self.hle_detection_entry['xdk_functions'][address] = (function, extra)
                    continue

                m = self.library_re.match(line)
                if m:
                    library, version = m.groups()
                    self.hle_detection_entry['xdk_libraries'][library] = version
                    continue

                if not self.hle_detection_entry['cxbx_version']:
                    version = self.version_re.findall(line)
                    if version:
                        self.hle_detection_entry['cxbx_version'] = version[0]
