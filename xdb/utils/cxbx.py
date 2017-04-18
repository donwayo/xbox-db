import re


class XboxTitleLog(object):

    version_re = re.compile('EmuMain: Cxbx-Reloaded Version ([0-9a-f]{8}).*\n')
    library_re = re.compile('HLE: \* Searching HLE database for (.*) version 1.0.([0-9]{4})\.\.\. Found\n')
    function_re = re.compile('HLE: 0x([0-9A-F]{8}) -> ([^ ]*)(?: \((.*)\))?\n')

    xbe_info_re = re.compile(
        'al Signature[^<]+<Hex Dump>([^<]+)[^\0]*Title ID[^:]+: 0x([A-F0-9]{8})[^\0]+Title[^:]+: L?"([^"]*)"',
        flags=re.M
    )
    xbe_info_libs_re = re.compile(
        r'Library Name[^:]*: (?P<name>[^\r\n]+)[\r\n]+' +
        'Ver[^\.]+\.0\.(?P<ver>\d{4})[\r\n]+Flags[^:]+:.*' +
        'QFEVersion : 0x(?P<QFE>\d{4})',
        flags=re.M
    )

    def __init__(self, krnl_debug_name, xbe_file):
        self.source_file = krnl_debug_name
        self.hle_detection_entry = self.parse_log(self.source_file)

    @staticmethod
    def parse_xbe_info(contents):
        xbe_info = {
            'signature': None,
            'title_id': None,
            'title_name': None,
            'disk_path': '/',
            'file_name': 'default.xbe',
            'libs': [],
            'contents': ''
        }

        m_match = XboxTitleLog.xbe_info_re.search(contents)

        m_groups = m_match.groups() if m_match else None

        if m_groups and len(m_groups) == 3:
            signature, title_id, xbe_info['title_name'] = m_groups
            xbe_info['signature'] = re.sub('[^A-F0-9]', '', signature.upper())
            xbe_info['libs'] = [lib.groupdict() for lib in XboxTitleLog.xbe_info_libs_re.finditer(contents)]
            xbe_info['title_id'] = title_id.upper()
            xbe_info['contents'] = contents

        return xbe_info

    @staticmethod
    def parse_log(source_file):
        hle_detection_entry = {
            'cxbx_version': None,
            'title_id': None,
            'signature': None,
            'xdk_libraries': {},
            'xdk_functions': {}
        }

        for line in source_file:

            # TODO: Account for sections, libraries and passes.

            m = XboxTitleLog.function_re.match(line)
            if m:
                address, func, extra = m.groups()
                hle_detection_entry['xdk_functions'][address] = (func, extra)
                continue

            m = XboxTitleLog.library_re.match(line)
            if m:
                library, version = m.groups()
                hle_detection_entry['xdk_libraries'][library] = version
                continue

            if not hle_detection_entry['cxbx_version']:
                version = XboxTitleLog.version_re.findall(line)
                if version:
                    hle_detection_entry['cxbx_version'] = version[0]

        return hle_detection_entry
