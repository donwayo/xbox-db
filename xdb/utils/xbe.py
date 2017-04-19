#
# xbe.py - Xbox xbe decoder
#
# Based on: http://www.caustik.com/cxbx/download/xbe.htm
# TODO: A future version of the library could use ctypes.structures to overcome this.
# TODO: Add logging
import io
from collections import namedtuple
import struct
import hashlib
import datetime
import codecs

version = '1.0.0'

# Fields in an xbe header
XbeHeaderBase = namedtuple('XbeHeader',
                           'magic digital_signature base_addr size_of_headers size_of_image size_of_image_header '
                           'time_date certificate_addr sections section_headers_addr init_flags entry_addr tls_addr '
                           'pe_stack_commit pe_heap_reserve pe_heap_commit pe_base_addr pe_sizeof_image '
                           'pe_checksum pe_time_date debug_path_name_addr debug_file_name_addr '
                           'debug_unicode_file_name_addr kernel_image_thunk_addr non_kernel_image_import_dir_addr '
                           'library_versions library_versions_addr kernel_library_version_addr '
                           'xapi_library_version_addr logo_bitmap_addr sizeof_logo_bitmap'
                           )

# Fields in an xbe cert
XbeCertBase = namedtuple('XbeCert',
                         'size time_date title_id raw_title_name alternate_title_id allowed_media game_region '
                         'game_ratings disk_number version lan_key signature_key title_alternate_signature_key'
                         )

# Fields in an xbe section header
XbeSectionHeaderBase = namedtuple('XbeSectionHeader',
                                  'section_flags virtual_addr virtual_size raw_addr raw_size section_name_addr '
                                  'section_name_ref_count head_shared_page_ref_count_addr '
                                  'tail_shared_page_ref_count_addr section_digest'
                                  )

# Fields in the library metadata
XbeLibBase = namedtuple('XbeLib',
                        'library_name major_version minor_version build_version library_flags'
                        )

XbeTLSBase = namedtuple('XbeTLS',
                        'data_start_addr data_end_addr tls_index_addr tls_callback_addr size_of_zero_fill '
                        'characteristics'

                        )

XBOX_PUBLIC_KEY_M = int.from_bytes(
    b"\xd3\xd7N\xe5f=\xd7\xe6\xc2\xd4\xa3\xa1\xf2\x176\xd4.R\xf6\xd2\x02\x10\xf5d\x9c4{" 
    b"\xff\xef\x7f\xc2\xee\xbd\x05\x8b\xdey\xb4w\x8e[\x8c\x14\x99\xe3\xae\xc6srs\xb5\xfb\x01[" 
    b"XFm\xfc\x8a\xd6\x95\xda\xed\x1b./\xa2)\xe1?\xf1\xb9[" 
    b"dQ.\xa2\xc0\xf7\xba\xb3>\x8au\xff\x06\x92\\\x07&uy\x10]G\xbe\xd1jR\x90\x0b\xaej\x0b3D\x93^\xf9" 
    b"\x9d\xfb\x15\xd9\xa4\x1c\xcfo\xe4q\x94\xbe\x13\x00\xa8R\xca\x07\xbd'\x98\x01\xa1\x9eO\xa3\xed" 
    b"\x9f\xa0\xaas\xc4q\xf3\xe9NrB\x9c\xf09\xce\xbe\x03v\xfa+\x89\x14\x9a\x81\x16\xc1\x80\x8c>k\xaa" 
    b"\x05\xecgZ\xcf\xa5p\xbd`\x0c\xe87\x9d\xeb\xf4R\xeaN`\x9f\xe4i\xcfR\xdbh\xf5\x11\xcbW\x8f\x9d" 
    b"\xa18\n\x0cG\x1b\xb4lZSn&\x98\xf1\x88\xae|\x96\xbc\xf6\xbf\xb0G\x9a\x8d\xe4\xb3\xe2\x98\x85a" 
    b"\xb1\xca_\xf7\x98Q-\x83\x81v\x0c\x88\xba\xd4\xc2\xd5<\x14\xc7r\xda~\xbd\x1bK\xa4",
    "little")

XBOX_PUBLIC_KEY_E = 65537


def mod_exp(base, exponent, modulus):
    """
    Computes s = (base ^ exponent) mod modulus
    (Bruce Schneier: "Applied Cryptography" pp. 244)
    """
    s = 1
    while exponent != 0:
        if exponent & 1:
            s = (s * base) % modulus
        exponent >>= 1
        base = (base * base) % modulus
    return s


class Xbe(object):
    def __init__(self, xbe_file=None, xbe_data=None):

        self._xbe_stream = None

        if xbe_data is not None:
            self._xbe_stream = io.BytesIO(xbe_data)
        elif xbe_file is not None:
            self._xbe_stream = xbe_file
        else:
            raise Exception('No xbe data provided.')

        self._header = None
        self._cert = None
        self._section_headers = None
        self._sections = None
        self._valid_signature = None
        self._libraries = None
        self._tls = None

        if not self.is_xbe(self._xbe_stream):
            raise Exception('Invalid file.')

    @property
    def header(self):
        return self._header if self._header else self._read_header()

    @property
    def certificate(self):
        return self._cert if self._cert else self._read_cert()

    @property
    def sections(self):
        return self._sections if self._sections else self._read_sections()

    def __getitem__(self, item):
        return self.sections[item]

    @property
    def tls(self):
        return self._tls if self._tls else self._read_tls()

    @property
    def libraries(self):
        return self._libraries if self._libraries else self._read_libraries()

    @property
    def valid_signature(self):
        if self._valid_signature is None:
            self.verify_signature()
        return self._valid_signature

    @property
    def debug_path_name(self):
        return self._read_string(self.header.debug_path_name_addr - self.header.base_addr)

    @property
    def debug_file_name(self):
        return self._read_string(self.header.debug_file_name_addr - self.header.base_addr)

    @property
    def debug_unicode_file_name(self):
        return self._read_string(self.header.debug_unicode_file_name_addr - self.header.base_addr, encoding='utf-16le')

    def _read_tls(self):
        # TODO: Fix TLS Address calculation.
        if self.header.tls_addr != 0 and False:
            self._xbe_stream.seek(self.header.tls_addr - self.header.base_addr)
            data = self._xbe_stream.read(XbeTLS.size)
            self._tls = XbeTLS.unpack(data)
        else:
            self._tls = XbeTLS.unpack(b'\0'*24)
        return self._tls

    def _read_string(self, addr, encoding='ascii', rsize=1024):
        string_data = []
        self._xbe_stream.seek(addr)
        reader = codecs.getreader(encoding)(self._xbe_stream)
        c = reader.read(1)
        while c and c != '\0':
            string_data.append(c)
            c = reader.read(1)

        return ''.join(string_data)

    def _read_libraries(self):
        self._libraries = {}

        self._xbe_stream.seek(self.header.library_versions_addr - self.header.base_addr)
        for _ in range(self.header.library_versions):
            xbe_data = self._xbe_stream.read(XbeLib.size)
            lib = XbeLib.unpack(xbe_data)
            self._libraries[lib.name] = lib

        return self._libraries

    def _read_header(self):

        self._xbe_stream.seek(0)
        xbe_data = self._xbe_stream.read(XbeHeader.size)

        self._header = XbeHeader.unpack(xbe_data)
        return self._header

    def _read_cert(self):
        self._xbe_stream.seek(self.header.certificate_addr - self.header.base_addr)
        xbe_data = self._xbe_stream.read(XbeCert.size)
        self._cert = XbeCert.unpack(xbe_data)
        return self._cert

    def _read_sections(self):

        self._xbe_stream.seek(self.header.section_headers_addr - self.header.base_addr)
        xbe_section_headers = [
            XbeSectionHeader.unpack(self._xbe_stream.read(XbeSectionHeader.size)) for _ in range(self.header.sections)
        ]

        self._sections = {}

        for xbe_section_header in xbe_section_headers:
            xbe_section = XbeSection(xbe_section_header, self._xbe_stream, self.header)
            self._sections[xbe_section.name] = xbe_section

        return self._sections

    @staticmethod
    def decode_signature(digital_signature):
        # TODO: Check the PKCS padding, and hash type stuff.
        signature = int.from_bytes(digital_signature, 'little')
        ct_signature = mod_exp(signature, XBOX_PUBLIC_KEY_E, XBOX_PUBLIC_KEY_M).to_bytes(256, 'little')
        signed_digest_list = list(ct_signature[:20])
        signed_digest_list.reverse()

        return bytes(signed_digest_list)

    def verify_signature(self):

        self._valid_signature = False

        # 1. Verify section integrity
        sections_valid = all([s.validate() for s in self.sections.values()])

        if not sections_valid:
            # TODO: Raise an exception.
            return False

        # 2. Calculate header SHA-1 digest (leaving out the magic, and digital signature fields):
        #    digest = SHA-1(header.length + header[0x104:])
        self._xbe_stream.seek(0x104)
        header_size = self.header.size_of_headers - 0x104
        header_bytes = self._xbe_stream.read(header_size)

        sha1 = hashlib.sha1()
        sha1.update(struct.pack('I', header_size))
        sha1.update(header_bytes)
        header_digest = sha1.digest()

        # 3. Decrypt signature
        #    Use RSA to decrypt the digital signature and check the padding.

        signature_hash = Xbe.decode_signature(self.header.digital_signature)

        # 4. Verify that it matches to the one calculated earlier.
        self._valid_signature = header_digest == signature_hash

        return self._valid_signature

    @staticmethod
    def is_xbe(stream):
        stream.seek(0)
        magic = stream.read(4)
        return magic == b'XBEH'

    def get_dump(self):
        dump = []
        dump.append("XBE information generated by xbe.py (Version {version} ({date})))\r\n".format(
            version=version, date=datetime.date.today()
        ))
        dump.append('Title identified as "{name}"\r\n'.format(name=self.certificate.title_name))

        dump.append('Dumping XBE file header...\r\n')
        dump.append('Magic Number                     : {magic}'.format(magic=self.header.magic.decode()))
        dump.append('Digitial Signature               : <Hex Dump>')  # Keeping the typo :)
        hex_signature = self.header.digital_signature.hex().upper()
        dump.append(
            (35 * ' ') + ('\r\n' + 35 * ' ').join([hex_signature[s:s + 32] for s in range(0, len(hex_signature), 32)])
            + '\r\n' + (35 * ' ') + '</Hex Dump>'
        )
        dump.append('Base Address                     : 0x{base:08X}'.format(base=self.header.base_addr))
        dump.append('Size of Headers                  : 0x{0:08X}'.format(self.header.size_of_headers))
        dump.append('Size of Image                    : 0x{0:08X}'.format(self.header.size_of_image))
        dump.append('Size of Image Header             : 0x{0:08X}'.format(self.header.size_of_image_header))
        dump.append('TimeDate Stamp                   : 0x{r:08X} ({f:%a %b  %w %H:%M:%S %Y})'.format(
            r=self.header.time_date,
            f=datetime.datetime.fromtimestamp(self.header.time_date)))
        dump.append('Certificate Address              : 0x{0:08X}'.format(self.header.certificate_addr))
        dump.append('Number of Sections               : 0x{0:08X}'.format(self.header.sections))
        dump.append('Section Headers Address          : 0x{0:08X}'.format(self.header.section_headers_addr))
        dump.append('Init Flags                       : 0x{0:08X}'.format(self.header.init_flags))
        dump.append('Entry Point                      : 0x{0:08X}'.format(self.header.entry_addr))
        dump.append('TLS Address                      : 0x{0:08X}'.format(self.header.tls_addr))
        dump.append('(PE) Stack Commit                : 0x{0:08X}'.format(self.header.pe_stack_commit))
        dump.append('(PE) Heap Reserve                : 0x{0:08X}'.format(self.header.pe_heap_reserve))
        dump.append('(PE) Heap Commit                 : 0x{0:08X}'.format(self.header.pe_heap_commit))
        dump.append('(PE) Base Address                : 0x{0:08X}'.format(self.header.pe_base_addr))
        dump.append('(PE) Size of Image               : 0x{0:08X}'.format(self.header.pe_sizeof_image))
        dump.append('(PE) Checksum                    : 0x{0:08X}'.format(self.header.pe_checksum))
        dump.append('(PE) TimeDate Stamp              : 0x{r:08X} ({f:%a %b  %w %H:%M:%S %Y})'.format(
            r=self.header.pe_time_date,
            f=datetime.datetime.fromtimestamp(self.header.pe_time_date)))
        dump.append('Debug Pathname Address           : 0x{r:08X} ("{f}")'.format(
            r=self.header.debug_path_name_addr,
            f=self.debug_path_name))
        dump.append('Debug Filename Address           : 0x{r:08X} ("{f}")'.format(
            r=self.header.debug_file_name_addr,
            f=self.debug_file_name))
        dump.append('Debug Unicode filename Address   : 0x{r:08X} (L"{f}")'.format(
            r=self.header.debug_unicode_file_name_addr,
            f=self.debug_unicode_file_name))
        dump.append('Kernel Image Thunk Address       : 0x{0:08X}'.format(self.header.kernel_image_thunk_addr))
        dump.append('NonKernel Import Dir Address     : 0x{0:08X}'.format(self.header.non_kernel_image_import_dir_addr))
        dump.append('Library Versions                 : 0x{0:08X}'.format(self.header.library_versions))
        dump.append('Library Versions Address         : 0x{0:08X}'.format(self.header.library_versions_addr))
        dump.append('Kernel Library Version Address   : 0x{0:08X}'.format(self.header.kernel_library_version_addr))
        dump.append('XAPI Library Version Address     : 0x{0:08X}'.format(self.header.xapi_library_version_addr))
        dump.append('Logo Bitmap Address              : 0x{0:08X}'.format(self.header.logo_bitmap_addr))
        dump.append('Logo Bitmap Size                 : 0x{0:08X}'.format(self.header.sizeof_logo_bitmap))

        dump.append('\r\nDumping XBE Certificate...\r\n')

        dump.append('Size of Certificate              : 0x{0:08X}'.format(self.certificate.size))
        dump.append('TimeDate Stamp                   : 0x{r:08X} ({f:%a %b  %w %H:%M:%S %Y})'.format(
            r=self.certificate.time_date,
            f=datetime.datetime.fromtimestamp(self.certificate.time_date)))
        dump.append('Title ID                         : 0x{0:08X}'.format(self.certificate.title_id))
        dump.append('Title                            : L"{0}"'.format(self.certificate.title_name))
        dump.append('Alternate Titles IDs             : 0x{0:08X}'.format(self.certificate.alternate_title_ids[0]))
        for title_id in self.certificate.alternate_title_ids[1:]:
            dump.append('                                   0x{0:08X}'.format(title_id))
        dump.append('Allowed Media                    : 0x{0:08X}'.format(self.certificate.allowed_media))
        dump.append('Game Region                      : 0x{0:08X}'.format(self.certificate.game_region))
        dump.append('Game Ratings                     : 0x{0:08X}'.format(self.certificate.game_ratings))
        dump.append('Disk Number                      : 0x{0:08X}'.format(self.certificate.disk_number))
        dump.append('Version                          : 0x{0:08X}'.format(self.certificate.version))
        dump.append('LAN Key                          : {0}'.format(self.certificate.lan_key.hex().upper()))
        dump.append('Signature Key                    : {0}'.format(self.certificate.signature_key.hex().upper()))
        dump.append('Title Alternate Signature Keys : <Hex Dump>')
        for alternate_key in self.certificate.title_alternate_signature_keys:
            dump.append('                                   {0}'.format(alternate_key.hex().upper()))
        dump.append('                                   </Hex Dump>\r\n')
        dump.append('Dumping XBE Section Headers...\r\n')
        dump.append('')

        for section in self.sections.values():
            dump.append('Section Name                     : 0x{0:08X} ("{1}")'.format(
                section.header.section_name_addr,
                section.name))
            dump.append('Flags                            : 0x{0:08X}'.format(section.header.section_flags))
            dump.append('Virtual Address                  : 0x{0:08X}'.format(section.header.virtual_addr))
            dump.append('Virtual Size                     : 0x{0:08X}'.format(section.header.virtual_size))
            dump.append('Raw Address                      : 0x{0:08X}'.format(section.header.raw_addr))
            dump.append('Size of Raw                      : 0x{0:08X}'.format(section.header.raw_size))
            dump.append('Section Name Address             : 0x{0:08X}'.format(section.header.section_name_addr))
            dump.append('Section Reference Count          : 0x{0:08X}'.format(section.header.section_name_ref_count))
            dump.append(
                'Head Shared Reference Count Addr : 0x{0:08X}'.format(section.header.head_shared_page_ref_count_addr))
            dump.append(
                'Tail Shared Reference Count Addr : 0x{0:08X}'.format(section.header.tail_shared_page_ref_count_addr))
            dump.append('Section Digest                   : {0}'.format(section.header.section_digest.hex().upper()))

            dump.append('')

        dump.append('Dumping XBE Library Versions...\r\n')

        for lib in self.libraries.values():
            dump.append('Library Name                     : {0}'.format(lib.name))
            dump.append('Version                          : {0}.{1}.{2}'.format(
                lib.major_version,
                lib.minor_version,
                lib.build_version))
            dump.append('Flags                            : QFEVersion : 0x{qfe:04X}, {retail}, {approved}'.format(
                qfe=lib.qfe_version,
                retail='Debug' if lib.debug else 'Retail',
                approved=XbeLib.approval[lib.approved]))

            dump.append('')

        dump.append('Dumping XBE TLS...\r\n')
        dump.append('Data Start Address               : 0x{0:08X}'.format(self.tls.data_start_addr))
        dump.append('Data End Address                 : 0x{0:08X}'.format(self.tls.data_end_addr))
        dump.append('TLS Index Address                : 0x{0:08X}'.format(self.tls.tls_index_addr))
        dump.append('TLS Callback Address             : 0x{0:08X}'.format(self.tls.tls_callback_addr))
        dump.append('Size of Zero Fill                : 0x{0:08X}'.format(self.tls.size_of_zero_fill))
        dump.append('Characteristics                  : 0x{0:08X}'.format(self.tls.characteristics))

        return '\r\n'.join(dump)


class XbeSectionHeader(XbeSectionHeaderBase):
    size = 56

    @property
    def writeable(self):
        return self.section_flags & 1

    @property
    def preload(self):
        return self.section_flags & 2

    @property
    def executable(self):
        return self.section_flags & 4

    @property
    def inserted_file(self):
        return self.section_flags & 8

    @property
    def head_page_read_only(self):
        return self.section_flags & 16

    @property
    def tail_page_read_only(self):
        return self.section_flags & 32

    @classmethod
    def unpack(cls, data_buffer):
        data_tuple = struct.unpack('9I20s', data_buffer)
        return cls._make(data_tuple)


class XbeHeader(XbeHeaderBase):
    XOR_KT_DEBUG = 0xEFB1F152
    XOR_KT_RETAIL = 0x5B6D40B6
    XOR_ET_DEBUG = 0x94859D4B
    XOR_ET_RETAIL = 0xA8FC57AB

    size = 376
    fmt = '4s256s29I'

    @property
    def entry_addr_retail(self):
        return self.entry_addr ^ self.XOR_ET_RETAIL

    @property
    def entry_addr_debug(self):
        return self.entry_addr ^ self.XOR_KT_DEBUG

    @property
    def init_flags_mount_utility_drive(self):
        return self.init_flags & 1

    @property
    def init_flags_format_utility_drive(self):
        return self.init_flags & 2

    @property
    def init_flags_limit_64mb(self):
        return self.init_flags & 4

    @property
    def init_flags_dont_setup_hd(self):
        return self.init_flags & 8

    @classmethod
    def unpack(cls, data_buffer):
        data_tuple = struct.unpack(XbeHeader.fmt, data_buffer)
        return cls._make(data_tuple)


class XbeCert(XbeCertBase):
    size = 464

    @property
    def alternate_title_ids(self):
        return struct.unpack('16I', self.alternate_title_id)

    @property
    def title_name(self):
        return self.raw_title_name.decode('utf-16').rstrip('\0')

    @property
    def title_alternate_signature_keys(self):
        return struct.unpack('16s'*16, self.title_alternate_signature_key)

    @classmethod
    def unpack(cls, data_buffer):
        data_tuple = struct.unpack('3I80s64s5I16s16s256s', data_buffer)
        return cls._make(data_tuple)


class XbeSection(object):
    @property
    def name(self):
        return self._name.split(b'\0')[0].decode('ascii')

    def validate(self):
        actual_section_digest = hashlib.sha1(b''.join([
            self.header.raw_size.to_bytes(4, byteorder='little'),
            self.data
        ])).digest()
        return actual_section_digest == self.header.section_digest

    def __init__(self, xbe_section_header, xbe_stream, xbe_header):
        self._data = None

        self._xbe_stream = xbe_stream
        self._xbe_header = xbe_header

        self.header = xbe_section_header

        # Load name
        self._xbe_stream.seek(self.header.section_name_addr - xbe_header.base_addr)
        self._name = self._xbe_stream.read(8)

    @property
    def data(self):
        return self._data if self._data else self.read_section_data()

    def read_section_data(self):
        self._xbe_stream.seek(self.header.raw_addr)
        self._data = self._xbe_stream.read(self.header.raw_size)
        return self._data


class XbeLib(XbeLibBase):
    size = 16

    approval = ('Unapproved', 'Possibly Approved', 'Approved')

    @property
    def qfe_version(self):
        return self.library_flags & 0x1FFF

    @property
    def approved(self):
        return (self.library_flags & 0x6000) >> 13

    @property
    def debug(self):
        return self.library_flags & 0x8000

    @property
    def name(self):
        return self.library_name.split(b'\0')[0].decode('ascii')

    @classmethod
    def unpack(cls, data_buffer):
        data_tuple = struct.unpack('8s4H', data_buffer)
        return cls._make(data_tuple)


class XbeTLS(XbeTLSBase):
    size = 24

    @classmethod
    def unpack(cls, data_buffer):
        data_tuple = struct.unpack('6I', data_buffer)
        return cls._make(data_tuple)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Dump XBE information like Cxbx would.')
    parser.add_argument('xbe', help='Xbox executable file path.',
                        metavar='Xbox Executable', type=argparse.FileType('rb'))
    parser.add_argument('--verify-signature', '-s', help='Only verify the digital signature.',
                        action='store_true')

    args = parser.parse_args()

    xbe = Xbe(args.xbe)

    # Verify digital signature
    if args.verify_signature:
        if xbe.verify_signature():
            print('Valid signature :)')
        else:
            print('Invalid signature :(')
        return

    # Dump information like Cxbx

    print(xbe.get_dump())

# TODO: Describe the following...
r"""
Init Flags                       : 0x00000000 [Setup Harddisk] 
Entry Point                      : 0xA8FFCB9C (Retail: 0x00039C37, Debug: 0x3C7A56D7)
Kernel Image Thunk Address       : 0x5B763836 (Retail: 0x001B7880, Debug: 0xB4C7C964)

Dumping XBE Section Headers...

Flags                            : 0x00000000 (Preload) (Executable) (Head Page RO) 

Dumping XBE TLS...

Data Start Address               : 0x00000000
Data End Address                 : 0x00000000
TLS Index Address                : 0x0020F6F0
TLS Callback Address             : 0x00000000
Size of Zero Fill                : 0x00000090
Characteristics                  : 0x00000000

"""

if __name__ == '__main__':
    main()
