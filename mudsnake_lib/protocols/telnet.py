import re
import zlib
from codecs import encode as codecs_encode
from twisted.internet.task import LoopingCall
from twisted.conch.telnet import Telnet, StatefulTelnetProtocol
from twisted.python.compat import _bytesChr as chr, iterbytes

from twisted.conch.telnet import SGA, NAWS, LINEMODE, IAC, WILL, WONT, DO, DONT, NOP, SB, SE, GA

# MSSP: 
MSSP = chr(70)  # b"\x46"
MSSP_VAR = chr(1)  # b"\x01"
MSSP_VAL = chr(2)  # b"\x02"

# MCCP - Mud Compression Protocol
MCCP1 = chr(85)  # b"\x55"
MCCP2 = chr(86)  # b"\x56"
MCCP3 = chr(87)  # b"\x56"
ZLIB_FLUSH = zlib.Z_SYNC_FLUSH
ZLIB_COMPRESS = zlib.compressobj(9)
ZLIB_DECOMPRESS = zlib.decompressobj(9)

# MXP - MUD eXtension Protocol
LINKS_SUB = re.compile(r"\|lc(.*?)\|lt(.*?)\|le", re.DOTALL)
MXP = chr(91)
MXP_TEMPSECURE = "\x1B[4z"
MXP_SEND = MXP_TEMPSECURE + '<SEND HREF="\\1">' + "\\2" + MXP_TEMPSECURE + "</SEND>"

# MSDP - Mud Server Data Protocol
MSDP = chr(69)
MSDP_VAR = chr(1)
MSDP_VAL = chr(2)
MSDP_TABLE_OPEN = chr(3)
MSDP_TABLE_CLOSE = chr(4)

MSDP_ARRAY_OPEN = chr(5)
MSDP_ARRAY_CLOSE = chr(6)

# pre-compiled regexes
# returns 2-tuple
msdp_regex_table = re.compile(
    br"%s\s*(\w*?)\s*%s\s*%s(.*?)%s" % (MSDP_VAR, MSDP_VAL, MSDP_TABLE_OPEN, MSDP_TABLE_CLOSE)
)
# returns 2-tuple
msdp_regex_array = re.compile(
    br"%s\s*(\w*?)\s*%s\s*%s(.*?)%s" % (MSDP_VAR, MSDP_VAL, MSDP_ARRAY_OPEN, MSDP_ARRAY_CLOSE)
)
msdp_regex_var = re.compile(br"%s" % MSDP_VAR)
msdp_regex_val = re.compile(br"%s" % MSDP_VAL)

# GMCP - Generic Mud Communication Protocol
GMCP = chr(201)

MUDSNAKE_TO_GMCP = {
    "client_options": "Core.Supports.Get",
    "get_inputfuncs": "Core.Commands.Get",
    "get_value": "Char.Value.Get",
    "repeat": "Char.Repeat.Update",
    "monitor": "Char.Monitor.Update",
}

# NAWS - Negotiate About Window Size
IS = chr(0)

# TTYPE Support
# telnet option codes
TTYPE = chr(24)  # b"\x18"
SEND = chr(1)  # b"\x01"

# terminal capabilities and their codes
MTTS = [
    (128, "PROXY"),
    (64, "SCREENREADER"),
    (32, "OSC_COLOR_PALETTE"),
    (16, "MOUSE_TRACKING"),
    (8, "XTERM256"),
    (4, "UTF-8"),
    (2, "VT100"),
    (1, "ANSI"),
]

# Begin Telnet Implementation

SUPPORTED_FEATURES = {
    MCCP1: False,
    MCCP2: True,
    MCCP3: True,
    MSSP: True,
    MXP: True,
    MSDP: True,
    GMCP: True,
    NAWS: True,
    TTYPE: True
}

NEGOTIATE_ORDER = [SGA, NAWS, TTYPE, MCCP2, MCCP3, MSSP, MSDP, GMCP, MXP]


class MudTelnetProtocol(StatefulTelnetProtocol):
    delimiter = b'\r\n'
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.negotiationMap = {
            MCCP2: self.negotiate_MCCP2,
            MCCP3: self.negotiate_MCCP3,
            MSDP: self.negotiate_MSDP,
            GMCP: self.negotiate_GMCP,
            NAWS: self.negotiate_NAWS,
            TTYPE: self.negotiate_TTYPE
        }
        
        self.willwontMap = {
            MCCP2: (self.enable_MCCP2, self.disable_MCCP2),
            MCCP3: (self.enable_MCCP3, self.disable_MCCP3),
            NAWS: (self.enable_NAWS, self.disable_NAWS),
            TTYPE: (self.enable_TTYPE, self.disable_TTYPE),
            GMCP: (self.enable_GMCP, self.disable_GMCP),
            MSDP: (self.enable_MSDB, self.disable_MSDP),
            MSSP: (self.enable_MSSP, self.disable_MSSP),
            MXP: (self.enable_MXP, self.disable_MXP),
            SGA: (self.enable_SGA, self.disable_SGA),
            LINEMODE: (self.enable_LINEMODE, self.disable_LINEMODE)
        }
        
        
        self.protocol_flags = {
            'SCREENWIDTH': 78,
            'SCREENHEIGHT': 0,
            'FORCEDENDLINE': True,
            'ANSI': True,
            'XTERM256': False,
            'CLIENTNAME': 'unknown',
            'MCCP2': False,
            'MCCP3': False,
            'GMCP': False,
            'MSDP': False,
            'SCREENREADER': False,
            'ENCODING': "utf-8",
            'NOPKEEPALIVE': True
        }
        
        self.ttype_step = 1

        self.game_data_buffer = b''

        self.inputfuncs_buffer = []

    def applicationDataReceived(self, data):
        self.game_data_buffer += data
        self.processTextCommands()

    def processTextCommands(self):
        if self.delimiter in self.game_data_buffer:
            cmd, remaining = self.game_data_buffer.split(self.delimiter, 1)
            self.inputfuncs_buffer.append(('text', [cmd], dict()))
            self.game_data_buffer = remaining
            if remaining:
                self.processTextCommands()
    
    def connectionMade(self):
        self.do(LINEMODE).addErrback(self.disable_LINEMODE)
        
        for feature in NEGOTIATE_ORDER:
            result = self.will(feature)
            if (cbacks := self.willwontMap.get(feature, None)):
                result.addCallbacks(*cbacks)
        
        self.transport.setTcpKeepAlive(1)
        self.nop_keep_alive = None
        self.toggle_nop_keepalive()

    def enableLocal(self, option):
        return SUPPORTED_FEATURES.get(option, False)

    def enable_MCCP2(self):
        self.begin_MCCP2()
        # delay(2, callback=self.begin_MCCP2)
    
    def disable_MCCP2(self):
        if self.protocol_flags["MCCP2"]:
            self.end_MCCP2()
        #self._write(IAC + DONT + MCCP2)

    def begin_MCCP2(self):
        self._write(IAC + SB + MCCP2 + IAC + SE)
        self.protocol_flags["MCCP2"] = True
    
    def end_MCCP2(self):
        self._write(ZLIB_FLUSH)
        self.protocol_flags["MCCP2"] = False

    def enable_MCCP3(self):
        pass

    def disable_MCCP3(self):
        pass

    def begin_MCCP3(self):
        self.protocol_flags["MCCP3"] = True
    
    def end_MCCP3(self):
        self.protocol_flags["MCCP3"] = False

    def enable_NAWS(self):
        self.requestNegotiation(NAWS)

    def disable_NAWS(self):
        pass

    def enable_TTYPE(self):
        self.requestNegotiation(TTYPE, SEND)

    def disable_TTYPE(self):
        pass
    
    def enable_GMCP(self):
        pass
    
    def disable_GMCP(self):
        pass
    
    def enable_MSDP(self):
        pass
    
    def disable_MSDP(self):
        pass
    
    def enable_MSSP(self):
        pass
    
    def disable_MSSP(self):
        pass
    
    def enable_MXP(self):
        pass
    
    def disable_MXP(self):
        pass
    
    def enable_SGA(self):
        pass
    
    def disable_SGA(self):
        pass
    
    def enable_LINEMODE(self):
        pass
    
    def disable_LINEMODE(self):
        pass
    
    def negotiate_MCCP2(self, data):
        pass
    
    def negotiate_MCCP3(self, data):
        self.begin_MCCP3()
    
    def negotiate_MSDP(self, data):
        pass
    
    def negotiate_GMCP(self, data):
        pass
    
    def negotiate_NAWS(self, data):
        if len(data) == 4:
            width = data[0] + data[1]
            self.protocol_flags["SCREENWIDTH"] = int(codecs_encode(width, "hex"), 16)
            height = data[2] + data[3]
            self.protocol_flags["SCREENHEIGHT"] = int(codecs_encode(height, "hex"), 16)
    
    def negotiate_TTYPE(self, data):

        options = self.protocol_flags

        if options and options.get("TTYPE", False) or self.ttype_step > 3:
            return

        try:
            option = b"".join(data).lstrip(IS).decode()
        except TypeError:
            # option is not on a suitable form for joining
            pass

        if self.ttype_step == 1:
            # this is supposed to be the name of the client/terminal.
            # For clients not supporting the extended TTYPE
            # definition, subsequent calls will just repeat-return this.
            try:
                clientname = option.upper()
            except AttributeError:
                # malformed option (not a string)
                clientname = "UNKNOWN"

            # use name to identify support for xterm256. Many of these
            # only support after a certain version, but all support
            # it since at least 4 years. We assume recent client here for now.
            xterm256 = False
            if clientname.startswith("MUDLET"):
                # supports xterm256 stably since 1.1 (2010?)
                xterm256 = clientname.split("MUDLET", 1)[1].strip() >= "1.1"
                self.protocol_flags["FORCEDENDLINE"] = False

            if clientname.startswith("TINTIN++"):
                self.protocol_flags["FORCEDENDLINE"] = True

            if (
                    clientname.startswith("XTERM")
                    or clientname.endswith("-256COLOR")
                    or clientname
                    in (
                    "ATLANTIS",  # > 0.9.9.0 (aug 2009)
                    "CMUD",  # > 3.04 (mar 2009)
                    "KILDCLIENT",  # > 2.2.0 (sep 2005)
                    "MUDLET",  # > beta 15 (sep 2009)
                    "MUSHCLIENT",  # > 4.02 (apr 2007)
                    "PUTTY",  # > 0.58 (apr 2005)
                    "BEIP",  # > 2.00.206 (late 2009) (BeipMu)
                    "POTATO",  # > 2.00 (maybe earlier)
                    "TINYFUGUE",  # > 4.x (maybe earlier)
            )
            ):
                xterm256 = True

            # all clients supporting TTYPE at all seem to support ANSI
            self.protocol_flags["ANSI"] = True
            self.protocol_flags["XTERM256"] = xterm256
            self.protocol_flags["CLIENTNAME"] = clientname
            self.requestNegotiation(TTYPE, SEND)

        elif self.ttype_step == 2:
            # this is a term capabilities flag
            term = option
            tupper = term.upper()
            # identify xterm256 based on flag
            xterm256 = (
                    tupper.endswith("-256COLOR")
                    or tupper.endswith("XTERM")  # Apple Terminal, old Tintin
                    and not tupper.endswith("-COLOR")  # old Tintin, Putty
            )
            if xterm256:
                self.protocol_flags["ANSI"] = True
                self.protocol_flags["XTERM256"] = xterm256
            self.protocol_flags["TERM"] = term
            # request next information
            self.requestNegotiation(TTYPE, SEND)

        elif self.ttype_step == 3:
            # the MTTS bitstring identifying term capabilities
            if option.startswith("MTTS"):
                option = option[4:].strip()
                if option.isdigit():
                    # a number - determine the actual capabilities
                    option = int(option)
                    support = dict(
                        (capability, True) for bitval, capability in MTTS if option & bitval > 0
                    )
                    self.protocol_flags.update(support)
                else:
                    # some clients send erroneous MTTS as a string. Add directly.
                    self.protocol_flags[option.upper()] = True

            self.protocol_flags["TTYPE"] = True
            # we must sync ttype once it'd done
            self.handshake_done()
        self.ttype_step += 1
    
    def renderOutgoing(self, data):
        return data
    
    def compressData(self, data):
        """
        Applies ZLIB level 9 compression to outgoing data if compression is enabled.
        
        Args:
            data (bytes): Data to be compressed.

        Returns:
            data (bytes): The compressed data.
        """
        if self.protocol_flags['MCCP2']:
            data = ZLIB_COMPRESS.compress(data) + ZLIB_COMPRESS.flush(ZLIB_FLUSH)
        return data

    def sendText(self, data):
        """
        
        
        Args:
            data (bytes): The data to be readied for sending out over the transport.

        Returns:
            data (bytes): The data that will be sent over the transport, after all encoding, compression, etc.

        """
        data = self.renderOutgoing(data)
        data = self.compressData(data)
        self._write(data)

    def sendPrompt(self, data):
        data = self.renderOutgoing(data)
        data = self.compressData(data)
        data += IAC + GA
        self._write(data)
    
    def sendOOB(self, cmd, *args, **kwargs):
        output = b''
        if self.protocol_flags["MSDP"]:
            output += self.renderMSDP(cmd, *args, **kwargs)
        if self.protocol_flags["GMCP"]:
            output += self.renderGMCP(cmd, *args, **kwargs)
        output = self.compressData(output)
        self._write(output)

    def send(self, **kwargs):
        """
        Sends a message to the client. This is in server-side language. (see .msg() )

        Args:
            **kwargs: 

        Returns:
            None
        """
        outgoing = b''

        for kwarg, val in kwargs.items():
            if kwarg == 'text':
                self.sendText(val)
            elif kwarg == 'prompt':
                self.sendPrompt(val)
            else:
                self.sendOOB(val)

    def dataReceived(self, data):
        if self.protocol_flags["MCCP3"]:
            data = ZLIB_DECOMPRESS.decompress(data) + ZLIB_DECOMPRESS.flush(ZLIB_FLUSH)
        super().dataReceived(data)

    def toggle_nop_keepalive(self):
        """
        Allow to toggle the NOP keepalive for those sad clients that
        can't even handle a NOP instruction. This is turned off by the
        protocol_flag NOPKEEPALIVE (settable e.g. by the default
        `@option` command).
        """
        if self.nop_keep_alive and self.nop_keep_alive.running:
            self.nop_keep_alive.stop()
        else:
            self.nop_keep_alive = LoopingCall(self._send_nop_keepalive)
            self.nop_keep_alive.start(30, now=False)

    def _send_nop_keepalive(self):
        """Send NOP keepalive unless flag is set"""
        if self.protocol_flags.get("NOPKEEPALIVE"):
            self._write(IAC + NOP)
