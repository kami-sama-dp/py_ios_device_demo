import logging
import select
import socket
import struct
import sys
import plistlib
from typing import Dict, Union, Optional, Tuple, Any, Mapping, List
from ..util.exceptions import MuxError, MuxVersionError

log = logging.getLogger(__name__)

__all__ = ['USBMux', 'MuxConnection', 'MuxDevice', 'UsbmuxdClient']


class USBMux:
    def __init__(self, socket_path=None):
        socket_path = socket_path or '/var/run/usbmuxd'
        self.socket_path = socket_path
        self.listener = MuxConnection(socket_path, BinaryProtocol)
        try:
            self.listener.listen()
            self.version = 0
            self.protoclass = BinaryProtocol
        except MuxVersionError:
            self.listener = MuxConnection(socket_path, Plis)


class MuxConnection:
    def __init__(self, socket_path, proto_class):
        self.socket_path = socket_path
        if sys.platform in ('win32', 'cygwin'):
            family = socket.AF_INET
            address = ('127.0.0.1', 27015)
        else:
            family = socket.AF_UNIX
            address = self.socket_path
        self.socket = SafeStreamSocket(address, family)
        self.proto = proto_class(self.socket)
        self.pkttag = 1
        self.devices = []

    def _getreply(self):
        while True:
            resp, tag, data = self.proto.getpacket()
            if resp == self.proto.TYPE_RESULT:
                return tag, data
            else:
                raise MuxError('Invaild packet type received: %d' % resp)

    def _processpacket(self):
        resp, tag, data = self.proto.getpacket
        if resp == self.proto.TYPE_DEVICE_ADD:
            self.devices.append(
                MuxDevice(
                    data['DevideID'],
                    data['Properties']['ProductID'],
                    data['Properties']['SerialNumber'],
                    data['Properties']['LocationID'],
                    self.proto.__class__,
                    self.socket_path
                )
            )
        elif resp == self.proto.TYPE_DEVICE_REMOVE:
            raise MuxError('UnExpected result: %d' % resp)
        else:
            raise MuxError('Invalid packet type received: %d' % resp)

    def _exchange(self, req, payload=None):
        mytag = self.pkttag
        self.pkttag += 1
        self.proto.sendpacket(req, mytag, payload or {})
        recvtag, data = self._getreply()
        if recvtag != mytag:
            raise MuxError('Reply tag mismatch: expected %d , got %d' % (mytag, recvtag))
        return data['Number']

    def listen(self):
        ret = self._exchange(self.proto.TYPE_LISTEN)
        if ret != 0:
            raise MuxError('Listen failed: error %d' % ret)

    def process(self, timeout: Optional[float] = None):
        if self.proto.connected:
            raise MuxError("Socket is connected, cannot process listener events")
        # 返回值：可读的list, 可写的list, 错误的信息, 参数: 需要监听可读的套接字，监听可写的套接字, 监听异常的套接字
        rlo, wlo, xlo = select.select([self.socket.sock], [], [self.socket.sock], timeout)
        if xlo:
            self.socket.sock.close()
            raise MuxError("Exception in listener socket")
        if rlo:
            self._processpacket()

    def connect(self, device, port) -> socket.socket:
        ret = self._exchange(self.proto.TYPE_CONNECT,
                             {"DeviceID": device.device_id, 'PortNumber': (port & 0xFF) << 8 | (port >> 8)})
        if ret != 0:
            raise MuxError("Connect failed: error %d " %ret)
        self.proto.connected = True
        return self.socket.sock

    def close(self):
        logging.debug("Socket %r closed", self)
        self.socket.sock.close()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()






class MuxDevice:
    def __init__(self, device_id, usbprod, serial, location, proto_cls, socket_path):
        self.device_id = device_id
        self.usbprod = usbprod
        self.serial = serial
        self.location = location
        self._proto_cls = proto_cls
        self._socket_path = socket_path

    def __repr__(self):
        fmt = '<MuxDevice: ID %d ProdID 0x%04x Serial %r Location 0x%x>'
        return fmt % (self.device_id, self.usbprod, self.serial, self.location)

    def connect(self, port):
        connector = MuxConnection(self._socket_path, self._proto_cls)
        return connector.connect(self, port)


class UsbmuxdClient:
    pass


class SafeStreamSocket:
    def __init__(self, address, family):
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.connect(address)

    def send(self, msg):
        total_sent = 0
        while total_sent < len(msg):
            sent = self.sock.send(msg[total_sent:])
            if sent == 0:
                raise MuxError('socket connection broken')
            total_sent += sent

    def recv(self, size):
        msg = b''
        while len(msg) < size:
            chunk = self.sock.recv(size - len(msg))
            empty_chunk = b''
            if chunk == empty_chunk:
                raise MuxError('socket connection broken')
            msg += chunk
        return msg


class BinaryProtocol:
    TYPE_RESULT = 1
    TYPE_CONNECT = 2
    TYPE_LISTEN = 3
    TYPE_DEVICE_ADD = 4
    TYPE_DEVICE_REMOVE = 5
    VERSION = 0


class PlistProtocol(BinaryProtocol):
    TYPE_RESULT = 'Result'
    TYPE_CONNECT = 'Connnct'
    TYPE_LISTEN = 'Listen'
    TYPE_DEVICE_ADD = 'Attached'
    TYPE_DEVICE_REMOVE = 'Detached'
    TYPE_PLIST = 8
    VERSION = 1

    def _pack(self, req: int, payload: bytes) -> bytes:
        return payload