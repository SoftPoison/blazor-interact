import msgpack
import struct
from dataclasses import dataclass
from enum import IntEnum

# Ripped straight from the aspnetcore source
class HubProtocolConstants(IntEnum):
    InvocationMessageType = 1
    StreamItemMessageType = 2
    CompletionMessageType = 3
    StreamInvocationMessageType = 4
    CancelInvocationMessageType = 5
    PingMessageType = 6
    CloseMessageType = 7

# Nice little type alias so I can remember what I can actually send
Encodable = list['Encodable']|dict[str, 'Encodable']|str|int|None

class Message:
    __message_types: dict[HubProtocolConstants, 'Message'] = {}

    message_type: HubProtocolConstants
    extra: list[Encodable]

    def __init_subclass__(cls, message_type, **kwargs) -> None:
        # use the magic of subclasses to set up automatic decoding from lists to specific types

        super.__init_subclass__(**kwargs)
        cls.__message_types[message_type] = cls
        cls.message_type = message_type

    def __init__(self, message_type, extra) -> None:
        self.message_type = message_type
        self.extra = extra

    def __repr__(self) -> str:
        return f'Message(message_type={repr(self.message_type)}, extra={repr(self.extra)})'

    def to_list(self) -> list[Encodable]:
        return [self.message_type, *self.extra]

    @classmethod
    def from_list(cls, l: list[Encodable]) -> 'Message':
        if l[0] in cls.__message_types:
            return cls.__message_types[l[0]].from_list(l)

        return cls(l[0], l[1:])

@dataclass(init=True, repr=True)
class InvocationMessage(Message, message_type=HubProtocolConstants.InvocationMessageType):
    something: dict[str, Encodable] # I don't actually know what this is for, but it seems to always be an empty dict?
    identifier: Encodable|None
    method: str
    arguments: list[Encodable]
    result: list[Encodable]|None = None

    def to_list(self) -> list[Encodable]:
        r = [self.message_type, self.something, self.identifier, self.method, self.arguments]
        if self.result != None:
            r.append(self.result)
        return r

    @classmethod
    def from_list(cls, l: list[Encodable]) -> 'InvocationMessage':
        # ignore l[0] (message_type)
        r = None if len(l) < 6 else l[5]
        return cls(l[1], l[2], l[3], l[4], r)

    def get_id(self):
        if self.identifier != None:
            return self.identifier
        
        return self.arguments[0]

@dataclass(init=True, repr=True)
class CompletionMessage(Message, message_type=HubProtocolConstants.CompletionMessageType):
    something: dict[str, Encodable] # I don't actually know what this is for, but it seems to always be an empty dict?
    identifier: Encodable|None
    num: int
    extra: Encodable

    def to_list(self) -> list[Encodable]:
        r = [self.message_type, self.something, self.identifier, self.num, *self.extra]
        return r

    @classmethod
    def from_list(cls, l: list[Encodable]) -> 'CompletionMessage':
        # ignore l[0] (message_type)
        return cls(l[1], l[2], l[3], l[4:])

@dataclass(init=True, repr=True)
class PingMessage(Message, message_type=HubProtocolConstants.PingMessageType):
    extra: list[Encodable]|None = None

    def to_list(self) -> list[Encodable]:
        if self.extra != None:
            return [self.message_type, *self.extra]

        return [self.message_type]

    @classmethod
    def from_list(cls, l: list[Encodable]) -> 'PingMessage':
        # ignore l[0] (message_type)
        return cls(l[1:])

def _byte(x):
    return struct.unpack('B', x)[0]

def _encode_msg_size(packed: bytes):
    sz = len(packed)
    while sz > 0:
        s = sz & 0x7f
        sz >>= 7
        if sz > 0:
            s |= 0x80

        yield s

def decode(data: bytes) -> list[Message]:
    """
    Takes a blazorpack encoded byte array of messages and spits out something we can actually work with.
    """

    # TODO: custom errors with wrapper around msgpack.unpackb

    num_bytes = len(data)
    messages = []

    idx = 0
    while idx < num_bytes:
        # decode message size. it's stored as a non-fixed-size integer, so it needs manual decoding
        msg_size = 0
        shift = 0

        while True:
            size_byte = _byte(data[idx:idx+1])
            idx += 1

            msg_size += (size_byte&0x7f) << shift
            shift += 7

            if size_byte < 0x80:
                break

        # decode message (now that we know the size)
        msg = msgpack.unpackb(data[idx:idx+msg_size])
        idx += msg_size

        # print('RAW:', msg)

        messages.append(Message.from_list(msg))

    return messages

def encode(messages: list[Message]) -> bytes:
    """
    Takes a list of Messages and spits out a blazorpack encoded byte array for sending to the server.
    """

    out = bytearray()

    for msg in messages:
        packed = msgpack.packb(msg.to_list())
        out.extend(_encode_msg_size(packed))
        out.extend(packed)

    return bytes(out)

if __name__ == '__main__':
    # CLI for manually decoding stuff from burp websockets history, then reencoding it for comparison

    import sys
    import json

    if len(sys.argv) != 2 or not sys.argv[1].lower() in ['encode', 'decode']:
        print(f'Usage: {sys.argv[0]} <encode|decode>')
        exit(1)

    to_hex = lambda bs: ' '.join([f'{x:02X}' for x in bs])
    from_hex = lambda h: bytes([int(x, 16) for x in filter(lambda s: s != '', h.split(' '))])

    if sys.argv[1] == 'encode':
        jem = input('JSON encoded message array: ')
        ms = json.loads(jem)
        messages = []
        for m in ms:
            messages.append(Message.from_list(m))

        out = to_hex(encode(messages))
        print('Encoded data:\n')
        print(out)

    elif sys.argv[1] == 'decode':
        h = input('Space separated hex-encoded message: ')
        bs = from_hex(h)

        messages = decode(bs)

        print('Decoded messages:\n')
        for message in messages:
            print(message)
        print()

        raw_messages = [m.to_list() for m in messages]
        print('As JSON encoded array:')
        print(json.dumps(raw_messages))
