import requests
import json
import urllib.parse as urlparse
import websocket
import threading
import blazorpack
import logging
import utils
from typing import Callable, Any

log = logging.getLogger(__name__)

_callback_ctr = utils.Counter()

def _unhandled_js_invocation_response(msg: blazorpack.InvocationMessage):
    log.warn(f'Unhandled invocation: {msg}')
    return (True, None)

def null_js_invocation_response(_: blazorpack.InvocationMessage):
    return (True, None)

def _logged_response(callback: Callable[[blazorpack.InvocationMessage], tuple[bool, Any]]):
    def wrapped(msg: blazorpack.InvocationMessage):
        log.info(f'Received in callback {msg}')
        return callback(msg)

    return wrapped

class Blazor():
    """
    Example usage:

    ```
    # Create new blazor connection
    bz = Blazor(session, "http://example.com/")
    # Set up the websocket connection
    bz.connect()
    # Start the blazor circuit
    bz.start_circuit(blazor_descriptor)
    # Send some random message
    bz.send_receive(InvocationMessage({}, None, 'Something', []))
    ```
    """

    _ws: websocket.WebSocketApp
    _handle: threading.Thread = None
    _ready = False
    _ready_signal = threading.Condition()
    _wait_response: dict[str, list[threading.Condition|blazorpack.CompletionMessage|blazorpack.InvocationMessage]] = {}

    # modifiable dictionary of callbacks for JS.BeginInvokeJS() requests
    js_invocation_responses: dict[str, Callable[[blazorpack.InvocationMessage], tuple[bool, Any]]] = {
        '__default': _unhandled_js_invocation_response,
        'Blazor._internal.attachWebRendererInterop': null_js_invocation_response,
        'localStorage.getItem': null_js_invocation_response,
        'OnAfterRender': null_js_invocation_response,
        'Blazor._internal.navigationManager.enableNavigationInterception': null_js_invocation_response,
        'Blazor._internal.navigationManager.navigateTo': null_js_invocation_response,

        'sessionState.registerCallback': _logged_response(lambda _: (True, _callback_ctr.get())),
        'toString': lambda _: (True, '[object Window]'),
    }

    def __init__(self, session: requests.Session, base_url: str):
        self._session = session
        self._base_url = base_url

    def _get_initializers(self):
        """
        Get the blazor initializers from the server.
        Not actually sure what these do yet
        """

        resp = self._session.get(urlparse.urljoin(self._base_url, '_blazor/initializers'))
        return resp.json()

    def _negotiate(self):
        """
        Request the connectionId and connectionToken from the server.

        This also returns the available transports, but this is ignored for now, and blazorpack over websockets is used.

        Example response from server:

        ```
        {
            "negotiateVersion": 1,
            "connectionId": "0D8bF07_Slrp7AgrlblUSQ",
            "connectionToken": "CyHWk_aAWZQH_IbhZmueFQ",
            "availableTransports": [
                {"transport": "WebSockets", "transferFormats": ["Text", "Binary"]},
                {"transport": "ServerSentEvents", "transferFormats": ["Text"]},
                {"transport": "LongPolling", "transferFormats": ["Text", "Binary"]}
            ]
        }
        ```
        """

        req = requests.Request(
            'POST',
            urlparse.urljoin(self._base_url, '_blazor/negotiate?negotiateVersion=1'),
            cookies=self._session.cookies,
            headers=self._session.headers.copy(),
            data='',
        )
        req.headers.update({
            'X-Requested-With': 'XMLHttpRequest',
            'X-Signalr-User-Agent': 'Microsoft SignalR/6.0 (6.0.3; Unknown OS; Browser; Unknown Runtime Version)',
        })

        resp = self._session.send(req.prepare())
        return resp.json()

    def _ws_on_open(self, ws: websocket.WebSocketApp):
        """
        Once the websocket is open, we immediately want to negotiate using blazorpack
        """

        log.info('opened connection. negotiating blazorpack protocol')
        ws.send(b'{"protocol":"blazorpack","version":1}\x1e', websocket.ABNF.OPCODE_BINARY)

    def _ws_on_error(self, ws, error):
        """
        Actual error handling should happen here and bubble back up, but like, I'm lazy
        """

        log.error(f'error: {error}')

    def _ws_on_close(self, ws, close_status_code, close_msg):
        """
        This should also bubble up, and set some internal state so we can no longer send messages.
        This will be done *later* ™️
        """

        log.info(f'Closed ({close_status_code} | {close_msg})')

    def _ws_on_message(self, ws, data):
        """
        A bunch of magic happens here wrt sending receiving stuff from the server.
        What really matters is that incoming messages are parsed and offloaded to handlers, otherwise falling through to a default logger warning.
        """

        # hopefully the first message we receive is `{}\x1e`, because that should be the response to the blazorpack negotiation message
        if not self._ready:
            if data != b'{}\x1e':
                log.critical('Failed! Got incorrect response')
                return
            
            # wake up the waiting parent thread, notifying it that 
            self._ready = True
            self._ready_signal.notify_all()
            self._ready_signal.release()
            return

        # decode and handle incoming messages
        messages = blazorpack.decode(data)
        for message in messages:
            # Automatically respond to pings
            if isinstance(message, blazorpack.PingMessage):
                log.debug('Received ping, sending pong')
                self.send([blazorpack.PingMessage()])

                continue

            # Some invocation messages are specific server->JS, others are responses to client->dotnet. Work out what to do based on the message method
            elif isinstance(message, blazorpack.InvocationMessage):
                message: blazorpack.InvocationMessage = message
                if message.method == 'JS.BeginInvokeJS':
                    message_id: int = message.arguments[0]
                    js_method: str = message.arguments[1]
                    response_values = self.js_invocation_responses.get(js_method, self.js_invocation_responses['__default'])(message)
                    response_json = json.dumps([message_id, response_values[0], response_values[1]])
                    response = blazorpack.InvocationMessage({}, None, 'EndInvokeJSFromDotNet', [message_id, True, response_json])
                    log.debug(f'Responding to JS.Invoke({js_method}) for method with {response}')
                    self.send([response])

                    continue

                elif message.method == 'JS.RenderBatch':
                    log.debug('Responding to RenderBatch with empty OnRenderCompleted')
                    message_id: int = message.arguments[0]
                    self.send([blazorpack.InvocationMessage({}, None, 'OnRenderCompleted', [message_id, None])])

                    continue

                elif message.method == 'JS.EndInvokeDotNet':
                    message_id = message.arguments[0]

                    if self._wait_response.get(message_id) == None:
                        log.warn(f'Received unhandled {message}')
                        continue

                    wr = self._wait_response[message_id]
                    wr[0].acquire()
                    wr[1] = message
                    wr[0].notify_all()
                    wr[0].release()

                    continue

            # sometimes we get completion messages instead of invocation messages as our response. usually this is from calling something from client->dotnet
            elif isinstance(message, blazorpack.CompletionMessage):
                message: blazorpack.CompletionMessage = message
                message_id = message.identifier
                if self._wait_response.get(message_id) == None:
                    log.warn(f'Received unhandled {message}')
                    continue

                wr = self._wait_response[message_id]
                wr[0].acquire()
                wr[1] = message
                wr[0].notify_all()
                wr[0].release()

                continue

            # if all else fails, fall through and log the message
            log.info(f'Received {message}')

    def _ws_connect(self, connection_token: str) -> threading.Thread:
        """
        Set up the websocket connection in its own thread
        """

        def runner(self: Blazor, connection_token: str):
            self._ready_signal.acquire()

            base = self._base_url
            if base.startswith('http://'):
                base = 'ws://' + base.removeprefix('http://')
            else:
                base = 'wss://' + base.removeprefix('https://')

            url = urlparse.urljoin(base, f'_blazor?id={connection_token}')

            # websocket.enableTrace(True)

            self._ws = websocket.WebSocketApp(
                url,
                header=self._session.headers.copy(),
                on_open=self._ws_on_open,
                on_error=self._ws_on_error,
                on_close=self._ws_on_close,
                on_message=self._ws_on_message,
            )

            self._ws.run_forever()

        return threading.Thread(target=runner, args=[self, connection_token])

    def connect(self, timeout: float = None):
        """
        Connect to the server, and spin up a background websocket for talking to the damn thing
        """

        # TODO: figure out initializers thing
        assert self._get_initializers() == []

        n = self._negotiate()
        token = n['connectionToken']
        self._handle = self._ws_connect(token)

        # wait until the connection is negotiated
        self._ready_signal.acquire()
        self._handle.start()
        self._ready_signal.wait(timeout)
        self._ready_signal.release()

    def start_circuit(self, blazor_descriptor):
        """
        "Start the ciruit".
        Whatever that means.
        """

        # there's technically a response here, but it can usually be ignored
        return self.send_receive(blazorpack.InvocationMessage({}, str(0), 'StartCircuit', [self._base_url, self._base_url, f'[{blazor_descriptor}]', '']))

    def send(self, messages: list[blazorpack.InvocationMessage]):
        """
        Send a message (well, messages) to the server, and don't wait for a response.

        This supports multiple messages because the protocol supports rolling them all up into one websocket payload.
        """

        packed = blazorpack.encode(messages)
        self._ws.send(packed, websocket.ABNF.OPCODE_BINARY)

    def send_receive(self, message: blazorpack.InvocationMessage) -> blazorpack.CompletionMessage|blazorpack.InvocationMessage:
        """
        Send a message to the server and block until it responds.

        Multi-message isn't supported yet because using multiple condition variables at a time seems tricky (there's bound to be a better way).
        """

        if self._wait_response.get(message.get_id()) != None:
            raise Exception('identifier already in use') # TODO: custom exception type

        cond = threading.Condition()
        cond.acquire()
        self._wait_response[message.get_id()] = [cond, None]

        self.send([message])
        cond.wait()

        cond.release()
        response = self._wait_response[message.get_id()][1]
        del self._wait_response[message.get_id()]

        return response
