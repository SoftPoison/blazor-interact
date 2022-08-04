from time import sleep
import requests
import urllib3
import urllib3.exceptions
import blazor
import logging
import utils
import json
import login
from blazorpack import InvocationMessage

log = logging.getLogger('main')

# this starts at 1, because 0 is used by `start_circuit()`
_ctr = utils.Counter(1)

local_storage = {}

def burp(sess):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    sess.verify=False
    sess.proxies = {'https': 'http://127.0.0.1:8080'}

def set_local_storage(msg: InvocationMessage): # localStorage.setItem
    log.info(f'Setting localstorage ({msg})')
    payload = json.loads(msg.arguments[2])
    data = json.loads(payload[1])
    for k, v in data.items():
        local_storage[k] = v
    log.info(f'New localstorage: {local_storage}')
    return (True, None)

def main():
    logging.basicConfig(format="[%(name)s] [%(levelname)s] %(message)s", level=logging.INFO)
    urllib3.connectionpool.log.setLevel(logging.WARNING)

    sess = requests.session()

    # add burp in the loop so we can figure out the specific auth flow of the website
    # burp(sess)

    log.info('authenticating...')
    blazor_descriptor = login.login(sess)

    bz = blazor.Blazor(sess, login.URL_BASE)

    # add some example hooks for local storage getting+setting
    bz.js_invocation_responses['localStorage.getItem'] = lambda _: (True, json.dumps(local_storage))
    bz.js_invocation_responses['localStorage.setItem'] = set_local_storage

    log.info('connecting...')
    bz.connect()

    log.info('starting circuit...')
    bz.start_circuit(blazor_descriptor)
    
    sleep(1) # give the server time to add some `__dotNetObject`'s (not necessary, but exposes extra functionality sometimes)

    # resp = bz.send_receive(InvocationMessage({}, None, 'BeginInvokeDotNetFromJS', [str(_ctr.get()), None, 'UpdateSessionStateAsync', 2, '[]']))
    # resp = bz.send_receive(InvocationMessage({}, None, 'BeginInvokeDotNetFromJS', [str(_ctr.get()), None, 'DispatchEventAsync', 1, '[{"eventHandlerId":1,"eventName":"click","eventFieldInfo":null},{"detail":1,"screenX":2668,"screenY":1494,"clientX":1677,"clientY":274,"offsetX":96,"offsetY":9,"pageX":1677,"pageY":274,"button":0,"buttons":0,"ctrlKey":false,"shiftKey":false,"altKey":false,"metaKey":false,"type":"click"}]']))
    resp = bz.send_receive(InvocationMessage({}, None, 'BeginInvokeDotNetFromJS', [str(_ctr.get()), 'Microsoft.JSInterop.Infrastructure.DotNetDispatcher', 'RenderTree', 0, '[]']))
    log.info(f'Got response: {resp}')

if __name__ == '__main__':
    main()
