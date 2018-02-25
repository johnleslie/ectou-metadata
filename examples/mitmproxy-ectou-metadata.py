# mitmproxy-ectou-metadata.py
#
# Example usage: mitmproxy -s mitmproxy-ectou-metadata.py --ignore-hosts '.+' --proxyauth "$(cat mitmproxy-auth-file.txt)" --listen-host 127.0.0.1 --listen-port 18080
# - will require HTTP Proxy Authentication
# - forwards traffic for 169.254.169.254 to an ectou-metadata instance on 127.0.0.1:18081
# - requests to ectou-metadata will be authenticated using credentials in ectou-auth-file.txt
# - May be used by docker build --build-arg="HTTP_PROXY=..." (see: https://github.com/moby/moby/pull/31584)

import base64
from mitmproxy import http

ectou_metadata_host = "127.0.0.1"
ectou_metadata_port = 18081
ectou_metadata_auth_file = 'ectou-auth-file.txt'

_auth_user_password = open(ectou_metadata_auth_file).read().strip()
_http_authorization = "Basic {}".format(base64.b64encode(_auth_user_password.encode('ascii')).decode('ascii'))


def request(flow):
    if flow.request.pretty_host == "169.254.169.254":
        flow.request.host = ectou_metadata_host
        flow.request.port = ectou_metadata_port
        flow.request.headers.set_all("Authorization", [_http_authorization])
