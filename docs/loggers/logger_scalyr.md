
# Logger: Scalyr client

Client for the Scalyr/DataSet [`addEvents`](https://app.eu.scalyr.com/help/api#addEvents) API endpoint.

Options:

* `server-url` (string)
  > Scalyr API Host

* `apikey` (string, required)
  > API Token with Log Write permissions

* `mode` (string)
  > Output format `text`, `json`, or `flat-json`

* `parser` (string)
  > When using text or json mode, the name of the parser Scalyr should use

* `flush-interval` (integer)
  > flush batch every X seconds

* `batch-size` (integer)
  > batch size for log entries in bytes

* `text-format` (string)
  > output text format, please refer to the default text format to see all available [text directives](../dnsconversions.md#text-format-inline), use this parameter if you want a specific format

* `proxy-url` (string)
  > Proxy URL

* `tls-insecure` (boolean)
  > If set to true, skip verification of server certificate.

* `tls-min-version` (string)
  > Specifies the minimum TLS version that the server will support.

* `ca-file` (string)
  > Specifies the path to the CA (Certificate Authority) file used to verify the server's certificate.

* `cert-file` (string)
  > Specifies the path to the certificate file to be used. This is a required parameter if TLS support is enabled.

* `key-file` (string)
  > Specifies the path to the key file corresponding to the certificate file. This is a required parameter if TLS support is enabled.

* `chan-buffer-size` (int)
  > Specifies the maximum number of packets that can be buffered before discard additional packets.
  > Set to zero to use the default global value.

* `session-info` (map)
  > Any "session" or server information for Scalyr. e.g. 'region', 'serverHost'. If 'serverHost' is not included, it is set using the hostname.

* `attrs` (map)
  > Any extra attributes that should be added to the log's fields.

The client can send the data in 3 formats: text (using `text-format`), json (by including the whole DNS message in the `message` field), or flat-json.
The first two formats (text, json) require setting the `parser` option and needs a corresponding parser defined in the Scalyr backend.
As Scalyr's JSON parsers (like 'dottedJSON') will not expand nested JSON and require one or more 'rewrite' statements, the Scalyr client supports a `flat-json` mode.

Defaults:

```yaml
scalyrclient:
  server-url: app.scalyr.com
  apikey: ""
  mode: text
  text-format: "timestamp-rfc3339ns identity operation rcode queryip queryport family protocol length qname qtype latency"
  sessioninfo: {}
  attrs: {}
  parser: ""
  flush-interval: 30
  proxy-url: ""
  tls-insecure: false
  tls-min-version: 1.2
  ca-file: ""
  cert-file: ""
  key-file: ""
  chan-buffer-size: 0
```
