caddy-vipps-login has been tested on Linux, but is in no way production ready!

# Building

* Checkout caddy's branch v2 from https://github.com/caddyserver/caddy/
* Copy caddy-standard/vippslogin into caddy's modules/standard directory.
* Build caddy

# Configuration

Add an authentication handler to your caddy 2 json config:

```
   {
	"handler": "authentication",
	"providers": {
	  "vipps_login": {
		  "client_id":"client_id from Vipps",
		  "client_secret":"client_secret from Vipps",
		  "redirect_url":"https://yourdomain.com/a-unique-url",
		  "root": "/same/directory/as/webserver/files",
		  "signing_key": "64 bytes base64 encoded key you generate yourself",
		  "forbidden_page": "/url/to/forbidden.html",
		  "session_duration": "duration of a session, in Go's time duration format"
		}
	}
  },
```

To protect a directory you can now create a .vipps-login file with one phonenumber per line (remember the 47 country prefix).

