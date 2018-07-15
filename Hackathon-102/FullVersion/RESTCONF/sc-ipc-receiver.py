import time, json;
import BaseHTTPServer;
from urlparse import urlparse, parse_qs

HOST_NAME = "localhost";
PORT_NUMBER = 8080;

NSFs = {};

def parse_to_yang(nsf_name, policy_name, rule):
	""" do parse action """

	print("do parse action");


class RequestHandler (BaseHTTPServer.BaseHTTPRequestHandler):
	def do_HEAD(self):
		self.send_response(200);
		self.send_header("Content-type", "text/json");
		self.end_headers();

	def do_GET(self):
		"""Respond to a GET request"""

		url = self.path.split("?")[0];
		if(url == "/sc/ipc/config/"):
			query_components = parse_qs(urlparse(self.path).query)
			nsf_name = query_components["nsf_name"][0];
			policy_name = query_components["policy_name"][0];
			rule = query_components["rule"][0];

			response_code = 200;
			response_msg = "Successfully Configured";

			if(nsf_name in NSFs):
				
				if(policy_name in NSFs[nsf_name]):
					response_code = 100;
					response_msg = "Policy name already Exists";
				else:
					NSFs[nsf_name][policy_name] = {};
					NSFs[nsf_name][policy_name]["rule"] = rule;
			else:
				NSFs[nsf_name] = {};
				NSFs[nsf_name][policy_name] = {};
				NSFs[nsf_name][policy_name]["rule"] = rule;

			print("Received: ");
			print(nsf_name, policy_name, rule);
			print("\n");

			self.send_response(200);
			self.send_header("Content-type", "text/json");
			self.end_headers();
			self.wfile.write(json.dumps({'code': response_code, 'message': response_msg}));
		
			if response_code == 200:
				parse_to_yang(nsf_name, policy_name, rule);

if __name__ == '__main__':
	server_class = BaseHTTPServer.HTTPServer
	httpd = server_class((HOST_NAME, PORT_NUMBER), RequestHandler)
	print time.asctime(), "Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER)
	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		pass
	httpd.server_close()
	print time.asctime(), "Server Stops - %s:%s" % (HOST_NAME, PORT_NUMBER)