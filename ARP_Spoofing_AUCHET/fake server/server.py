import http.server
import socketserver
import os 

PORT=80

class RequestHandler(http.server.SimpleHTTPRequestHandler):
	def log_request(self,format, *args):
		print(f"[log] Request received: {self.client_address[0]} - {self.requestline}")
	def do_GET(self):
		self.path='fake.html'
		return http.server.SimpleHTTPRequestHandler.do_GET(self)
	def do_HEAD(self):
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()
def run_server():
	if not os.path.exists('fake.html'):
		print("[!] fake.html missing !")
		return 
	try:
		with socketserver.TCPServer(("",PORT), RequestHandler) as httpd:
			print(f"[*] Fake web server started on Port : {PORT} (http://192.168.47.10)")
			httpd.serve_forever()
	except PermissionError:
		print("[!] Error : permission denied")
	except Exception as e:
		print(f"[!] Error : {e}")

if __name__ == "__main__":
	run_server()
