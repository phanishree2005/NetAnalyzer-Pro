from http.server import BaseHTTPRequestHandler
import os

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # This tells Vercel how to handle the request
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # We provide a link and a message because Streamlit 
        # usually requires a dedicated host like Streamlit Cloud.
        html_content = """
        <html>
            <head><title>NetAnalyzer Pro</title></head>
            <body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
                <h1>🔬 NetAnalyzer Pro</h1>
                <p>Deployment successful!</p>
                <p>Note: For the best experience with live network traffic, 
                we recommend <b>Streamlit Community Cloud</b>.</p>
                <hr/>
                <p>Starting Simulation Mode...</p>
                <script>
                    console.log("Streamlit initialization would happen here.");
                </script>
            </body>
        </html>
        """
        self.wfile.write(html_content.encode('utf-8'))
