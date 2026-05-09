import os
import sys

# This bridge allows Streamlit to run on Vercel's Python runtime
# by invoking the streamlit CLI as a module.

def handler(request):
    os.system("streamlit run network_analyzer/ui/dashboard.py --server.port 8080")
    return {
        "statusCode": 200,
        "body": "Streamlit is initializing..."
    }
