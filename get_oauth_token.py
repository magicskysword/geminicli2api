import os
import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from google_auth_oauthlib.flow import Flow
from src.config import CLIENT_ID, CLIENT_SECRET, SCOPES, GEMINI_CREDENTIALS_PATH

logging.basicConfig(level=logging.INFO)

class _OAuthCallbackHandler(BaseHTTPRequestHandler):
    auth_code = None
    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        code = query_components.get("code", [None])[0]
        if code:
            _OAuthCallbackHandler.auth_code = code
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>OAuth authentication successful!</h1><p>You can close this window.</p>")
        else:
            self.send_response(400)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Authentication failed.</h1><p>Please try again.</p>")

def save_credentials_to_file(creds, project_id):
    """Saves the credentials using the official to_json method and adds the project_id."""
    if not os.path.exists(GEMINI_CREDENTIALS_PATH):
        os.makedirs(GEMINI_CREDENTIALS_PATH)
        logging.info(f"Created credentials directory: {GEMINI_CREDENTIALS_PATH}")

    # 使用官方方法生成包含所有标准字段的 JSON 字符串
    creds_json_str = creds.to_json()
    
    # 解析为字典
    creds_data = json.loads(creds_json_str)
    
    # 添加我们的自定义 project_id 字段
    creds_data["project_id"] = project_id
    
    # 定义最终的文件路径
    file_path = os.path.join(GEMINI_CREDENTIALS_PATH, f"{project_id}.json")

    # 将增强后的字典写入文件
    with open(file_path, "w") as f:
        json.dump(creds_data, f, indent=2)
    logging.info(f"Credentials for project '{project_id}' saved successfully to: {file_path}")


def main():
    """Main function to run the OAuth flow for multiple project IDs."""
    try:
        with open("project_ids.json", "r") as f:
            data = json.load(f)
            project_ids = data.get("project_ids", [])
    except FileNotFoundError:
        logging.error("Error: 'project_ids.json' not found. Please create it in the root directory.")
        return
    except json.JSONDecodeError:
        logging.error("Error: Could not decode JSON from 'project_ids.json'.")
        return

    if not project_ids:
        logging.error("Error: 'project_ids' list is empty or not found in 'project_ids.json'.")
        return

    client_config = {
        "installed": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }

    import oauthlib.oauth2.rfc6749.parameters
    original_validate = oauthlib.oauth2.rfc6749.parameters.validate_token_parameters

    def patched_validate(params):
        try:
            return original_validate(params)
        except Warning:
            pass
    
    oauthlib.oauth2.rfc6749.parameters.validate_token_parameters = patched_validate

    try:
        with HTTPServer(("", 8080), _OAuthCallbackHandler) as server:
            for project_id in project_ids:
                print(f"\n{'='*80}")
                print(f"Starting OAuth flow for project: {project_id}")
                print(f"{'='*80}")

                flow = Flow.from_client_config(
                    client_config,
                    scopes=SCOPES,
                    redirect_uri="http://localhost:8080"
                )
                
                auth_url, _ = flow.authorization_url(
                    access_type="offline",
                    prompt="consent",
                    include_granted_scopes='true'
                )
                
                print(f"\nPlease open this URL in your browser to log in for project '{project_id}':")
                print(auth_url)
                print(f"{'='*80}\n")
                
                # Wait for the callback
                _OAuthCallbackHandler.auth_code = None  # Reset before waiting
                print("Waiting for authorization callback...")
                while not _OAuthCallbackHandler.auth_code:
                    server.handle_request()
                auth_code = _OAuthCallbackHandler.auth_code

                if not auth_code:
                    logging.error(f"Failed to retrieve authorization code for project '{project_id}'. Skipping.")
                    continue

                try:
                    flow.fetch_token(code=auth_code)
                    credentials = flow.credentials
                    save_credentials_to_file(credentials, project_id)
                except Exception as e:
                    logging.error(f"Authentication failed for project '{project_id}': {e}")
    
    except Exception as e:
        logging.error(f"An unexpected error occurred with the server: {e}")
    finally:
        oauthlib.oauth2.rfc6749.parameters.validate_token_parameters = original_validate

if __name__ == "__main__":
    main()