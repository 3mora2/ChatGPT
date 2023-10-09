import tls_client
from tls_client.response import Response


class Server:
    OpenAI_HOST = "chat.openai.com"
    user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:114.0) Gecko/20100101 Firefox/114.0"

    def __init__(self):
        self.session = tls_client.Session(
            # client_identifier="chrome117",
            client_identifier="chrome112",
            random_tls_extension_order=True
        )

    def request(self, method: str, url: str, **kwargs) -> "Response":
        if "chat.openai.com" not in url:
            url = f"https://{self.OpenAI_HOST}/backend-api/{url}"

        headers = self.session.headers
        headers.update(self.headers())
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))
        PUID = self.session.headers.get("PUID")
        if PUID:
            headers["cookie"] = f"_puid={PUID};"

        r = self.session.execute_request(method=method.upper(), url=url, headers=headers, **kwargs)
        return r

    def headers(self):
        return {
            "User-Agent": self.user_agent,
            "Host": f"{self.OpenAI_HOST}",
            "Origin": f"https://{self.OpenAI_HOST}/chat",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "Keep-Alive": "timeout=360",
            "sec-ch-ua": "\"Chromium\";v=\"112\", \"Brave\";v=\"112\", \"Not:A-Brand\";v=\"99\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Linux\"",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "sec-gpc": "1"
        }
