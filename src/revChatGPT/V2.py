import json
import tls_client
from . import typings as t

OPENAI_API_HOST = 'https://api.openai.com'


class Chatbot:
    """
    Chatbot class for ChatGPT
    """
    session: tls_client.Session

    def __init__(
            self,
            key: str,
            check=True
    ) -> None:
        self.models = []
        self.key = key
        self.session = tls_client.Session(
            client_identifier="firefox_110",
        )
        if check:
            self.get_model()

    @property
    def headers(self):
        return {
            'Content-Type': 'application/json',
            "Authorization": f'Bearer {self.key}',
        }

    def check_response(self, response):
        if response.status_code in [200, ]:
            return
        error = t.Error(
            source="check_response",
            message=response.text,
            code=t.ErrorType.AUTHENTICATION_ERROR,
        )
        raise error

    def get_model(self):
        url = f'{OPENAI_API_HOST}/v1/models'
        r = self.session.get(url, headers=self.headers)
        self.check_response(r)
        self.models = list(map(lambda model: model.get("id"), r.json().get("data")))

    def ask(self, prompt, messages=None, temperature=1, model='gpt-3.5-turbo', timeout=300, stream=False):
        if messages is None:
            messages = []

        if self.models and model not in self.models:
            error = t.Error(
                source="ask",
                message="Not valid Model",
                code=t.ErrorType.INVALID_REQUEST_ERROR,
            )
            raise error

        url = f"{OPENAI_API_HOST}/v1/chat/completions"

        body = {
            "messages": [
                {"role": "system", "content": prompt},
                *messages],
            # "max_tokens": 1000,
            "temperature": temperature,
            "stream": stream,
            "model": model
        }

        res = self.session.post(url, headers=self.headers, json=body, timeout_seconds=timeout)
        self.check_response(res)
        message = ""
        if stream is False:
            message = res.json()["choices"][0]["message"]["content"]
            return message
        else:
            # TODO:
            lines = res.content.split(b"\n")
            for line in lines:
                # remove b' and ' at the beginning and end and ignore case
                line = str(line)[2:-1]
                if line.lower() == "internal server error":
                    error = t.Error(
                        source="ask",
                        message="Internal Server Error",
                        code=t.ErrorType.SERVER_ERROR,
                    )
                    raise error
                if not line or line is None:
                    continue
                if "data: " in line:
                    line = line[6:]
                if line == "[DONE]":
                    break

                # DO NOT REMOVE THIS
                line = line.replace('\\"', '"')
                line = line.replace("\\'", "'")
                line = line.replace("\\\\", "\\")

                try:
                    line = json.loads(line)
                except json.decoder.JSONDecodeError:
                    continue
                if not self.__check_fields(line):
                    continue
                if line.get("message").get("author").get("role") != "assistant":
                    continue

                cid = line["conversation_id"]
                pid = line["message"]["id"]
                metadata = line["message"].get("metadata", {})
                message_exists = False
                author = {}
                if line.get("message"):
                    author = metadata.get("author", {}) or line["message"].get("author", {})
                    if (
                            line["message"].get("content")
                            and line["message"]["content"].get("parts")
                            and len(line["message"]["content"]["parts"]) > 0
                    ):
                        message_exists = True
                message: str = (
                    line["message"]["content"]["parts"][0] if message_exists else ""
                )
                model = metadata.get("model_slug", None)
                finish_details = metadata.get("finish_details", {"type": None})["type"]
                # {
                #     "author": author,
                #     "message": message,
                #     "conversation_id": cid,
                #     "parent_id": pid,
                #     "model": model,
                #     "finish_details": finish_details,
                #     "end_turn": line["message"].get("end_turn", True),
                #     "recipient": line["message"].get("recipient", "all"),
                #     "citations": metadata.get("citations", []),
                # }
            return message

    @staticmethod
    def __check_fields(data: dict) -> bool:
        try:
            data["message"]["content"]
        except (TypeError, KeyError):
            return False
        return True
