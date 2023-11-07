"""
Standard ChatGPT
"""
from __future__ import annotations
import json
import logging
import secrets
import time
import uuid
from functools import wraps
from requests import HTTPError
from typing import Generator
from typing import Callable as TFunction
import requests
from . import typings as t
from .utils import get_input


def generate_random_hex(length: int = 17) -> str:
    """Generate a random hex string

    Args:
        length (int, optional): Length of the hex string. Defaults to 17.

    Returns:
        str: Random hex string
    """
    return secrets.token_hex(length)


def random_int(min_: int, max_: int) -> int:
    """Generate a random integer

    Args:
        min_ (int): Minimum value
        max_ (int): Maximum value

    Returns:
        int: Random integer
    """
    return secrets.randbelow(max_ - min_) + min_


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(funcName)s - %(message)s",
    )

log = logging.getLogger(__name__)


def logger(is_timed: bool) -> TFunction:
    """Logger decorator

    Args:
        is_timed (bool): Whether to include function running time in exit log

    Returns:
        _type_: decorated function
    """

    def decorator(func: TFunction) -> TFunction:
        wraps(func)

        def wrapper(*args, **kwargs):
            log.debug(
                "Entering %s with args %s and kwargs %s",
                func.__name__,
                args,
                kwargs,
            )
            start = time.time()
            out = func(*args, **kwargs)
            end = time.time()
            if is_timed:
                log.debug(
                    "Exiting %s with return value %s. Took %s seconds.",
                    func.__name__,
                    out,
                    end - start,
                )
            else:
                log.debug("Exiting %s with return value %s", func.__name__, out)
            return out

        return wrapper

    return decorator


User_Agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36'


class Chatbot:
    """
    Chatbot class for ChatGPT
    """

    @logger(is_timed=True)
    def __init__(
            self,
            config: dict[str, str] = None,

    ) -> None:
        """Initialize a chatbot

        Args:


        Raises:
            Exception: _description_
        """
        if config is None:
            config = {}

        self.session = requests.Session()

        if "proxy" in config:
            if not isinstance(config["proxy"], str):
                error = TypeError("Proxy must be a string!")
                raise error
            proxies = {
                "http": config["proxy"],
                "https": config["proxy"],
            }
            self.session.proxies.update(proxies)

        else:
            self.__password = "Am123456789"

        self.config = config
        self.token_key = ""
        self.credential = ""
        self.conversation_id = ""
        self.parent_id = ""
        # if "token_key" in config:
        #     self.token_key = config["token_key"]

        self.conversation_mapping = {}
        self.conversation_id_prev_queue = []
        self.parent_id_prev_queue = []

        self.disable_history = config.get("disable_history", False)

        self.__check_credentials()

    @logger(is_timed=True)
    def __check_credentials(self) -> None:
        url = "https://chat-shared3.zhile.io/api/loads"

        headers = {
            'sec-ch-ua': '"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"',
            'Referer': 'https://chat-shared3.zhile.io/shared.html?v=2',
            'DNT': '1',
            'sec-ch-ua-mobile': '?0',
            'User-Agent': User_Agent,
            'sec-ch-ua-platform': '"Windows"'
        }
        response = self.session.request("GET", url, headers=headers)
        if not response.ok:
            error = t.Error(
                source="__check_credentials",
                message="Cant get list",
                code=t.ErrorType.SERVER_ERROR,
            )
            raise error

        loads = response.json()["loads"]
        loads.sort(key=lambda x: x['count'])
        loads_ = list(filter(lambda x: x['count'] > 0, loads))
        if not loads_:
            loads_ = loads
        url_login = "https://chat-shared3.zhile.io/auth/login"

        self.token_key = loads_[0]["token_id"]
        payload = f'token_key={self.token_key}&session_password={self.__password}'
        headers = {
            'authority': 'chat-shared3.zhile.io',
            'accept': '*/*',
            'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
            'content-type': 'application/x-www-form-urlencoded',
            'dnt': '1',
            'origin': 'https://chat-shared3.zhile.io',
            'referer': 'https://chat-shared3.zhile.io/shared.html?v=2',
            'sec-ch-ua': '"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': User_Agent
        }

        response = self.session.request("POST", url_login, headers=headers, data=payload)
        if not response.ok:
            error = t.Error(
                source="__check_credentials",
                message="Cant Login",
                code=t.ErrorType.SERVER_ERROR,
            )
            raise error
        self.credential = response.cookies.get("credential")

    @logger(is_timed=True)
    def __send_request(
            self,
            data: dict,
            timeout: float = 360,
            **kwargs,
    ):
        log.debug("Sending the payload")

        cid, pid = None, data["parent_message_id"]
        message = ""

        self.conversation_id_prev_queue.append(cid)
        self.parent_id_prev_queue.append(pid)
        headers = {
            'sec-ch-ua': '"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"',
            'DNT': '1',
            'Accept-Language': 'en-US',
            'sec-ch-ua-mobile': '?0',
            'User-Agent': User_Agent,
            'Content-Type': 'application/json',
            'accept': 'text/event-stream',
            'Referer': 'https://chat-shared3.zhile.io/?v=2',
            'X-Authorization': f'Bearer {self.credential}',
            'sec-ch-ua-platform': '"Windows"',
            'Cookie': f'credential={self.credential}'
        }
        url = "https://chat-shared3.zhile.io/api/conversation"
        response = self.session.request("POST", url, headers=headers, data=json.dumps(data), stream=True,
                                        timeout=timeout, )
        # response = self.session.post(
        #     url=f"{self.base_url}conversation",
        #     data=json.dumps(data),
        #     timeout=timeout,
        #     stream=True,
        # )

        self.__check_response(response)

        # finish_details = None
        lines = response.content.split(b"\n")
        error = None
        for line in lines:
            # remove b' and ' at the beginning and end and ignore case
            line = str(line)[2:-1]
            if line.lower() == "internal server error":
                log.error(f"Internal Server Error: {line}")
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
                if "error" in line:
                    error = t.Error(
                        source="OpenAI",
                        message=line["error"],
                        code=t.ErrorType.EXPIRED_ACCESS_TOKEN_ERROR,
                    )

                continue
            if line.get("message").get("author").get("role") != "assistant":
                continue

            cid = line["conversation_id"]
            pid = line["message"]["id"]
            # metadata = line["message"].get("metadata", {})
            message_exists = False
            # author = {}
            if line.get("message"):
                # author = metadata.get("author", {}) or line["message"].get("author", {})
                if (
                        line["message"].get("content")
                        and line["message"]["content"].get("parts")
                        and len(line["message"]["content"]["parts"]) > 0
                ):
                    message_exists = True

            message: str = (
                line["message"]["content"]["parts"][0] if message_exists else ""
            )
            # model = metadata.get("model_slug", None)
            # finish_details = metadata.get("finish_details", {"type": None})["type"]
            error = None
            # yield {
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

        if error:
            raise error
        self.conversation_mapping[cid] = pid
        if pid is not None:
            self.parent_id = pid
        if cid is not None:
            self.conversation_id = cid
        message = message.strip("\n")
        return message

        # if not (auto_continue and finish_details == "max_tokens"):
        #     return

        # for i in self.continue_write(
        #         conversation_id=cid,
        #         model=model,
        #         timeout=timeout,
        #         auto_continue=False,
        # ):
        #     i["message"] = message + i["message"]
        #     yield i

    @logger(is_timed=True)
    def post_messages(
            self,
            messages: list[dict],
            conversation_id: str | None = None,
            parent_id: str | None = None,
            plugin_ids: list = None,
            model: str | None = None,
            timeout: float = 360,
            **kwargs,
    ) -> Generator[dict, None, None]:
        """Ask a question to the chatbot
        Args:
            messages (list[dict]): The messages to send
            conversation_id (str | None, optional): UUID for the conversation to continue on. Defaults to None.
            parent_id (str | None, optional): UUID for the message to continue on. Defaults to None.
            model (str | None, optional): The model to use. Defaults to None.
            plugin_ids (bool, optional): Whether to continue the conversation automatically. Defaults to False.
            timeout (float, optional): Timeout for getting the full response, unit is second. Defaults to 360.

        Yields: Generator[dict, None, None] - The response from the chatbot
            dict: {
                "message": str,
                "conversation_id": str,
                "parent_id": str,
                "model": str,
                "finish_details": str, # "max_tokens" or "stop"
                "end_turn": bool,
                "recipient": str,
                "citations": list[dict],
            }
        """
        if plugin_ids is None:
            plugin_ids = []
        if parent_id and not conversation_id:
            raise t.Error(
                source="User",
                message="conversation_id must be set once parent_id is set",
                code=t.ErrorType.USER_ERROR,
            )

        if conversation_id and conversation_id != self.conversation_id:
            self.parent_id = None
        conversation_id = conversation_id or self.conversation_id
        parent_id = parent_id or self.parent_id or ""
        if not conversation_id and not parent_id:
            parent_id = str(uuid.uuid4())

        if conversation_id and not parent_id:
            if conversation_id in self.conversation_mapping:
                parent_id = self.conversation_mapping[conversation_id]
            else:
                print(
                    "Warning: Invalid conversation_id provided, treat as a new conversation",
                )
                conversation_id = None
                parent_id = str(uuid.uuid4())
        model = model or self.config.get("model") or "text-davinci-002-render-sha"
        data = {

            "action": "next",
            "messages": messages,
            "parent_message_id": parent_id,
            "model": model,
            "history_and_training_disabled": self.disable_history,
            "plugin_ids": [],
            "suggestions": [],
            "arkose_token": "",
            "force_paragen": False,
            "conversation_mode": {
                "kind": "primary_assistant"
            }
        }

        plugin_ids = self.config.get("plugin_ids", []) or plugin_ids
        if len(plugin_ids) > 0 and not conversation_id:
            data["plugin_ids"] = plugin_ids

        return self.__send_request(
            data,
            timeout=timeout,
        )

    @logger(is_timed=True)
    def ask(
            self,
            prompt: str,
            conversation_id: str | None = None,
            parent_id: str = "",
            model: str = "",
            plugin_ids: list = None,
            timeout: float = 360,
            **kwargs,
    ) -> Generator[dict, None, None]:
        """Ask a question to the chatbot
        Args:
            prompt (str): The question
            conversation_id (str, optional): UUID for the conversation to continue on. Defaults to None.
            parent_id (str, optional): UUID for the message to continue on. Defaults to "".
            model (str, optional): The model to use. Defaults to "".
            plugin_ids (bool, optional): Whether to continue the conversation automatically. Defaults to False.
            timeout (float, optional): Timeout for getting the full response, unit is second. Defaults to 360.

        Yields: The response from the chatbot
            dict: {
                "message": str,
                "conversation_id": str,
                "parent_id": str,
                "model": str,
                "finish_details": str, # "max_tokens" or "stop"
                "end_turn": bool,
                "recipient": str,
            }
        """
        if plugin_ids is None:
            plugin_ids = []
        messages = [
            {
                "id": str(uuid.uuid4()),
                "role": "user",
                "author": {"role": "user"},
                "content": {"content_type": "text", "parts": [prompt]},
                "metadata": {}
            },
        ]

        return self.post_messages(
            messages,
            conversation_id=conversation_id,
            parent_id=parent_id,
            plugin_ids=plugin_ids,
            model=model,
            timeout=timeout,
        )

    @logger(is_timed=False)
    def __check_fields(self, data: dict) -> bool:
        try:
            data["message"]["content"]
        except (TypeError, KeyError):
            return False
        return True

    @logger(is_timed=False)
    def __check_response(self, response) -> None:
        """Make sure response is success

        Args:
            response (_type_): _description_

        Raises:
            Error: _description_
        """
        http_error_msg = ""
        reason = ""
        try:
            if 400 <= response.status_code < 500:
                http_error_msg = (
                    f"{response.status_code} Client Error: {reason} for url: {response.url}"
                )

            elif 500 <= response.status_code < 600:
                http_error_msg = (
                    f"{response.status_code} Server Error: {reason} for url: {response.url}"
                )

            if http_error_msg:
                raise HTTPError(http_error_msg, response=self)

        except requests.exceptions.HTTPError as ex:
            error = t.Error(
                source="OpenAI",
                message=response.text,
                code=response.status_code,
            )
            raise error from ex

    @logger(is_timed=False)
    def reset_chat(self) -> None:
        """
        Reset the conversation ID and parent ID.

        :return: None
        """
        self.conversation_id = None
        self.parent_id = str(uuid.uuid4())


get_input = logger(is_timed=False)(get_input)
