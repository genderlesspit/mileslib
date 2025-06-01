import requests
from util import milesutil as MUtil
from context.milescontext import mileslib

class Requests:
    """
    Centralized HTTP client with shared session, retries, and logging.

    All methods use the shared `requests.Session` and `@mileslib` for logging, retries, timing, and safe mode.
    """

    session = requests.Session()

    @staticmethod
    def _do_request(
            method: str,
            url: str,
            *,
            data=None,
            json=None,
            headers=None,
            timeout: float = 5.0,
            expect_json: bool = False
    ) -> requests.Response | dict | str | None:
        """
        Core request logic used by all HTTP wrappers.

        Args:
            method (str): HTTP method name, e.g. 'get', 'post'.
            url (str): Full URL to request.
            data/json (dict): Optional request payload.
            headers (dict): Optional headers.
            timeout (float): Request timeout in seconds.
            expect_json (bool): If True, return parsed JSON or raise.

        Returns:
            Response object or JSON dict or None
        """
        MUtil.try_import("requests")
        MUtil.check_types(method, str, "method")
        MUtil.check_types(url, str, "url")

        method = method.lower()
        req = getattr(Requests.session, method)
        resp = req(url, data=data, json=json, headers=headers, timeout=timeout)
        resp.raise_for_status()

        if expect_json:
            return resp.json()

        return resp

    @staticmethod
    def http_get(
            url: str,
            headers: dict = None,
            retries: int = 3,
            timeout: float = 5.0,
            expect_json: bool = False
    ) -> requests.Response | dict | None:
        """
        HTTP GET with retries and optional JSON parsing.

        Args:
            url (str): URL to GET.
            headers (dict): Optional headers.
            retries (int): Retry attempts.
            timeout (float): Timeout in seconds.
            expect_json (bool): If True, return response.json().

        Returns:
            Response or parsed JSON or None.
        """
        return MUtil.attempt(
            lambda: Requests._do_request(
                "get",
                url,
                headers=headers,
                timeout=timeout,
                expect_json=expect_json,
            ),
            retries=retries
        )

    @staticmethod
    def http_post(
            url: str,
            data: dict,
            headers: dict = None,
            retries: int = 3,
            timeout: float = 5.0,
            expect_json: bool = False
    ) -> requests.Response | dict | None:
        """
        HTTP POST with retries and JSON payload.

        Args:
            url (str): URL to POST to.
            data (dict): JSON payload.
            headers (dict): Optional headers.
            retries (int): Retry attempts.
            timeout (float): Timeout in seconds.
            expect_json (bool): If True, return response.json().

        Returns:
            Response or parsed JSON or None.
        """
        MUtil.check_types(data, dict, "data")
        return MUtil.attempt(
            lambda: Requests._do_request(
                "post",
                url,
                json=data,
                headers=headers,
                timeout=timeout,
                expect_json=expect_json,
            ),
            retries=retries
        )

    @staticmethod
    @mileslib(logged=False, safe=True)
    def ensure_endpoint(
            url: str,
            timeout: float = 3.0,
            expect_json: bool = False,
            expect_keys: list[str] = None,
            status_ok: range = range(200, 400),
    ) -> bool:
        """
        Check if an HTTP endpoint is up and optionally validate its response content.

        Args:
            url (str): URL to check.
            timeout (float): Timeout in seconds.
            expect_json (bool): If True, requires response to be JSON-decodable.
            expect_keys (list[str], optional): List of keys that must exist in JSON payload.
            status_ok (range): Acceptable status code range.

        Returns:
            bool: True if endpoint is reachable and meets criteria, False otherwise.
        """
        try:
            resp = Requests._do_request("get", url, timeout=timeout)

            if hasattr(resp, "status_code") and resp.status_code not in status_ok:
                print(f"[ensure_endpoint] Status code {resp.status_code} not in {list(status_ok)}")
                return False

            if expect_json:
                try:
                    payload = resp.json() if hasattr(resp, "json") else resp
                except Exception:
                    print(f"[ensure_endpoint] Response is not valid JSON from {url}")
                    return False

                if expect_keys:
                    missing = [k for k in expect_keys if k not in payload]
                    if missing:
                        print(f"[ensure_endpoint] Missing expected keys {missing} in response from {url}")
                        return False

            return True

        except Exception as e:
            print(f"[ensure_endpoint] Request to {url} failed: {e}")
            return False

reqs = Requests
http_get = Requests.http_get
http_post = Requests.http_post
REQUESTS_USAGE = """
MUtil Requests Aliases
------------------------------

http_get(url: str, retries=3) -> requests.Response
    Perform a GET request with automatic retry and logging.

http_post(url: str, data: dict, retries=3) -> requests.Response
    Perform a POST request with JSON payload, retry support, and logging.
"""