from mileslib_core import log
from mileslib_core import sm
import pytest
from unittest import mock
from requests import Response, HTTPError
import requests

### Static Methods ###

### Script ###

class Requests:
    @staticmethod
    @sm.timer(label="http_get")
    def http_get(url: str, retries: int = 3) -> requests.Response:
        sm.try_import("requests")
        sm.check_input(url, str, "url")
        sm.check_input(retries, int, "retries")
        log.info("Starting GET request", url=url)

        # define the single‐try function
        def _do_get():
            resp = requests.get(url)
            resp.raise_for_status()
            return resp

        # delegate retry logic
        return sm.attempt(_do_get, retries=retries)

    @staticmethod
    @sm.timer(label="http_post")
    def http_post(url: str, data: dict, retries: int = 3) -> requests.Response:
        sm.try_import("requests")
        sm.check_input(url, str, "url")
        sm.check_input(data, dict, "data")
        sm.check_input(retries, int, "retries")
        log.info("Starting POST request", url=url, payload=data)

        def _do_post():
            resp = requests.post(url, json=data)
            resp.raise_for_status()
            return resp

        return sm.attempt(_do_post, retries=retries)

@pytest.fixture
def fake_response():
    response = mock.Mock(spec=Response)
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.return_value = {"ok": True}
    return response

@mock.patch("test_requests.requests.get")
def test_http_get_success(mock_get, fake_response):
    mock_get.return_value = fake_response

    resp = Requests.http_get("https://example.com")
    assert resp.status_code == 200
    mock_get.assert_called_once_with("https://example.com")

@mock.patch("test_requests.requests.get")
def test_http_get_failure_then_success(mock_get):
    # Raise once, then succeed
    fail_resp = mock.Mock()
    fail_resp.raise_for_status.side_effect = HTTPError("fail")

    good_resp = mock.Mock(spec=Response)
    good_resp.raise_for_status.return_value = None
    good_resp.status_code = 200

    mock_get.side_effect = [fail_resp, good_resp]

    resp = Requests.http_get("https://retry.com", retries=2)
    assert resp.status_code == 200
    assert mock_get.call_count == 2

@mock.patch("test_requests.requests.get")
def test_http_get_all_fail(mock_get):
    fail_resp = mock.Mock()
    fail_resp.raise_for_status.side_effect = HTTPError("fail")
    mock_get.return_value = fail_resp

    with pytest.raises(HTTPError):
        Requests.http_get("https://fail.com", retries=3)
    assert mock_get.call_count == 3

@mock.patch("test_requests.requests.post")
def test_http_post_success(mock_post, fake_response):
    mock_post.return_value = fake_response
    data = {"name": "test"}

    resp = Requests.http_post(None, "https://example.com", data)
    assert resp.status_code == 200
    mock_post.assert_called_once_with("https://example.com", json=data)

@mock.patch("test_requests.requests.post")
def test_http_post_failure_then_success(mock_post):
    fail_resp = mock.Mock()
    fail_resp.raise_for_status.side_effect = HTTPError("fail")

    good_resp = mock.Mock(spec=Response)
    good_resp.raise_for_status.return_value = None
    good_resp.status_code = 200

    mock_post.side_effect = [fail_resp, good_resp]
    data = {"key": "val"}

    resp = Requests.http_post(None, "https://retry.com", data, retries=2)
    assert resp.status_code == 200
    assert mock_post.call_count == 2

@mock.patch("test_requests.requests.post")
def test_http_post_all_fail(mock_post):
    fail_resp = mock.Mock()
    fail_resp.raise_for_status.side_effect = HTTPError("fail")
    mock_post.return_value = fail_resp

    with pytest.raises(HTTPError):
        Requests.http_post(None, "https://fail.com", {"bad": "data"}, retries=3)
    assert mock_post.call_count == 3
