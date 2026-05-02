import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from app.config import HTTP_TIMEOUT, USER_AGENT


def create_session(max_retries=2):
    session = requests.Session()
    retry = Retry(total=max_retries, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": USER_AGENT})
    session.verify = False
    return session


def http_get(url, timeout=None, allow_redirects=True, **kwargs):
    session = create_session()
    try:
        resp = session.get(url, timeout=timeout or HTTP_TIMEOUT, allow_redirects=allow_redirects, **kwargs)
        return resp
    except requests.RequestException:
        return None
    finally:
        session.close()


def http_post(url, data=None, json_data=None, timeout=None, allow_redirects=True, **kwargs):
    session = create_session()
    try:
        resp = session.post(url, data=data, json=json_data, timeout=timeout or HTTP_TIMEOUT,
                            allow_redirects=allow_redirects, **kwargs)
        return resp
    except requests.RequestException:
        return None
    finally:
        session.close()


def http_request(method, url, **kwargs):
    session = create_session()
    kwargs.setdefault("timeout", HTTP_TIMEOUT)
    try:
        return session.request(method, url, **kwargs)
    except requests.RequestException:
        return None
    finally:
        session.close()
