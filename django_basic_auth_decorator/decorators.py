import base64
import hashlib
from functools import wraps
from typing import Callable
from typing import ParamSpec
from typing import TypeVar

from django.http import HttpRequest
from django.http import HttpResponse

P = ParamSpec("P")
R = TypeVar("R", covariant=True)


def _credential_hash(username: str, password: str) -> str:
    # changing a password changes the hash, which invalidates old cookies
    return hashlib.sha256(f"{username}:{password}".encode()).hexdigest()


def basic_auth(
    credentials: list[tuple[str, str]],
    realm: str = "API Docs",
    cookie_age: int | None = None,
):
    """
    Protect a view with basic auth.

    Browsers forget basic auth credentials when they restart. Set cookie_age
    (in seconds) to also remember a successful login in a signed cookie.
    """
    cookie_name = (
        f"basic_auth_{hashlib.sha256(realm.encode()).hexdigest()[:8]}"
    )

    def has_valid_cookie(request: HttpRequest) -> bool:
        if cookie_age is None:
            return False
        value = request.get_signed_cookie(
            cookie_name, default=None, salt=realm, max_age=cookie_age
        )
        return value is not None and value in (
            _credential_hash(u, p) for u, p in credentials
        )

    def decorator(view_func: Callable[[HttpRequest], R]):
        @wraps(view_func)
        def wrapper(request: HttpRequest) -> R | HttpResponse:
            if has_valid_cookie(request):
                return view_func(request)

            if "HTTP_AUTHORIZATION" in request.META:
                auth = request.META["HTTP_AUTHORIZATION"].split()
                if len(auth) == 2 and auth[0].lower() == "basic":
                    try:
                        username, password = (
                            base64.b64decode(auth[1])
                            .decode("utf-8")
                            .split(":", 1)
                        )
                        if (username, password) in credentials:
                            response = view_func(request)
                            if cookie_age is not None and isinstance(
                                response, HttpResponse
                            ):
                                response.set_signed_cookie(
                                    cookie_name,
                                    _credential_hash(username, password),
                                    salt=realm,
                                    max_age=cookie_age,
                                    secure=request.is_secure(),
                                    httponly=True,
                                    samesite="Lax",
                                )
                            return response
                    except (ValueError, UnicodeDecodeError):
                        pass

            response = HttpResponse(status=401)
            response["WWW-Authenticate"] = f'Basic realm="{realm}"'
            return response

        return wrapper

    return decorator
