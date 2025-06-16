import base64
from functools import wraps
from typing import Callable
from typing import ParamSpec
from typing import TypeVar

from django.http import HttpRequest
from django.http import HttpResponse

P = ParamSpec("P")
R = TypeVar("R", covariant=True)


def basic_auth(credentials: list[tuple[str, str]]):
    def decorator(view_func: Callable[[HttpRequest], R]):
        @wraps(view_func)
        def wrapper(request: HttpRequest) -> R | HttpResponse:
            if "HTTP_AUTHORIZATION" in request.META:
                auth = request.META["HTTP_AUTHORIZATION"].split()
                if len(auth) == 2 and auth[0].lower() == "basic":
                    try:
                        username, password = (
                            base64.b64decode(auth[1])
                            .decode("utf-8")
                            .split(":", 1)
                        )
                        if username == "" and password == "":
                            return HttpResponse(status=401)
                        if (username, password) in credentials:
                            return view_func(request)
                    except (ValueError, UnicodeDecodeError):
                        pass

            response = HttpResponse(status=401)
            response["WWW-Authenticate"] = 'Basic realm="API Docs"'
            return response

        return wrapper

    return decorator
