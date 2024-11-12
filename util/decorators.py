import functools

from flask import jsonify

from util.exception import APIError


def auto_handle_exception_and_jsonify(func):
    """
    A decorator that wraps the passed in function and logs any exceptions that occur
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        response_data = APIError.default_response_data()
        try:
            response_data = func()
        except APIError as e:
            response_data = e.gen_response_data()
        finally:
            return jsonify(response_data)

    return wrapper
