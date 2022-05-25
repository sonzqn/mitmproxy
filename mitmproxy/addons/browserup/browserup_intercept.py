"""Intercept HTTP request"""
import json
import re

from mitmproxy import http, ctx


class MyStubs:
    intercepts = {}

    def __init__(self):
        pass

    def request(self, flow: http.HTTPFlow) -> None:
        intercept = MyStubs.get_intercept(flow)
        if intercept:
            intercept_response = intercept.get("response")
            if intercept_response:
                if intercept_response.get("action").upper() == "STUB":
                    ctx.log.error("process stub response")
                    flow.response = http.Response.make(
                        intercept_response.get("status_code"),  # (optional) status code
                        intercept_response.get("body").encode('utf-8'),  # (optional) content
                        {"Content-Type": "text/html"}  # (optional) headers
                    )
                else:
                    flow.request.headers["intercept_key"] = intercept.get("key")

    def response(self, flow: http.HTTPFlow):
        intercept_key = flow.request.headers.get("intercept_key", None)
        if intercept_key:
            intercept = MyStubs.intercepts.get(intercept_key)
            intercept_response = intercept.get("response")
            if intercept_response:
                ctx.log.error("process modify response")
                status_code = intercept_response.get("status_code", None)
                if status_code:
                    flow.response.status_code = status_code
                body = intercept_response.get("body", None)
                if body:
                    if intercept_response.get("action").upper() == "PATCH":
                        try:
                            src = json.loads(flow.response.content)
                            if type(src) is dict:
                                patch = json.loads(body)
                                MyStubs.patch_json_object(src, patch)
                                flow.response.content = json.dumps(patch).encode('utf-8')
                        except ValueError as err:
                            ctx.log.error(err)
                    else:
                        flow.response.content = body.encode('utf-8')

    @staticmethod
    def get_intercept(flow):
        for key in MyStubs.intercepts:
            intercept = MyStubs.intercepts.get(key)
            # ctx.log.error(json.dumps(intercept))
            predicate = intercept["predicate"]
            if MyStubs.is_match(flow, predicate):
                return {
                    "key": key,
                    "response": intercept["response"]
                }
        return None

    @staticmethod
    def is_match(flow, predicate):
        method = predicate.get("method", None)
        url = predicate.get("url", None)
        headers = predicate.get("headers", None)
        params = predicate.get("params", None)
        body = predicate.get("body", None)
        if method:
            methods = []
            ms = method.split("|")
            for m in ms:
                m = m.strip(" ")
                if m != "":
                    methods.append(m)
            if flow.request.method not in methods:
                return False
        if url and re.search(url, flow.request.pretty_url) is None:
            return False
        if headers:
            for key in headers:
                value = flow.request.headers.get(key, None)
                if value is None:
                    return False
                matcher_value = headers.get(key)
                if re.search(value, matcher_value) is None:
                    return False
        if params:
            for key in params:
                value = flow.request.query.get(key, None)
                if value is None:
                    return False
                matcher_value = params.get(key)
                if re.search(value, matcher_value) is None:
                    return False
        if body:
            if re.search(flow.request.content, body) is None:
                return False
        return True

    @staticmethod
    def patch_json_object(src: dict, patch: dict):
        for key in src:
            src_value = src.get(key)
            patch_value = patch.get(key, None)
            ctx.log.error("The key and value are ({}) = ({}) | type: {}".format(key, src_value, type(src_value)))
            if patch_value is None:
                patch[key] = src_value
            elif type(patch_value) is type(src_value) and type(patch_value) is dict:
                MyStubs.patch_json_object(src_value, patch_value)
            elif patch_value == "{{remove}}":
                del patch[key]
