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
            return_type = intercept_response.get("return_type", None)
            if intercept_response:
                if intercept_response.get("action").upper() == "STUB":
                    ctx.log.info("============ Process stub response ============")
                    stub_body = intercept_response.get("body")
                    # khai báo thằng stub content type là kiểu text
                    # stub_content_type = "text/html"

                    if type(stub_body) is str:
                        x = stub_body.replace("'", '"')
                        stub_body = json.loads(x)

                    if type(stub_body) is dict:
                        stub_body = json.dumps(stub_body)

                        # sort response
                        MyStubs.sort_response_by_key(stub_body)
                        MyStubs.sort_response_by_value(stub_body)

                        # stub_content_type = "application/json; charset=utf-8"
                    stub_content_type = "application/json; charset=utf-8"
                    flow.response = http.Response.make(
                        intercept_response.get("status_code"),  # (optional) status code
                        stub_body.encode('utf-8'),  # (optional) content
                        {"Content-Type": stub_content_type}  # (optional) headers
                    )
                else:
                    flow.request.headers["intercept_key"] = intercept.get("key")

    def response(self, flow: http.HTTPFlow):
        intercept_key = flow.request.headers.get("intercept_key", None)
        if intercept_key:
            intercept = MyStubs.intercepts.get(intercept_key)
            intercept_response = intercept.get("response")

            if intercept_response:
                ctx.log.info("============ Process modify response ============")
                status_code = intercept_response.get("status_code", None)
                if status_code:
                    ctx.log.info("Change status code from {} to {}".format(flow.response.status_code, status_code))
                    flow.response.status_code = status_code
                body = intercept_response.get("body", None)

                if body:
                    if intercept_response.get("action").upper() == "PATCH":
                        try:
                            src = json.loads(flow.response.content)
                            if type(src) is str:
                                x = src.replace("'", '"')
                                src = json.loads(x)
                            if type(src) is dict:
                                MyStubs.patch_json_object(src, body)
                                ctx.log.info("@Original response content:")
                                ctx.log.info(flow.response.content)
                                flow.response.content = json.dumps(src).encode('utf-8')
                                ctx.log.info("@Patched response content:")
                                ctx.log.info(flow.response.content)
                        except ValueError as err:
                            ctx.log.error(err)
                    else:
                        ctx.log.error(type(body))
                        ctx.log.error(body)
                        if type(body) is str:
                            x = body.replace("'", '"')
                            body = json.loads(x)
                        if type(body) is dict:
                            ctx.log.info("@Original response content:")
                            ctx.log.info(flow.response.content)
                            flow.response.content = json.dumps(body).encode('utf-8')
                            ctx.log.info("@Replaced response content:")
                            ctx.log.error(flow.response.content)
                        else:
                            flow.response.content = body.encode('utf-8')

    @staticmethod
    def get_intercept(flow):
        for key in MyStubs.intercepts:
            intercept = MyStubs.intercepts.get(key)
            # ctx.log.error(json.dumps(intercept))
            predicate = intercept["predicate"]
            if MyStubs.is_match(flow, predicate):
                ctx.log.info("Found matched intercept with name: {}".format(predicate.get("name")))
                return {
                    "key": key,
                    "response": intercept["response"]
                }
        return None

    @staticmethod
    def is_match(flow, predicate):
        if re.search("intercept$", flow.request.pretty_url) is not None:
            return False
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
                if re.search(matcher_value, value) is None:
                    return False
        if params:
            for key in params:
                value = flow.request.query.get(key, None)
                if value is None:
                    return False
                matcher_value = params.get(key)
                if re.search(matcher_value, value) is None:
                    return False
        if body:
            if re.search(flow.request.content, body) is None:
                return False
        return True

    @staticmethod
    def patch_json_object(src: dict, patch: dict):
        for key in patch:
            # lấy giá trị của src
            src_value = src.get(key)
            patch_value = patch.get(key, None)
            # ctx.log.error("The key and value are ({}) = ({}) | type: {}".format(key, src_value, type(src_value)))
            # ctx.log.error("Path value: {}".format(patch_value))
            #
            # patch có giá trị thì sẽ vá ko quan tâm đến src
            if patch_value is not None and patch_value != "{{remove}}":
                src[key] = patch_value
            #
            elif type(patch_value) is type(src_value) and type(patch_value) is dict:
                MyStubs.patch_json_object(src_value, patch_value)
            #
            # src không có, pacth bằng remove thì xóa path và không trả về giá trị này
            elif src_value is not None and patch_value == "{{remove}}":
                del src[key]


    @staticmethod
    def sort_response_by_key(stub_body: dict):
        x = json.loads(stub_body)
        print(sorted(x.items()))

    @staticmethod
    def sort_response_by_value(stub_body: dict):
        x = json.loads(stub_body)
        print(type(x))

        # sort theo value tang dan trong trường hợp không phải là nested dict
        # Sử dụng vòng lặp
        # sorted_values = sorted(x.values())
        # sorted_x = {}
        # for i in sorted_values:
        #     for k in x.keys():
        #         if x[k] == i:
        #             sorted_x[k] = x[k]
        #             break
        # print(sorted_x)

        # Sử dụng function sorted
        # sorted_x = {}
        # sorted_keys = sorted(x, key=x.get)
        # for w in sorted_keys:
        #     sorted_x[w] = x[w]
        # print(sorted_x)