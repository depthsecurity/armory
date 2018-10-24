#!/usr/bin/python

import requests
import json
import pdb
import urllib3
import shutil
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NessusRequest(object):

    HEADERS = {}

    def __init__(
        self,
        username,
        password,
        host,
        verify=False,
        proxies=None,
        uuid=None,
        folder_id=None,
        policy_id=23,
    ):

        self.VERIFY = verify
        self.PROXIES = proxies

        self.HOST = host
        self.login(username, password, host)

        self.folder_id = folder_id
        self.policy_id = policy_id
        self.uuid = uuid

    def req(self, verb, uri, **kwargs):

        if verb == "get":
            func = requests.get
        elif verb == "post":
            func = requests.post
        elif verb == "put":
            func = requests.put
        else:
            func = requests.get

        return func(
            self.HOST + uri,
            headers=self.HEADERS,
            verify=self.VERIFY,
            proxies=self.PROXIES,
            **kwargs
        )

    def login(self, username, password, host):

        # We need to get both the API key and the Session token

        res = self.req("get", "/nessus6.js")

        token_location = res.text.find('getApiToken",value:function(){return')

        self.HEADERS["X-API-TOKEN"] = res.text[
            token_location : token_location + 200
        ].split('"')[2]
        self.HEADERS["Content-Type"] = "application/json"
        data = '{"username":"%s","password":"%s"}' % (username, password)
        res = self.req("post", "/session", data=data)

        self.HEADERS["X-Cookie"] = "token=" + json.loads(res.text)["token"]

    def launch_job(self, targets, name="Job launched from Armory"):

        data = {
            "uuid": self.uuid,
            "settings": {
                "emails": "",
                "filter_type": "and",
                "filters": [],
                "launch_now": True,
                "enabled": False,
                "file_targets": "",
                "text_targets": targets,
                "policy_id": self.policy_id,
                "scanner_id": "1",
                "folder_id": self.folder_id,
                "description": "Launched by Armory",
                "name": name,
            },
        }

        res = json.loads(self.req("post", "/scans", data=json.dumps(data)).text)
        return res["scan"]["id"]

    def get_status(self, job_id):

        res = json.loads(self.req("get", "/scans/{}".format(str(job_id))).text)
        return res["info"]["status"]

    def export_file(self, job_id, output_path):

        data = json.dumps({"format": "nessus"})

        res = json.loads(
            self.req("post", "/scans/{}/export".format(job_id), data=data).text
        )

        token = res["token"]
        fsize = res["file"]

        res = json.loads(self.req("get", "/tokens/{}/status".format(token)).text)

        while res["status"] != "ready":
            print("Download not ready yet. Sleeping for 5 seconds")
            time.sleep(5)
            res = json.loads(self.req("get", "/tokens/{}/status".format(token)).text)

        print("Download ready.")
        res = self.req("get", "/tokens/{}/download".format(token), stream=True)
        res.raw.decode_content = True
        with open(output_path, "wb") as f:
            shutil.copyfileobj(res.raw, f)
