import contextlib
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "download_all.py"


def load_downloader():
    spec = importlib.util.spec_from_file_location("adjust_download_all", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RouteHandler(BaseHTTPRequestHandler):
    routes = {}
    requests = []

    def do_GET(self):
        type(self).requests.append(
            {
                "path": self.path,
                "range": self.headers.get("Range"),
                "authorization": self.headers.get("Authorization"),
                "user_agent": self.headers.get("User-Agent"),
            }
        )
        route = type(self).routes.get(self.path)
        if route is None:
            self.send_error(404)
            return
        if callable(route):
            route(self)
            return
        status, headers, body = route
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class LocalServer:
    def __enter__(self):
        RouteHandler.routes = {}
        RouteHandler.requests = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), RouteHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = "http://{}:{}".format(host, port)
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def route(self, path, body=b"", status=200, headers=None):
        RouteHandler.routes[path] = (status, headers or {}, body)

    def callback(self, path, callback):
        RouteHandler.routes[path] = callback

    @property
    def requests(self):
        return list(RouteHandler.requests)


class DownloadAllTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.downloader = load_downloader()

    def test_fetch_releases_follows_pagination_and_sends_headers(self):
        with LocalServer() as server:
            page_two = server.base_url + "/releases?page=2"
            page_one_body = json.dumps(
                [
                    {
                        "tag_name": "v2.0.0",
                        "assets": [
                            {
                                "name": "sdk-2.zip",
                                "size": 2,
                                "browser_download_url": server.base_url + "/sdk-2.zip",
                                "digest": "sha256:" + hashlib.sha256(b"v2").hexdigest(),
                            }
                        ],
                    }
                ]
            ).encode()
            page_two_body = json.dumps(
                [
                    {
                        "tag_name": "v1.0.0",
                        "assets": [
                            {
                                "name": "sdk-1.zip",
                                "size": 2,
                                "browser_download_url": server.base_url + "/sdk-1.zip",
                                "digest": None,
                            }
                        ],
                    }
                ]
            ).encode()
            server.route(
                "/releases?page=1",
                page_one_body,
                headers={"Link": '<{}>; rel="next"'.format(page_two)},
            )
            server.route("/releases?page=2", page_two_body)

            release_count, assets = self.downloader.fetch_releases(
                server.base_url + "/releases?page=1", token="secret-token"
            )

            self.assertEqual(2, release_count)
            self.assertEqual(["v2.0.0", "v1.0.0"], [asset.tag for asset in assets])
            self.assertEqual("Bearer secret-token", server.requests[0]["authorization"])
            self.assertIn("adjust-signature-sdk-downloader", server.requests[0]["user_agent"])

    def test_safe_target_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            invalid = [
                ("../escape", "sdk.zip"),
                ("v1", "../sdk.zip"),
                ("v1/child", "sdk.zip"),
                ("v1", "child/sdk.zip"),
                ("v1", "child\\sdk.zip"),
            ]
            for tag, name in invalid:
                with self.subTest(tag=tag, name=name):
                    with self.assertRaises(self.downloader.MetadataError):
                        self.downloader.safe_target(root, tag, name)

    def test_complete_file_is_skipped_without_asset_request(self):
        data = b"already complete"
        with tempfile.TemporaryDirectory() as temp_dir, LocalServer() as server:
            root = Path(temp_dir)
            target = root / "v1" / "sdk.zip"
            target.parent.mkdir()
            target.write_bytes(data)
            asset = self.downloader.Asset(
                "v1",
                "sdk.zip",
                len(data),
                server.base_url + "/sdk.zip",
                "sha256:" + hashlib.sha256(data).hexdigest(),
            )

            result = self.downloader.download_asset(asset, root, retries=1)

            self.assertEqual("skipped", result)
            self.assertEqual([], server.requests)

    def test_partial_file_is_resumed_with_range(self):
        data = b"abcdef"
        with tempfile.TemporaryDirectory() as temp_dir, LocalServer() as server:
            root = Path(temp_dir)
            part = root / "v1" / "sdk.zip.part"
            part.parent.mkdir()
            part.write_bytes(data[:3])

            def ranged(handler):
                self.assertEqual("bytes=3-", handler.headers.get("Range"))
                handler.send_response(206)
                handler.send_header("Content-Range", "bytes 3-5/6")
                handler.end_headers()
                handler.wfile.write(data[3:])

            server.callback("/sdk.zip", ranged)
            asset = self.downloader.Asset("v1", "sdk.zip", 6, server.base_url + "/sdk.zip", "")

            result = self.downloader.download_asset(asset, root, retries=1)

            self.assertEqual("resumed", result)
            self.assertEqual(data, (root / "v1" / "sdk.zip").read_bytes())
            self.assertFalse(part.exists())

    def test_server_ignoring_range_restarts_instead_of_appending(self):
        data = b"abcdef"
        with tempfile.TemporaryDirectory() as temp_dir, LocalServer() as server:
            root = Path(temp_dir)
            part = root / "v1" / "sdk.zip.part"
            part.parent.mkdir()
            part.write_bytes(data[:3])
            server.route("/sdk.zip", data)
            asset = self.downloader.Asset("v1", "sdk.zip", 6, server.base_url + "/sdk.zip", "")

            result = self.downloader.download_asset(asset, root, retries=1)

            self.assertEqual("downloaded", result)
            self.assertEqual(data, (root / "v1" / "sdk.zip").read_bytes())

    def test_digest_mismatch_keeps_part_and_does_not_create_final_file(self):
        expected = b"good"
        received = b"evil"
        with tempfile.TemporaryDirectory() as temp_dir, LocalServer() as server:
            root = Path(temp_dir)
            server.route("/sdk.zip", received)
            asset = self.downloader.Asset(
                "v1",
                "sdk.zip",
                len(received),
                server.base_url + "/sdk.zip",
                "sha256:" + hashlib.sha256(expected).hexdigest(),
            )

            with self.assertRaises(self.downloader.DownloadError):
                self.downloader.download_asset(asset, root, retries=1)

            self.assertFalse((root / "v1" / "sdk.zip").exists())
            self.assertEqual(received, (root / "v1" / "sdk.zip.part").read_bytes())

    def test_run_continues_after_one_asset_fails(self):
        good_data = b"good"
        with tempfile.TemporaryDirectory() as temp_dir, LocalServer() as server:
            assets = [
                {
                    "name": "bad.zip",
                    "size": 3,
                    "browser_download_url": server.base_url + "/bad.zip",
                    "digest": None,
                },
                {
                    "name": "good.zip",
                    "size": len(good_data),
                    "browser_download_url": server.base_url + "/good.zip",
                    "digest": None,
                },
            ]
            body = json.dumps([{"tag_name": "v1", "assets": assets}]).encode()
            server.route("/releases", body)
            server.route("/bad.zip", b"no", status=500)
            server.route("/good.zip", good_data)
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                exit_code = self.downloader.run(
                    Path(temp_dir), server.base_url + "/releases", retries=1
                )

            self.assertEqual(1, exit_code)
            self.assertEqual(good_data, (Path(temp_dir) / "v1" / "good.zip").read_bytes())
            self.assertIn("failed: 1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
