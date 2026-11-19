#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""e2e_openwrt.py 的单元测试（不依赖 docker / 网络 / 真实二进制）。

用 unittest.mock 替换 subprocess.run，验证：
  1) RSS 解析：parse_rss_line 与 read_rss（mock dexec）各种输入
  2) mock procd 记录解析：check_procd_log 各种缺失组合
  3) run() / dexec() 的命令拼装与失败行为（逐条复核 docker 参数）
  4) free_port / check_versions 的管道行为（mock）

运行：
    python3 scripts/test_e2e_openwrt.py
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import e2e_openwrt as e2e  # noqa: E402


class TestParseRss(unittest.TestCase):
    def test_parse_rss_line_standard(self):
        self.assertEqual(e2e.parse_rss_line("VmRSS:\t   1234 kB"), 1234)

    def test_parse_rss_line_spaces(self):
        self.assertEqual(e2e.parse_rss_line("Name:\tfrps\nVmRSS:  9876 kB\nThreads:\t8"), 9876)

    def test_parse_rss_line_without_unit(self):
        # 有些内核把单位写成 KB 或省略，取第二个字段即可
        self.assertEqual(e2e.parse_rss_line("VmRSS: 4096 KB"), 4096)

    def test_parse_rss_line_missing(self):
        self.assertIsNone(e2e.parse_rss_line("Name:\tfrps\nVmSize: 999 kB"))

    def test_parse_rss_line_malformed(self):
        self.assertIsNone(e2e.parse_rss_line("VmRSS:  ??? kB"))
        self.assertIsNone(e2e.parse_rss_line(""))

    def test_read_rss_ok(self):
        cp = subprocess.CompletedProcess([], 0, stdout="VmRSS:\t2048 kB\n", stderr="")
        with mock.patch.object(e2e, "dexec", return_value=cp) as d:
            got = e2e.read_rss("nfrp-server")
        self.assertEqual(got, "2048 kB")
        # 复核：read_rss 的确通过 dexec 走 docker exec sh -c，含 pgrep + /proc
        args = d.call_args.args
        self.assertEqual(args[0], "sh")
        self.assertEqual(args[1], "-c")
        self.assertIn("pgrep -f", args[2])
        self.assertIn("/proc/$pid/status", args[2])

    def test_read_rss_no_rss(self):
        cp = subprocess.CompletedProcess([], 0, stdout="NO-RSS\n", stderr="")
        with mock.patch.object(e2e, "dexec", return_value=cp):
            self.assertEqual(e2e.read_rss("nfrp-server"), "NO-RSS")

    def test_read_rss_unparsed(self):
        cp = subprocess.CompletedProcess([], 0, stdout="garbage\n", stderr="")
        with mock.patch.object(e2e, "dexec", return_value=cp):
            self.assertTrue(e2e.read_rss("nfrp-server").startswith("UNPARSED["))


class TestProcdLog(unittest.TestCase):
    FULL = "\n".join([
        "open",
        "param:respawn 3600 5 0",
        "param:stdout 1",
        "param:stderr 1",
        "close",
        "---RELOAD---",
        "restart-called",
    ])

    def test_full_log(self):
        ok, why = e2e.check_procd_log(self.FULL)
        self.assertTrue(ok)
        self.assertEqual(why, "全部满足")

    def test_missing_respawn(self):
        out = self.FULL.replace("param:respawn 3600 5 0\n", "")
        ok, why = e2e.check_procd_log(out)
        self.assertFalse(ok)
        self.assertIn("respawn", why)

    def test_missing_stdout(self):
        out = self.FULL.replace("param:stdout 1\n", "")
        ok, why = e2e.check_procd_log(out)
        self.assertFalse(ok)
        self.assertIn("stdout=logd", why)

    def test_missing_stderr(self):
        out = self.FULL.replace("param:stderr 1\n", "")
        ok, why = e2e.check_procd_log(out)
        self.assertFalse(ok)
        self.assertIn("stderr=logd", why)

    def test_missing_reload(self):
        out = self.FULL.replace("\nrestart-called", "")
        ok, why = e2e.check_procd_log(out)
        self.assertFalse(ok)
        self.assertIn("reload/restart", why)

    def test_respawn_no_args_not_accepted(self):
        # "param:respawn" 后面没有参数不算（要求 "param:respawn "）
        out = self.FULL.replace("param:respawn 3600 5 0", "param:respawn")
        ok, _ = e2e.check_procd_log(out)
        self.assertFalse(ok)


class TestRunCommands(unittest.TestCase):
    def test_run_builds_subprocess_run(self):
        cp = subprocess.CompletedProcess(["docker", "ps"], 0, stdout="ok", stderr="")
        with mock.patch.object(e2e.subprocess, "run", return_value=cp) as r:
            got = e2e.run(["docker", "ps"])
        self.assertEqual(got.stdout, "ok")
        r.assert_called_once()
        args, kwargs = r.call_args
        self.assertEqual(args[0], ["docker", "ps"])
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])

    def test_run_check_failure_raises(self):
        cp = subprocess.CompletedProcess([], 7, stdout="", stderr="boom")
        with mock.patch.object(e2e.subprocess, "run", return_value=cp):
            with self.assertRaises(RuntimeError):
                e2e.run(["docker", "bad"], check=True)

    def test_run_no_check_returns(self):
        cp = subprocess.CompletedProcess([], 7, stdout="", stderr="boom")
        with mock.patch.object(e2e.subprocess, "run", return_value=cp):
            got = e2e.run(["docker", "bad"], check=False)
        self.assertEqual(got.returncode, 7)

    def test_dexec_prepends_docker_exec(self):
        cp = subprocess.CompletedProcess([], 0, stdout="x", stderr="")
        with mock.patch.object(e2e, "run", return_value=cp) as r:
            e2e.dexec("cat", "/tmp/x")
        args = r.call_args.args[0]
        self.assertEqual(args[:4], ["docker", "exec", e2e.CONTAINER, "cat"])
        self.assertEqual(args[4], "/tmp/x")

    def test_start_container_docker_args(self):
        # 逐条复核 docker run 参数：detach / name / host 网络 / entrypoint
        with mock.patch.object(e2e, "cleanup_container"), \
             mock.patch.object(e2e, "run", return_value=subprocess.CompletedProcess([], 0)) as r:
            e2e.start_container("nfrp-openwrt:test")
        args = r.call_args.args[0]
        self.assertEqual(args[0], "docker")
        self.assertEqual(args[1], "run")
        self.assertEqual(args[2], "-d")
        self.assertIn("--name", args)
        self.assertIn(e2e.CONTAINER, args)
        self.assertIn("--network", args)
        self.assertEqual(args[args.index("--network") + 1], "host")
        self.assertIn("--entrypoint", args)
        self.assertEqual(args[args.index("--entrypoint") + 1], "/bin/sh")
        self.assertIn("nfrp-openwrt:test", args)
        self.assertEqual(args[-1], "sleep infinity")

    def test_check_versions_judgement(self):
        good = subprocess.CompletedProcess([], 0, stdout="0.71.0\n", stderr="")
        bad = subprocess.CompletedProcess([], 0, stdout="frpc version 0.71.0\n", stderr="")
        with mock.patch.object(e2e, "dexec", side_effect=[good, bad]), \
             mock.patch.object(e2e, "report") as rep:
            e2e.check_versions()
        calls = rep.call_args_list
        self.assertTrue(calls[0].args[1])   # 裸版本通过
        self.assertFalse(calls[1].args[1])  # 带前缀不通过


if __name__ == "__main__":
    unittest.main(verbosity=2)
