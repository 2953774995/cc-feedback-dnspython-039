#!/bin/bash
cd "$(dirname "$0")"
PY=.venv/bin/python
[ -x "$PY" ] || PY=python3

echo "============================================================"
echo "第一部分：验收探针"
echo "============================================================"
$PY probes/run_probes.py
PROBE_RC=$?
echo

echo "============================================================"
echo "第二部分：既有测试（不得退化）"
echo "============================================================"
# 本仓库有 13 条用例需要真实网络/系统解析器（TestTLS、LiveResolverTests、
# test_ddr 的在线查询、resolver_override），在离线评测机上基线即失败，
# 与本次实现无关，故按节点 id 排除后再判「不得退化」。
LIVE_TESTS=(
  "tests/test_async.py::AsyncTests::testCanonicalNameCNAME"
  "tests/test_async.py::AsyncTests::testQueryTLS"
  "tests/test_async.py::AsyncTests::testQueryTLSWithContext"
  "tests/test_async.py::AsyncTests::testQueryTLSWithSocket"
  "tests/test_ddr.py::test_basic_ddr_async"
  "tests/test_ddr.py::test_basic_ddr_sync"
  "tests/test_query.py::QueryTests::testQueryTLS"
  "tests/test_query.py::QueryTests::testQueryTLSWithContext"
  "tests/test_query.py::QueryTests::testQueryTLSWithSocket"
  "tests/test_query.py::QueryTests::testQueryTLSwithPadding"
  "tests/test_resolver.py::LiveResolverTests"
  "tests/test_resolver.py::LiveResolverTests::testTLSNameserver"
  "tests/test_resolver_override.py::OverrideSystemResolverTestCase::test_basic_getaddrinfo"
)
DESELECT=()
for t in "${LIVE_TESTS[@]}"; do DESELECT+=(--deselect "$t"); done

$PY -m pytest -q "${DESELECT[@]}" 2>&1 | tail -3
PYTEST_RC=${PIPESTATUS[0]}
echo

echo "############################################################"
echo "# 汇总"
echo "############################################################"
[ $PROBE_RC -eq 0 ] && echo "验收探针：PASS" || echo "验收探针：FAIL"
[ $PYTEST_RC -eq 0 ] && echo "既有测试：PASS" || echo "既有测试：FAIL"
if [ $PROBE_RC -eq 0 ] && [ $PYTEST_RC -eq 0 ]; then
    echo; echo "总体结果：全部通过"; exit 0
fi
echo; echo "总体结果：存在未通过项"; exit 1
