#!/usr/bin/env python3
"""验收探针：DNS 响应批量审计（10 条契约）。

全部离线：报文用 dns.message 现场构造，不发任何真实查询。
在未实现 `dns.audit` 的基线上，10 条全部 FAIL。
"""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RESULTS = []


def probe(name):
    def deco(fn):
        try:
            fn()
        except AssertionError as exc:
            RESULTS.append((name, False, str(exc) or "断言失败"))
        except Exception as exc:
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            RESULTS.append((name, True, ""))
        return fn

    return deco


def audit():
    import dns.audit as m  # noqa: F401

    return m


def _msg(qname="example.com", qtype="A", ttl=300, rdata="1.2.3.4", rcode=None, tc=False, answers=None):
    import dns.flags
    import dns.message
    import dns.rcode
    import dns.rrset

    q = dns.message.make_query(qname, qtype)
    r = dns.message.make_response(q)
    if answers is None:
        answers = [(qname, qtype, ttl, rdata)]
    for name, typ, t, rd in answers:
        r.answer.append(dns.rrset.from_text(name, t, "IN", typ, rd))
    if rcode is not None:
        r.set_rcode(rcode)
    if tc:
        r.flags |= dns.flags.TC
    return r.to_wire()


@probe("P01 批量入口与正常响应")
def p01():
    m = audit()
    out = m.scan_responses([_msg(), _msg()])
    assert hasattr(out, "items") and hasattr(out, "stats"), "需返回 items 与 stats"
    assert len(out.items) == 2, f"应返回 2 条，实际 {len(out.items)}"
    for key in ("index", "ok", "reason", "rcode", "answers"):
        assert key in out.items[0], f"item 缺字段 {key}"
    assert all(i.ok and i.reason == "ok" for i in out.items), f"正常响应应 ok，实际 {[i.reason for i in out.items]}"
    a = out.items[0].answers[0]
    for key in ("name", "type", "ttl", "rdata"):
        assert key in a, f"answer 缺字段 {key}"
    assert a["rdata"] == "1.2.3.4" and a["ttl"] == 300, f"answer 内容不对：{a}"


@probe("P02 错误码与截断位")
def p02():
    import dns.rcode

    m = audit()
    out = m.scan_responses([_msg(rcode=dns.rcode.NXDOMAIN)])
    assert out.items[0].reason == "rcode_error", f"应为 rcode_error，实际 {out.items[0].reason}"
    assert out.items[0].rcode.upper().endswith("NXDOMAIN") or "NXDOMAIN" in str(out.items[0].rcode), \
        f"rcode 应可读，实际 {out.items[0].rcode}"
    out2 = m.scan_responses([_msg(tc=True)])
    assert out2.items[0].reason == "truncated", f"应为 truncated，实际 {out2.items[0].reason}"


@probe("P03 坏报文隔离")
def p03():
    m = audit()
    garbage = [b"\x00\x00\x00\x00", b"\xff" * 12, b"\x12\x34"]
    out = m.scan_responses(garbage + [_msg()])
    reasons = [i.reason for i in out.items]
    assert reasons[:3] == ["malformed"] * 3, f"坏报文应全为 malformed，实际 {reasons}"
    assert reasons[3] == "ok", "坏报文之后的正常响应应继续"


@probe("P04 问题段不匹配")
def p04():
    m = audit()
    wire = _msg(qname="real.example.com")
    out = m.scan_responses([wire], expected_questions=[{"name": "other.example.com", "qtype": "A"}])
    assert out.items[0].reason == "question_mismatch", f"应为 question_mismatch，实际 {out.items[0].reason}"
    out2 = m.scan_responses([wire], expected_questions=[{"name": "real.example.com", "qtype": "A"}])
    assert out2.items[0].ok, f"匹配时应 ok，实际 {out2.items[0].reason}"
    out3 = m.scan_responses([wire])
    assert out3.items[0].ok, "未给 expected_questions 时跳过该判断"


@probe("P05 CNAME 链跟随")
def p05():
    m = audit()
    chain = _msg(
        qname="a.example.com",
        answers=[
            ("a.example.com", "CNAME", 300, "b.example.com"),
            ("b.example.com", "CNAME", 300, "c.example.com"),
            ("c.example.com", "A", 300, "9.9.9.9"),
        ],
    )
    out = m.scan_responses([chain])
    item = out.items[0]
    assert item.ok, f"CNAME 链应 ok，实际 {item.reason}"
    assert getattr(item, "cname_hops", None) == 2, f"应记 2 跳，实际 {getattr(item, 'cname_hops', None)}"
    assert item.answers[-1]["rdata"] == "9.9.9.9", "链尾 A 记录应保留"


@probe("P06 CNAME 环检测")
def p06():
    m = audit()
    loop = _msg(
        qname="x.example.com",
        answers=[
            ("x.example.com", "CNAME", 300, "y.example.com"),
            ("y.example.com", "CNAME", 300, "x.example.com"),
        ],
    )
    out = m.scan_responses([loop])
    assert out.items[0].reason == "cname_loop", f"应为 cname_loop，实际 {out.items[0].reason}"


@probe("P07 TTL 异常告警")
def p07():
    m = audit()
    zero = _msg(ttl=0)
    huge = _msg(ttl=999999)
    out = m.scan_responses([zero, huge], max_ttl=86400)
    for item in out.items:
        assert item.reason == "ttl_anomaly", f"TTL 异常应记 ttl_anomaly，实际 {item.reason}"
        assert item.ok, "TTL 异常只是告警，ok 仍应为真"


@probe("P08 无 answer 与多问题并存")
def p08():
    m = audit()
    out = m.scan_responses([_msg(answers=[])])
    assert out.items[0].reason == "no_answer", f"应为 no_answer，实际 {out.items[0].reason}"
    import dns.flags
    import dns.rcode

    both = _msg(rcode=dns.rcode.SERVFAIL, tc=True)
    out2 = m.scan_responses([both])
    assert out2.items[0].reason == "truncated", f"两者并存应取 truncated，实际 {out2.items[0].reason}"
    issues = getattr(out2.items[0], "issues", [])
    joined = " ".join(str(x) for x in issues)
    assert "rcode" in joined and "truncat" in joined.lower(), f"issues 应列两项，实际 {issues}"


@probe("P09 统计与空输入")
def p09():
    m = audit()
    import dns.rcode

    out = m.scan_responses([_msg(), _msg(rcode=dns.rcode.NXDOMAIN), b"\x00garbage"])
    st = out.stats
    assert st["ok"] == 1 and st["bad"] == 2, f"ok/bad 不对：{st}"
    assert st["by_reason"].get("rcode_error") == 1, f"by_reason 不对：{st['by_reason']}"
    assert st["by_qtype"].get("A") == 2, f"by_qtype 不对：{st['by_qtype']}"
    empty = m.scan_responses([])
    assert empty.items == [] and empty.stats["ok"] == 0, "空输入应返回空结构"


@probe("P10 万级性能与既有解析不回归")
def p10():
    import dns.message

    m = audit()
    wire = _msg()
    packets = [wire for _ in range(10000)]
    t0 = time.perf_counter()
    out = m.scan_responses(packets)
    cost = time.perf_counter() - t0
    assert out.stats["ok"] == 10000, f"万条应全部 ok，实际 {out.stats['ok']}"
    assert cost < 2.0, f"万条耗时 {cost:.2f}s 超过 2s"
    msg = dns.message.from_wire(wire)
    assert msg.answer[0][0].address == "1.2.3.4", "既有 from_wire 被破坏"


def main():
    print("=" * 60)
    print("验收探针：DNS 响应批量审计（10 条契约）")
    print("=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, detail in RESULTS:
        print(f"PASS  {name}" if ok else f"FAIL  {name}\n      {detail}")
    print("-" * 60)
    print(f"探针结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
