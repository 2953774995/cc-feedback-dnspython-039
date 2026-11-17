# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2026 DNS audit contributors
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""Offline batch auditing of DNS response messages.

The audit layer sits on top of :func:`dns.message.from_wire` and turns a
stream of raw DNS response packets into per-packet verdicts plus aggregate
statistics.  Packets that cannot be parsed are isolated as ``malformed``
instead of aborting the whole batch, so a capture containing corrupt
responses can always be scanned end to end.

The module is purely offline: it never sends queries or opens sockets, and
it reuses the wire parser and rdata machinery rather than reimplementing
them.
"""

from typing import Any, Iterable, Sequence

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype

#: Maximum number of CNAME hops tolerated before the chain is considered
#: broken (a loop or an over-long chain both map to ``cname_loop``).
MAX_CNAME_HOPS = 10

#: Verdicts that describe a broken response rather than a warning.
_BAD_REASONS = frozenset(
    {
        "malformed",
        "rcode_error",
        "truncated",
        "question_mismatch",
        "no_answer",
        "cname_loop",
    }
)


class AuditItem:
    """Audit verdict for a single response packet.

    Attributes are also accessible with mapping syntax (``item["reason"]``)
    so callers can treat each item as a plain record when loading the
    results into a database.
    """

    __slots__ = (
        "index",
        "ok",
        "reason",
        "rcode",
        "answers",
        "issues",
        "cname_hops",
        "cname_terminal",
    )

    def __init__(self, index: int) -> None:
        #: Zero-based position of the packet in the input stream.
        self.index = index
        #: ``True`` when the response is usable.  TTL anomalies are warnings
        #: and leave this flag set.
        self.ok = False
        #: Primary verdict; one of ``ok``, ``rcode_error``, ``truncated``,
        #: ``malformed``, ``question_mismatch``, ``no_answer``,
        #: ``cname_loop`` or ``ttl_anomaly``.
        self.reason = "malformed"
        #: Text form of the response code (e.g. ``"NXDOMAIN"``), or
        #: ``None`` for packets that could not be parsed.
        self.rcode: str | None = None
        #: Answer records in wire order, each a dict with ``name``,
        #: ``type``, ``ttl`` and ``rdata`` (all stringified except ttl).
        self.answers: list[dict[str, Any]] = []
        #: Every issue detected on this packet, in verdict-priority order.
        #: Empty for fully clean responses.
        self.issues: list[str] = []
        #: Number of CNAME hops followed in the answer section, or ``None``
        #: when the packet could not be parsed.
        self.cname_hops: int | None = None
        #: Owner name where the CNAME chain ends, or ``None`` when there is
        #: no CNAME chain / the packet could not be parsed.
        self.cname_terminal: str | None = None

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError as exc:
            raise KeyError(key) from exc

    def __contains__(self, key: object) -> bool:
        return key in self.__slots__

    def __repr__(self) -> str:
        return (
            f"<AuditItem index={self.index} ok={self.ok} "
            f"reason={self.reason!r} answers={len(self.answers)}>"
        )


class AuditResult:
    """Container returned by :func:`scan_responses`."""

    __slots__ = ("items", "stats")

    def __init__(
        self, items: list[AuditItem], stats: dict[str, Any]
    ) -> None:
        #: One :class:`AuditItem` per input packet, in input order.
        self.items = items
        #: Aggregate counters: ``ok``, ``bad``, ``by_reason``,
        #: ``by_rcode`` and ``by_qtype``.
        self.stats = stats

    def __repr__(self) -> str:
        return f"<AuditResult items={len(self.items)} stats={self.stats!r}>"


def _extract_answers(
    message: dns.message.Message, max_ttl: int
) -> tuple[list[dict[str, Any]], dict[Any, Any], bool]:
    """Pull answer records out in wire order.

    Returns the stringified answer records, a map from CNAME owner name to
    its target (first occurrence wins, mirroring wire order), and whether
    any record carries an anomalous TTL.
    """

    answers: list[dict[str, Any]] = []
    cname_map: dict[Any, Any] = {}
    ttl_anomaly = False
    for rrset in message.answer:
        rdtype_text = dns.rdatatype.to_text(rrset.rdtype)
        name_text = rrset.name.to_text()
        is_cname = rrset.rdtype == dns.rdatatype.CNAME
        for rdata in rrset:
            ttl = int(rrset.ttl)
            answers.append(
                {
                    "name": name_text,
                    "type": rdtype_text,
                    "ttl": ttl,
                    "rdata": rdata.to_text(),
                }
            )
            if ttl == 0 or ttl > max_ttl:
                ttl_anomaly = True
            if is_cname and rrset.name not in cname_map:
                cname_map[rrset.name] = rdata.target
    return answers, cname_map, ttl_anomaly


def _follow_cname(
    message: dns.message.Message, cname_map: dict[Any, Any]
) -> tuple[int, str | None, bool]:
    """Walk the CNAME graph contained in the answer section.

    Returns ``(hops, terminal, broken)`` where *broken* marks a loop or a
    chain longer than :data:`MAX_CNAME_HOPS`.  Walking starts at the first
    question name; without a question section it starts at the first CNAME
    owner name encountered.
    """

    if not cname_map:
        return 0, None, False
    if message.question:
        current = message.question[0].name
    else:
        current = next(iter(cname_map))
    seen: set[Any] = set()
    hops = 0
    while current in cname_map:
        if current in seen:
            return hops, None, True
        seen.add(current)
        hops += 1
        if hops > MAX_CNAME_HOPS:
            return hops, None, True
        current = cname_map[current]
    return hops, current.to_text(), False


def _question_mismatch(
    message: dns.message.Message, expected: dict[str, Any] | None
) -> bool:
    if expected is None:
        return False
    if not message.question:
        return True
    question = message.question[0]
    try:
        expected_name = dns.name.from_text(expected["name"])
        expected_qtype = dns.rdatatype.RdataType.make(expected["qtype"])
    except (KeyError, dns.exception.DNSException):
        # Malformed audit configuration: treat as a mismatch rather than
        # tearing down the whole batch.
        return True
    return question.name != expected_name or question.rdtype != expected_qtype


def _audit_one(
    index: int,
    packet: bytes,
    expected: dict[str, Any] | None,
    max_ttl: int,
) -> tuple[AuditItem, str | None]:
    item = AuditItem(index)

    try:
        message = dns.message.from_wire(packet)
    except Exception:
        # Any parser failure (truncated header, bad compression pointer,
        # trailing junk, ...) isolates this single packet.
        item.reason = "malformed"
        item.issues = ["malformed"]
        return item, None

    item.rcode = dns.rcode.to_text(message.rcode())
    item.answers, cname_map, ttl_anomaly = _extract_answers(message, max_ttl)
    hops, terminal, cname_broken = _follow_cname(message, cname_map)
    item.cname_hops = hops
    item.cname_terminal = terminal

    truncated = bool(message.flags & dns.flags.TC)
    rcode_bad = message.rcode() != dns.rcode.NOERROR
    mismatch = _question_mismatch(message, expected)
    no_answer = len(item.answers) == 0

    # Order doubles as verdict priority: truncation outranks the rcode,
    # hard failures outrank the TTL warning.
    issues: list[str] = []
    if truncated:
        issues.append("truncated")
    if rcode_bad:
        issues.append("rcode_error")
    if mismatch:
        issues.append("question_mismatch")
    if cname_broken:
        issues.append("cname_loop")
    if no_answer:
        issues.append("no_answer")
    if ttl_anomaly:
        issues.append("ttl_anomaly")
    item.issues = issues

    if not issues:
        item.reason = "ok"
        item.ok = True
    elif issues == ["ttl_anomaly"]:
        # TTL anomalies are warnings, not failures.
        item.reason = "ttl_anomaly"
        item.ok = True
    else:
        item.reason = issues[0]
        item.ok = item.reason not in _BAD_REASONS

    if message.question:
        qtype_text = dns.rdatatype.to_text(message.question[0].rdtype)
    else:
        qtype_text = None
    return item, qtype_text


def scan_responses(
    packets: Iterable[bytes],
    expected_questions: Sequence[dict[str, Any]] | None = None,
    max_ttl: int = 86400,
) -> AuditResult:
    """Audit a batch of raw DNS response packets.

    :param packets: Raw DNS messages in wire format.
    :param expected_questions: Optional per-packet expectations, each a
        ``{"name", "qtype"}`` mapping aligned with *packets* by index.
        When supplied, the first question of every packet must match,
        otherwise the packet is flagged ``question_mismatch``; when
        ``None`` the check is skipped entirely.
    :param max_ttl: Upper bound for answer TTLs; records with TTL 0 or a
        TTL above this value trigger a ``ttl_anomaly`` warning.
    :returns: An :class:`AuditResult` with per-packet :attr:`~AuditResult.items`
        and aggregate :attr:`~AuditResult.stats`.
    """

    items: list[AuditItem] = []
    by_reason: dict[str, int] = {}
    by_rcode: dict[str, int] = {}
    by_qtype: dict[str, int] = {}
    ok_count = 0

    for index, packet in enumerate(packets):
        if expected_questions is not None and index < len(expected_questions):
            expected = expected_questions[index]
        else:
            expected = None
        item, qtype_text = _audit_one(index, packet, expected, max_ttl)
        items.append(item)

        by_reason[item.reason] = by_reason.get(item.reason, 0) + 1
        if item.rcode is not None:
            by_rcode[item.rcode] = by_rcode.get(item.rcode, 0) + 1
        if qtype_text is not None:
            by_qtype[qtype_text] = by_qtype.get(qtype_text, 0) + 1
        if item.ok:
            ok_count += 1

    stats = {
        "ok": ok_count,
        "bad": len(items) - ok_count,
        "by_reason": by_reason,
        "by_rcode": by_rcode,
        "by_qtype": by_qtype,
    }
    return AuditResult(items, stats)
