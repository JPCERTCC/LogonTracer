"""PageRank regression tests (imports logontracer.py; no Neo4j needed)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.argv = ["logontracer.py"]

import pandas as pd  # noqa: E402
import pytest  # noqa: E402

lt = pytest.importorskip("logontracer")


def test_no_substring_edges():
    events = pd.DataFrame({"ipaddress": ["192.0.2.1", "192.0.2.12"], "username": ["ana@", "joana@"]})
    ranks = lt.pagerank(events, [], {}, {}, [])
    # Two disconnected, symmetric components -> identical ranks per role
    assert ranks["192.0.2.1"] == pytest.approx(ranks["192.0.2.12"])
    assert ranks["ana@"] == pytest.approx(ranks["joana@"])


def test_uniform_graph_no_zero_division():
    events = pd.DataFrame({"ipaddress": ["192.0.2.1"], "username": ["192.0.2.1"]})
    assert set(lt.pagerank(events, [], {}, {}, []).values()) == {0.0}


def test_flagged_nodes_rank_higher():
    events = pd.DataFrame({"ipaddress": ["192.0.2.1", "192.0.2.2", "192.0.2.3"],
                           "username": ["ana@", "rui@", "eva@"]})
    base = lt.pagerank(events, [], {}, {}, [])
    flagged = lt.pagerank(events, [], {}, {}, [], {"rui@"})
    assert base["rui@"] == pytest.approx(base["ana@"])
    assert flagged["rui@"] != pytest.approx(flagged["ana@"])


def test_empty_event_set():
    events = pd.DataFrame({"ipaddress": [], "username": []})
    assert lt.pagerank(events, [], {}, {}, []) == {}
