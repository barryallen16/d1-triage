"""Tests for triage/dataset.py - method windows and name neutralization."""
from triage.dataset import build_window, method_ranges, neutralize

SRC = """package foo;

import java.io.File;

public class Example {
    private int field;

    public void safeMethod(String input) {
        File f = new File(input);
        System.out.println(f);
    }

    public void badMethod(String input) {
        File f = new File(input);
        if (input.startsWith("/")) {
            throw new RuntimeException();
        }
    }
}
"""


def test_method_ranges_finds_methods():
    ranges = method_ranges(SRC)
    names = {r[0] for r in ranges}
    assert "safeMethod" in names
    assert "badMethod" in names


def test_build_window_returns_enclosing_method():

    name, window = build_window(SRC, 8, None, juliet=False)
    assert name == "safeMethod"
    assert "safeMethod" in window
    assert "badMethod" not in window


def test_build_window_line_outside_method():

    assert build_window(SRC, 2, None, juliet=False) is None


def test_neutralize_flips_prefix_per_row():
    code = "public void good1() { } public void bad2() { }"
    rng_a = __import__("random").Random(1)
    rng_b = __import__("random").Random(2)
    out_a = neutralize(code, rng_a)
    out_b = neutralize(code, rng_b)

    for out in (out_a, out_b):
        assert "good1" not in out and "bad2" not in out

    good_a_funcA = out_a.find("funcA1") < out_a.find("funcB1")
    good_b_funcA = out_b.find("funcA1") < out_b.find("funcB1")
    assert good_a_funcA != good_b_funcA

    import random

    seen_good_funcA = set()
    for seed in range(50):
        out = neutralize(code, random.Random(seed))
        seen_good_funcA.add(out.find("funcA1") < out.find("funcB1"))
    assert seen_good_funcA == {True, False}


def test_neutralize_removes_leak_comments():
    code = "/* POTENTIAL FLAW */ public void bad() { } // FIX: something"
    out = neutralize(code, __import__("random").Random(0))
    assert "POTENTIAL FLAW" not in out
    assert "FIX:" not in out
