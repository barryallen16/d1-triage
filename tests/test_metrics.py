"""Tests for triage/metrics.py - hand-computed expectations."""
import numpy as np

from triage.metrics import ece, precision_at_recall, summarize


def test_precision_at_recall_basic():

    y = np.array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0])
    score = np.linspace(0.95, 0.05, 15)
    p, r = precision_at_recall(y, score, 0.9)
    assert p == 1.0
    assert r == 0.9


def test_precision_at_recall_mixed():
    y = np.array([1, 0, 1, 0, 1, 0, 1, 0, 1, 0])
    score = np.linspace(0.9, 0.1, 10)


    p, r = precision_at_recall(y, score, 0.9)
    assert p == 5 / 9
    assert r == 1.0


def test_precision_at_recall_unreachable():


    y = np.array([0, 0, 0, 1, 0])
    score = np.array([0.1, 0.2, 0.3, 0.9, 0.4])
    p, r = precision_at_recall(y, score, 0.9)

    assert p == 1.0
    assert r == 1.0


def test_precision_at_recall_groups_ties():

    y = np.array([1, 1, 0, 0])
    score = np.array([0.75, 0.75, 0.75, 0.75])
    p, r = precision_at_recall(y, score, 0.9)
    assert p == 0.5
    assert r == 1.0


def test_ece_perfect_calibration():

    y = np.array([0.0, 0.0, 1.0, 1.0])
    score = np.array([0.0, 0.0, 1.0, 1.0])
    assert ece(y, score, bins=2) == 0.0


def test_ece_poor_calibration():
    y = np.array([0.0, 0.0, 0.0, 0.0])
    score = np.array([0.9, 0.9, 0.9, 0.9])

    assert ece(y, score, bins=10) == 0.9


def test_summarize_basic():
    y = np.array([1, 1, 0, 0])
    score = np.array([0.9, 0.8, 0.3, 0.2])
    out = summarize(y, score, "m")
    assert out["precision"] == 1.0
    assert out["recall"] == 1.0
    assert out["f1"] == 1.0
    assert out["tp"] == 2
    assert out["fp"] == 0
    assert out["fn"] == 0


def test_summarize_all_negatives():
    y = np.array([0, 0, 0])
    score = np.array([0.1, 0.2, 0.3])
    out = summarize(y, score, "m")
    assert out["precision"] == 0.0
    assert out["recall"] == 0.0
    assert out["roc_auc"] != out["roc_auc"]
    assert "roc_auc" in out
