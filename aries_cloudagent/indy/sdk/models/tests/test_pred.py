from unittest import TestCase

from ..predicate import Predicate


class TestPredicate(TestCase):
    """Predicate tests for coverage"""

    def test_get_monikers(self):
        """Get predicate."""
        assert Predicate.get("LT") == Predicate.get("$lt") == Predicate.get("<")
        assert Predicate.get("LE") == Predicate.get("$lte") == Predicate.get("<=")
        assert Predicate.get("GE") == Predicate.get("$gte") == Predicate.get(">=")
        assert Predicate.get("GT") == Predicate.get("$gt") == Predicate.get(">")
        assert Predicate.get("!=") is None

        assert Predicate.get("LT").fortran == "LT"
        assert Predicate.get("LT").wql == "$lt"
        assert Predicate.get("LT").math == "<"

    def test_cmp(self):
        """Test comparison via predicates"""
        assert Predicate.get("LT").value.yes(0, 1)
        assert Predicate.get("LT").value.yes("0", "1")
        assert Predicate.get("LT").value.no(0, 0)
        assert Predicate.get("LT").value.no(1, 0)
        assert Predicate.get("LT").value.no("1", "0")
        assert Predicate.get("LT").value.no("0", "0")

        assert Predicate.get("LE").value.yes(0, 1)
        assert Predicate.get("LE").value.yes("0", "1")
        assert Predicate.get("LE").value.yes(0, 0)
        assert Predicate.get("LE").value.no(1, 0)
        assert Predicate.get("LE").value.no("1", "0")
        assert Predicate.get("LE").value.yes("0", "0")

        assert Predicate.get("GE").value.no(0, 1)
        assert Predicate.get("GE").value.no("0", "1")
        assert Predicate.get("GE").value.yes(0, 0)
        assert Predicate.get("GE").value.yes(1, 0)
        assert Predicate.get("GE").value.yes("1", "0")
        assert Predicate.get("GE").value.yes("0", "0")

        assert Predicate.get("GT").value.no(0, 1)
        assert Predicate.get("GT").value.no("0", "1")
        assert Predicate.get("GT").value.no(0, 0)
        assert Predicate.get("GT").value.yes(1, 0)
        assert Predicate.get("GT").value.yes("1", "0")
        assert Predicate.get("GT").value.no("0", "0")
