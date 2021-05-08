from unittest import TestCase

from asynctest import TestCase as AsyncTestCase
from asynctest import mock as async_mock

import pytest

from ..non_rev_interval import IndyNonRevocationInterval

FROM = 1000000000
TO = 1234567890

INTERVAL_FROM = IndyNonRevocationInterval(fro=FROM)
INTERVAL_TO = IndyNonRevocationInterval(to=TO)
INTERVAL = IndyNonRevocationInterval(fro=FROM, to=TO)


class TestInterval(TestCase):
    """Non-revocation interval tests"""

    def test_serde(self):
        """Test serialization and deserialization."""
        for interval in (INTERVAL_FROM, INTERVAL_TO, INTERVAL):
            non_revo_dict = interval.serialize()
            assert non_revo_dict.get("from") == interval.fro
            assert non_revo_dict.get("to") == interval.to

            model = IndyNonRevocationInterval.deserialize(non_revo_dict)
            assert model.fro == interval.fro and model.to == interval.to
            assert model.timestamp()

    def test_covers(self):
        """Test spanning check."""
        assert INTERVAL_FROM.covers(FROM)
        assert INTERVAL_FROM.covers(TO)
        assert INTERVAL_FROM.covers()

        assert INTERVAL_TO.covers(FROM)
        assert INTERVAL_TO.covers(TO)
        assert not INTERVAL_TO.covers()

        assert INTERVAL.covers(FROM)
        assert INTERVAL.covers(TO)
        assert not INTERVAL.covers()
