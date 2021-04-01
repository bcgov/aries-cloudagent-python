from os import environ

from asynctest import TestCase as AsyncTestCase

from ..didcomm_prefix import DIDCommPrefix


class TestDIDCommPrefix(AsyncTestCase):
    def test_didcomm_prefix(self):
        DIDCommPrefix.set({})
        assert environ.get("DIDCOMM_PREFIX") == DIDCommPrefix.OLD.value

        DIDCommPrefix.set({"aip_version": 2})
        assert environ.get("DIDCOMM_PREFIX") == DIDCommPrefix.NEW.value
        assert DIDCommPrefix.qualify_current("hello") == (
            f"{DIDCommPrefix.NEW.value}/hello"
        )

        DIDCommPrefix.set({"aip_version": 1})
        assert environ.get("DIDCOMM_PREFIX") == DIDCommPrefix.OLD.value
        assert DIDCommPrefix.qualify_current("hello") == (
            f"{DIDCommPrefix.OLD.value}/hello"
        )

        old_q_hello = DIDCommPrefix.OLD.qualify("hello")
        new_q_hello = DIDCommPrefix.NEW.qualify("hello")
        assert old_q_hello == f"{DIDCommPrefix.OLD.value}/hello"
        assert new_q_hello == f"{DIDCommPrefix.NEW.value}/hello"

        assert DIDCommPrefix.unqualify(old_q_hello) == "hello"
        assert DIDCommPrefix.unqualify(new_q_hello) == "hello"
        assert DIDCommPrefix.unqualify("already unqualified") == "already unqualified"
        assert DIDCommPrefix.unqualify(None) is None

        qualified = "http://custom-prefix/message/type/1.0"
        assert DIDCommPrefix.qualify_current(qualified) == qualified
        assert DIDCommPrefix.NEW.qualify(qualified) == qualified
        assert DIDCommPrefix.unqualify(qualified) == qualified

    def test_didcomm_qualify_all(self):
        mtype = "a/message/1.0"
        mcls = "protocol.Cls"
        messages = {mtype: mcls}
        assert DIDCommPrefix.qualify_all(messages) == {
            DIDCommPrefix.NEW.qualify(mtype): mcls,
            DIDCommPrefix.OLD.qualify(mtype): mcls,
        }
