import pytest
import time

from ...core.in_memory import InMemoryProfile
from ...messaging.decorators.signature_decorator import SignatureDecorator
from ...wallet.in_memory import InMemoryWallet
from ...wallet.error import (
    WalletError,
    WalletDuplicateError,
    WalletNotFoundError,
)


@pytest.fixture()
async def wallet():
    profile = InMemoryProfile.test_profile()
    wallet = InMemoryWallet(profile)
    yield wallet


class TestInMemoryWallet:
    test_seed = "testseed000000000000000000000001"
    test_did = "55GkHamhTU1ZbTbV2ab9DE"
    test_verkey = "3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx"
    test_target_seed = "testseed000000000000000000000002"
    test_target_did = "GbuDUYXaUZRfHD2jeDuQuP"
    test_target_verkey = "9WCgWKUaAJj3VWxxtzvvMQN3AoFxoBtBDo9ntwJnVVCC"
    test_metadata = {"meta": True}
    test_update_metadata = {"meta": False}
    test_message = "test message"
    test_message_bytes = b"test message bytes"
    missing_did = "YVnYBGTdjZUoQXKQjHV87i"
    missing_verkey = "JAfHCRDH9ZW5E7m4mofjr8cpAHaZdiRQ94it75aXUPK3"
    test_signature = (
        b"\xd6\x98\x04\x88\xd2-\xc1D\x02\x15\xc9Z\x9bK \x8f\xe0\x8b5\xd0Z$"
        b"\xe3\x02\x19\xa1\xb3\x86\xfa2\x07\xc8\xbd3-\x1c\xc4\x8d\x8e\xa3\x9be"
        b"\xea\xcf\x8bc\xfa_\x0c\xb2jE\xe4}\x12+\xbc0\x01l\xdb\x97\xf6\x02"
    )

    @pytest.mark.asyncio
    async def test_create_signing_key_random(self, wallet):
        assert str(wallet)
        info = await wallet.create_signing_key()
        assert info and info.verkey

    @pytest.mark.asyncio
    async def test_create_signing_key_seeded(self, wallet):
        info = await wallet.create_signing_key(self.test_seed)
        assert info.verkey == self.test_verkey

        with pytest.raises(WalletDuplicateError):
            await wallet.create_signing_key(self.test_seed)

        with pytest.raises(WalletError):
            await wallet.create_signing_key("invalid-seed", None)

    @pytest.mark.asyncio
    async def test_signing_key_metadata(self, wallet):
        info = await wallet.create_signing_key(self.test_seed, self.test_metadata)
        assert info.metadata == self.test_metadata
        info2 = await wallet.get_signing_key(self.test_verkey)
        assert info2.metadata == self.test_metadata
        await wallet.replace_signing_key_metadata(
            self.test_verkey, self.test_update_metadata
        )
        info3 = await wallet.get_signing_key(self.test_verkey)
        assert info3.metadata == self.test_update_metadata

        with pytest.raises(WalletNotFoundError):
            await wallet.replace_signing_key_metadata(
                self.missing_verkey, self.test_update_metadata
            )

        with pytest.raises(WalletNotFoundError):
            await wallet.get_signing_key(self.missing_verkey)

    @pytest.mark.asyncio
    async def test_create_local_random(self, wallet):
        info = await wallet.create_local_did(None, None)
        assert info and info.did and info.verkey

    @pytest.mark.asyncio
    async def test_create_local_seeded(self, wallet):
        info = await wallet.create_local_did(self.test_seed, None)
        assert info.did == self.test_did
        assert info.verkey == self.test_verkey

        # should not raise WalletDuplicateError - same verkey
        await wallet.create_local_did(self.test_seed, None)

        with pytest.raises(WalletError):
            _ = await wallet.create_local_did("invalid-seed", None)

    @pytest.mark.asyncio
    async def test_rotate_did_keypair(self, wallet):
        with pytest.raises(WalletNotFoundError):
            await wallet.rotate_did_keypair_start(self.test_did)

        with pytest.raises(WalletNotFoundError):
            await wallet.rotate_did_keypair_apply(self.test_did)

        info = await wallet.create_local_did(self.test_seed, self.test_did)

        with pytest.raises(WalletError):
            await wallet.rotate_did_keypair_apply(self.test_did)

        new_verkey = await wallet.rotate_did_keypair_start(self.test_did)
        assert info.verkey != new_verkey
        await wallet.rotate_did_keypair_apply(self.test_did)

        new_info = await wallet.get_local_did(self.test_did)
        assert new_info.did == self.test_did
        assert new_info.verkey != info.verkey

    @pytest.mark.asyncio
    async def test_create_local_with_did(self, wallet):
        info = await wallet.create_local_did(None, self.test_did)
        assert info.did == self.test_did

        with pytest.raises(WalletDuplicateError):
            await wallet.create_local_did(None, self.test_did)

    @pytest.mark.asyncio
    async def test_local_verkey(self, wallet):
        info = await wallet.create_local_did(self.test_seed, self.test_did)
        assert info.did == self.test_did
        assert info.verkey == self.test_verkey

        info2 = await wallet.get_local_did(self.test_did)
        assert info2.did == self.test_did
        assert info2.verkey == self.test_verkey

        info3 = await wallet.get_local_did_for_verkey(self.test_verkey)
        assert info3.did == self.test_did
        assert info3.verkey == self.test_verkey

        with pytest.raises(WalletNotFoundError):
            _ = await wallet.get_local_did(self.missing_did)
        with pytest.raises(WalletNotFoundError):
            _ = await wallet.get_local_did_for_verkey(self.missing_verkey)

    @pytest.mark.asyncio
    async def test_local_metadata(self, wallet):
        info = await wallet.create_local_did(
            self.test_seed, self.test_did, None, self.test_metadata
        )
        assert info.did == self.test_did
        assert info.verkey == self.test_verkey
        assert info.metadata == self.test_metadata
        info2 = await wallet.get_local_did(self.test_did)
        assert info2.metadata == self.test_metadata
        await wallet.replace_local_did_metadata(
            self.test_did, self.test_update_metadata
        )
        info3 = await wallet.get_local_did(self.test_did)
        assert info3.metadata == self.test_update_metadata

        with pytest.raises(WalletNotFoundError):
            await wallet.replace_local_did_metadata(
                self.missing_did, self.test_update_metadata
            )

        await wallet.set_did_endpoint(self.test_did, "http://1.2.3.4:8021", None)
        info4 = await wallet.get_local_did(self.test_did)
        assert info4.metadata["endpoint"] == "http://1.2.3.4:8021"

    @pytest.mark.asyncio
    async def test_create_public_did(self, wallet):
        info = await wallet.create_local_did(
            self.test_seed, self.test_did, None, self.test_metadata
        )
        assert not info.metadata.get("public")
        assert not info.metadata.get("posted")

        posted = await wallet.get_posted_dids()
        assert not posted

        info_public = await wallet.create_public_did()
        assert info_public.metadata.get("public")
        assert info_public.metadata.get("posted")

        # test replace
        info_replace = await wallet.create_public_did()
        assert info_replace.metadata.get("public")
        assert info_replace.metadata.get("posted")
        info_check = await wallet.get_local_did(info_public.did)
        assert not info_check.metadata.get("public")
        assert info_check.metadata.get("posted")

        posted = await wallet.get_posted_dids()
        assert posted and posted[0].did == info_public.did

    @pytest.mark.asyncio
    async def test_set_public_did(self, wallet):
        info = await wallet.create_local_did(
            self.test_seed, self.test_did, None, self.test_metadata
        )
        assert not info.metadata.get("public")

        with pytest.raises(WalletNotFoundError):
            await wallet.set_public_did("55GkHamhTU1ZbTbV2ab9DF")

        # test assign
        info_same = await wallet.set_public_did(info.did)
        assert info_same.did == info.did
        assert info_same.metadata.get("public")

        info_new = await wallet.create_local_did()
        assert info_new.did != info_same.did
        assert not info_new.metadata.get("public")

        loc = await wallet.get_local_did(self.test_did)
        pub = await wallet.set_public_did(loc.did)
        assert pub.did == loc.did
        assert pub.metadata.get("public") == loc.metadata.get("public")

        # test replace
        info_final = await wallet.set_public_did(info_new.did)
        assert info_final.did == info_new.did
        assert info_final.metadata.get("public")

    @pytest.mark.asyncio
    async def test_sign_verify(self, wallet):
        info = await wallet.create_local_did(self.test_seed, self.test_did)
        message_bin = self.test_message.encode("ascii")
        signature = await wallet.sign_message(message_bin, info.verkey)
        assert signature == self.test_signature
        verify = await wallet.verify_message(message_bin, signature, info.verkey)
        assert verify

        bad_sig = b"x" + signature[1:]
        verify = await wallet.verify_message(message_bin, bad_sig, info.verkey)
        assert not verify
        bad_msg = b"x" + message_bin[1:]
        verify = await wallet.verify_message(bad_msg, signature, info.verkey)
        assert not verify
        verify = await wallet.verify_message(
            message_bin, signature, self.test_target_verkey
        )
        assert not verify

        with pytest.raises(WalletError):
            await wallet.sign_message(message_bin, self.missing_verkey)

        with pytest.raises(WalletError) as excinfo:
            await wallet.sign_message(None, self.missing_verkey)
        assert "Message not provided" in str(excinfo.value)

        with pytest.raises(WalletError) as excinfo:
            await wallet.sign_message(message_bin, None)
        assert "Verkey not provided" in str(excinfo.value)

        with pytest.raises(WalletError) as excinfo:
            await wallet.verify_message(message_bin, signature, None)
        assert "Verkey not provided" in str(excinfo.value)

        with pytest.raises(WalletError) as excinfo:
            await wallet.verify_message(message_bin, None, info.verkey)
        assert "Signature not provided" in str(excinfo.value)

        with pytest.raises(WalletError) as excinfo:
            await wallet.verify_message(None, message_bin, info.verkey)
        assert "Message not provided" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_pack_unpack(self, wallet):
        await wallet.create_local_did(self.test_seed, self.test_did)

        packed_anon = await wallet.pack_message(self.test_message, [self.test_verkey])
        unpacked_anon, from_verkey, to_verkey = await wallet.unpack_message(packed_anon)
        assert unpacked_anon == self.test_message
        assert from_verkey is None
        assert to_verkey == self.test_verkey

        with pytest.raises(WalletError) as excinfo:
            await wallet.pack_message(None, [])
        assert "Message not provided" in str(excinfo.value)

        await wallet.create_local_did(self.test_target_seed, self.test_target_did)
        packed_auth = await wallet.pack_message(
            self.test_message, [self.test_target_verkey], self.test_verkey
        )
        unpacked_auth, from_verkey, to_verkey = await wallet.unpack_message(packed_auth)
        assert unpacked_auth == self.test_message
        assert from_verkey == self.test_verkey
        assert to_verkey == self.test_target_verkey

        with pytest.raises(WalletError):
            unpacked_auth, from_verkey, to_verkey = await wallet.unpack_message(b"bad")
        with pytest.raises(WalletError):
            unpacked_auth, from_verkey, to_verkey = await wallet.unpack_message(b"{}")
        with pytest.raises(WalletError):
            await wallet.unpack_message(None)

    @pytest.mark.asyncio
    async def test_signature_round_trip(self, wallet):
        key_info = await wallet.create_signing_key()
        msg = {"test": "signed field"}
        timestamp = int(time.time())
        sig = await SignatureDecorator.create(msg, key_info.verkey, wallet, timestamp)
        verified = await sig.verify(wallet)
        assert verified
        msg_decode, ts_decode = sig.decode()
        assert msg_decode == msg
        assert ts_decode == timestamp
