import pytest
import time

from ...core.in_memory import InMemoryProfile
from ...messaging.decorators.signature_decorator import SignatureDecorator
from ...wallet.in_memory import InMemoryWallet
from ...wallet.key_type import KeyType
from ...wallet.did_method import DIDMethod
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
    test_sov_did = "55GkHamhTU1ZbTbV2ab9DE"
    test_key_ed25519_did = "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
    test_key_bls12381g2_did = "did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa"
    test_ed25519_verkey = "3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx"
    test_bls12381g2_verkey = "nZZe9Nizhaz9JGpgjysaNkWGg5TNEhpib5j6WjTUHJ5K46dedUrZ57PUFZBq9Xckv8mFJjx6G6Vvj2rPspq22BagdADEEEy2F8AVLE1DhuwWC5vHFa4fUhUwxMkH7B6joqG"
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
    async def test_create_signing_key_ed25519_random(self, wallet: InMemoryWallet):
        assert str(wallet)
        info = await wallet.create_signing_key(KeyType.ED25519)
        assert info and info.verkey

    @pytest.mark.asyncio
    @pytest.mark.ursa_bbs_signatures
    async def test_create_signing_key_bls12381g2_random(self, wallet: InMemoryWallet):
        assert str(wallet)
        info = await wallet.create_signing_key(KeyType.BLS12381G2)
        assert info and info.verkey

    @pytest.mark.asyncio
    async def test_create_signing_key_ed25519_seeded(self, wallet: InMemoryWallet):
        info = await wallet.create_signing_key(KeyType.ED25519, self.test_seed)
        assert info.verkey == self.test_ed25519_verkey

        with pytest.raises(WalletDuplicateError):
            await wallet.create_signing_key(KeyType.ED25519, self.test_seed)

        with pytest.raises(WalletError):
            await wallet.create_signing_key(KeyType.ED25519, "invalid-seed", None)

    @pytest.mark.asyncio
    @pytest.mark.ursa_bbs_signatures
    async def test_create_signing_key_bls12381g2_seeded(self, wallet: InMemoryWallet):
        info = await wallet.create_signing_key(KeyType.BLS12381G2, self.test_seed)
        assert info.verkey == self.test_bls12381g2_verkey

        with pytest.raises(WalletDuplicateError):
            await wallet.create_signing_key(KeyType.BLS12381G2, self.test_seed)

        with pytest.raises(WalletError):
            await wallet.create_signing_key(KeyType.BLS12381G2, "invalid-seed", None)

    @pytest.mark.asyncio
    async def test_create_signing_key_unsupported_key_type(
        self, wallet: InMemoryWallet
    ):
        with pytest.raises(WalletError):
            await wallet.create_signing_key(KeyType.X25519)

        with pytest.raises(WalletError):
            await wallet.create_signing_key(KeyType.BLS12381G1)

        with pytest.raises(WalletError):
            await wallet.create_signing_key(KeyType.BLS12381G1G2)

    @pytest.mark.asyncio
    async def test_signing_key_metadata(self, wallet: InMemoryWallet):
        info = await wallet.create_signing_key(
            KeyType.ED25519, self.test_seed, self.test_metadata
        )
        assert info.metadata == self.test_metadata
        info2 = await wallet.get_signing_key(self.test_ed25519_verkey)
        assert info2.metadata == self.test_metadata
        await wallet.replace_signing_key_metadata(
            self.test_ed25519_verkey, self.test_update_metadata
        )
        info3 = await wallet.get_signing_key(self.test_ed25519_verkey)
        assert info3.metadata == self.test_update_metadata

        with pytest.raises(WalletNotFoundError):
            await wallet.replace_signing_key_metadata(
                self.missing_verkey, self.test_update_metadata
            )

        with pytest.raises(WalletNotFoundError):
            await wallet.get_signing_key(self.missing_verkey)

    @pytest.mark.asyncio
    @pytest.mark.ursa_bbs_signatures
    async def test_signing_key_metadata_bls(self, wallet: InMemoryWallet):
        info = await wallet.create_signing_key(
            KeyType.BLS12381G2, self.test_seed, self.test_metadata
        )
        assert info.metadata == self.test_metadata
        info2 = await wallet.get_signing_key(self.test_bls12381g2_verkey)
        assert info2.metadata == self.test_metadata
        await wallet.replace_signing_key_metadata(
            self.test_bls12381g2_verkey, self.test_update_metadata
        )
        info3 = await wallet.get_signing_key(self.test_bls12381g2_verkey)
        assert info3.metadata == self.test_update_metadata

    @pytest.mark.asyncio
    async def test_create_local_sov_random(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(DIDMethod.SOV, KeyType.ED25519, None, None)
        assert info and info.did and info.verkey

    @pytest.mark.asyncio
    async def test_create_local_key_random_ed25519(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(DIDMethod.KEY, KeyType.ED25519, None, None)
        assert info and info.did and info.verkey

    @pytest.mark.asyncio
    @pytest.mark.ursa_bbs_signatures
    async def test_create_local_key_random_bls12381g2(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(
            DIDMethod.KEY, KeyType.BLS12381G2, None, None
        )
        assert info and info.did and info.verkey

    @pytest.mark.asyncio
    async def test_create_local_incorrect_key_type_for_did_method(
        self, wallet: InMemoryWallet
    ):
        with pytest.raises(WalletError):
            await wallet.create_local_did(DIDMethod.SOV, KeyType.BLS12381G2, None, None)

    @pytest.mark.asyncio
    async def test_create_local_sov_seeded(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(
            DIDMethod.SOV, KeyType.ED25519, self.test_seed, None
        )
        assert info.did == self.test_sov_did
        assert info.verkey == self.test_ed25519_verkey

        # should not raise WalletDuplicateError - same verkey
        await wallet.create_local_did(
            DIDMethod.SOV, KeyType.ED25519, self.test_seed, None
        )

        with pytest.raises(WalletError):
            _ = await wallet.create_local_did(
                DIDMethod.SOV, KeyType.ED25519, "invalid-seed", None
            )

    @pytest.mark.asyncio
    @pytest.mark.ursa_bbs_signatures
    async def test_create_local_key_seeded_bls12381g2(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(
            DIDMethod.KEY, KeyType.BLS12381G2, self.test_seed, None
        )
        assert info.did == self.test_key_bls12381g2_did
        assert info.verkey == self.test_bls12381g2_verkey

        # should not raise WalletDuplicateError - same verkey
        await wallet.create_local_did(
            DIDMethod.KEY, KeyType.BLS12381G2, self.test_seed, None
        )

        with pytest.raises(WalletError):
            _ = await wallet.create_local_did(
                DIDMethod.KEY, KeyType.BLS12381G2, "invalid-seed", None
            )

    @pytest.mark.asyncio
    async def test_create_local_key_seeded_ed25519(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(
            DIDMethod.KEY, KeyType.ED25519, self.test_seed, None
        )
        assert info.did == self.test_key_ed25519_did
        assert info.verkey == self.test_ed25519_verkey

        # should not raise WalletDuplicateError - same verkey
        await wallet.create_local_did(
            DIDMethod.KEY, KeyType.ED25519, self.test_seed, None
        )

        with pytest.raises(WalletError):
            _ = await wallet.create_local_did(
                DIDMethod.KEY, KeyType.ED25519, "invalid-seed", None
            )

    @pytest.mark.asyncio
    async def test_rotate_did_keypair(self, wallet: InMemoryWallet):
        with pytest.raises(WalletNotFoundError):
            await wallet.rotate_did_keypair_start(self.test_sov_did)

        with pytest.raises(WalletNotFoundError):
            await wallet.rotate_did_keypair_apply(self.test_sov_did)

        info = await wallet.create_local_did(
            DIDMethod.SOV, KeyType.ED25519, self.test_seed, self.test_sov_did
        )
        key_info = await wallet.create_local_did(DIDMethod.KEY, KeyType.ED25519)

        with pytest.raises(WalletError):
            await wallet.rotate_did_keypair_apply(self.test_sov_did)

        with pytest.raises(WalletError) as context:
            await wallet.rotate_did_keypair_start(key_info.did)
        assert "DID method 'key' does not support key rotation" in str(context.value)

        new_verkey = await wallet.rotate_did_keypair_start(self.test_sov_did)
        assert info.verkey != new_verkey
        await wallet.rotate_did_keypair_apply(self.test_sov_did)

        new_info = await wallet.get_local_did(self.test_sov_did)
        assert new_info.did == self.test_sov_did
        assert new_info.verkey != info.verkey

    @pytest.mark.asyncio
    async def test_create_local_with_did(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(
            DIDMethod.SOV, KeyType.ED25519, None, self.test_sov_did
        )
        assert info.did == self.test_sov_did

        with pytest.raises(WalletDuplicateError):
            await wallet.create_local_did(
                DIDMethod.SOV, KeyType.ED25519, None, self.test_sov_did
            )

        with pytest.raises(WalletError) as context:
            await wallet.create_local_did(
                DIDMethod.KEY, KeyType.ED25519, None, "did:sov:random"
            )
        assert "Not allowed to set DID for DID method 'key'" in str(context.value)

    @pytest.mark.asyncio
    async def test_local_verkey(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(
            DIDMethod.SOV, KeyType.ED25519, self.test_seed, self.test_sov_did
        )
        assert info.did == self.test_sov_did
        assert info.verkey == self.test_ed25519_verkey

        info2 = await wallet.get_local_did(self.test_sov_did)
        assert info2.did == self.test_sov_did
        assert info2.verkey == self.test_ed25519_verkey

        info3 = await wallet.get_local_did_for_verkey(self.test_ed25519_verkey)
        assert info3.did == self.test_sov_did
        assert info3.verkey == self.test_ed25519_verkey

    @pytest.mark.asyncio
    @pytest.mark.ursa_bbs_signatures
    async def test_local_verkey_bls12381g2(self, wallet: InMemoryWallet):
        await wallet.create_local_did(DIDMethod.KEY, KeyType.BLS12381G2, self.test_seed)
        bls_info_get = await wallet.get_local_did_for_verkey(
            self.test_bls12381g2_verkey
        )
        assert bls_info_get.did == self.test_key_bls12381g2_did
        assert bls_info_get.verkey == self.test_bls12381g2_verkey

        with pytest.raises(WalletNotFoundError):
            _ = await wallet.get_local_did(self.missing_did)
        with pytest.raises(WalletNotFoundError):
            _ = await wallet.get_local_did_for_verkey(self.missing_verkey)

    @pytest.mark.asyncio
    async def test_local_metadata(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(
            DIDMethod.SOV,
            KeyType.ED25519,
            self.test_seed,
            self.test_sov_did,
            self.test_metadata,
        )
        assert info.did == self.test_sov_did
        assert info.verkey == self.test_ed25519_verkey
        assert info.metadata == self.test_metadata
        info2 = await wallet.get_local_did(self.test_sov_did)
        assert info2.metadata == self.test_metadata
        await wallet.replace_local_did_metadata(
            self.test_sov_did, self.test_update_metadata
        )
        info3 = await wallet.get_local_did(self.test_sov_did)
        assert info3.metadata == self.test_update_metadata

        with pytest.raises(WalletNotFoundError):
            await wallet.replace_local_did_metadata(
                self.missing_did, self.test_update_metadata
            )

        await wallet.set_did_endpoint(self.test_sov_did, "http://1.2.3.4:8021", None)
        info4 = await wallet.get_local_did(self.test_sov_did)
        assert info4.metadata["endpoint"] == "http://1.2.3.4:8021"

    @pytest.mark.asyncio
    @pytest.mark.ursa_bbs_signatures
    async def test_local_metadata_bbs(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(
            DIDMethod.KEY,
            KeyType.BLS12381G2,
            self.test_seed,
            None,
            self.test_metadata,
        )
        assert info.did == self.test_key_bls12381g2_did
        assert info.verkey == self.test_bls12381g2_verkey
        assert info.metadata == self.test_metadata
        info2 = await wallet.get_local_did(self.test_key_bls12381g2_did)
        assert info2.metadata == self.test_metadata
        await wallet.replace_local_did_metadata(
            self.test_key_bls12381g2_did, self.test_update_metadata
        )
        info3 = await wallet.get_local_did(self.test_key_bls12381g2_did)
        assert info3.metadata == self.test_update_metadata

    @pytest.mark.asyncio
    async def test_create_public_did(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(
            DIDMethod.SOV,
            KeyType.ED25519,
            self.test_seed,
            self.test_sov_did,
            self.test_metadata,
        )
        assert not info.metadata.get("public")
        assert not info.metadata.get("posted")

        posted = await wallet.get_posted_dids()
        assert not posted

        info_public = await wallet.create_public_did(
            DIDMethod.SOV,
            KeyType.ED25519,
        )
        assert info_public.metadata.get("public")
        assert info_public.metadata.get("posted")

        # test replace
        info_replace = await wallet.create_public_did(
            DIDMethod.SOV,
            KeyType.ED25519,
        )
        assert info_replace.metadata.get("public")
        assert info_replace.metadata.get("posted")
        info_check = await wallet.get_local_did(info_public.did)
        assert not info_check.metadata.get("public")
        assert info_check.metadata.get("posted")

        posted = await wallet.get_posted_dids()
        assert posted and posted[0].did == info_public.did

    @pytest.mark.asyncio
    async def test_create_public_did_x_not_sov(self, wallet: InMemoryWallet):
        with pytest.raises(WalletError) as context:
            await wallet.create_public_did(
                DIDMethod.KEY,
                KeyType.ED25519,
            )
        assert "Creating public DID is only allowed for did:sov DIDs" in str(
            context.value
        )

    @pytest.mark.asyncio
    async def test_create_public_did_x_unsupported_key_type_method(
        self, wallet: InMemoryWallet
    ):
        with pytest.raises(WalletError) as context:
            await wallet.create_public_did(
                DIDMethod.SOV,
                KeyType.BLS12381G2,
            )
        assert "Invalid key type" in str(context.value)

    @pytest.mark.asyncio
    async def test_set_public_did(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(
            DIDMethod.SOV,
            KeyType.ED25519,
            self.test_seed,
            self.test_sov_did,
            self.test_metadata,
        )
        assert not info.metadata.get("public")

        with pytest.raises(WalletNotFoundError):
            await wallet.set_public_did("55GkHamhTU1ZbTbV2ab9DF")

        # test assign
        info_same = await wallet.set_public_did(info.did)
        assert info_same.did == info.did
        assert info_same.metadata.get("public")

        info_new = await wallet.create_local_did(DIDMethod.SOV, KeyType.ED25519)
        assert info_new.did != info_same.did
        assert not info_new.metadata.get("public")

        loc = await wallet.get_local_did(self.test_sov_did)
        pub = await wallet.set_public_did(loc.did)
        assert pub.did == loc.did
        assert pub.metadata.get("public") == loc.metadata.get("public")

        # test replace
        info_final = await wallet.set_public_did(info_new.did)
        assert info_final.did == info_new.did
        assert info_final.metadata.get("public")

    @pytest.mark.asyncio
    async def test_set_public_did_x_not_sov(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(
            DIDMethod.KEY,
            KeyType.ED25519,
        )
        with pytest.raises(WalletError) as context:
            await wallet.set_public_did(info.did)
        assert "Setting public DID is only allowed for did:sov DIDs" in str(
            context.value
        )

    @pytest.mark.asyncio
    async def test_sign_verify(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(
            DIDMethod.SOV, KeyType.ED25519, self.test_seed, self.test_sov_did
        )
        message_bin = self.test_message.encode("ascii")
        signature = await wallet.sign_message(message_bin, info.verkey)
        assert signature == self.test_signature
        verify = await wallet.verify_message(
            message_bin, signature, info.verkey, KeyType.ED25519
        )
        assert verify

        bad_sig = b"x" + signature[1:]
        verify = await wallet.verify_message(
            message_bin, bad_sig, info.verkey, KeyType.ED25519
        )
        assert not verify
        bad_msg = b"x" + message_bin[1:]
        verify = await wallet.verify_message(
            bad_msg, signature, info.verkey, KeyType.ED25519
        )
        assert not verify
        verify = await wallet.verify_message(
            message_bin, signature, self.test_target_verkey, KeyType.ED25519
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
            await wallet.verify_message(message_bin, signature, None, KeyType.ED25519)
        assert "Verkey not provided" in str(excinfo.value)

        with pytest.raises(WalletError) as excinfo:
            await wallet.verify_message(message_bin, None, info.verkey, KeyType.ED25519)
        assert "Signature not provided" in str(excinfo.value)

        with pytest.raises(WalletError) as excinfo:
            await wallet.verify_message(None, message_bin, info.verkey, KeyType.ED25519)
        assert "Message not provided" in str(excinfo.value)

    @pytest.mark.asyncio
    @pytest.mark.ursa_bbs_signatures
    async def test_sign_verify_bbs(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(
            DIDMethod.KEY, KeyType.BLS12381G2, self.test_seed
        )
        message_bin = self.test_message.encode("ascii")
        signature = await wallet.sign_message(message_bin, info.verkey)
        assert signature
        verify = await wallet.verify_message(
            message_bin, signature, info.verkey, KeyType.BLS12381G2
        )
        assert verify

        bad_msg = b"x" + message_bin[1:]
        verify = await wallet.verify_message(
            bad_msg, signature, info.verkey, KeyType.BLS12381G2
        )
        assert not verify

        with pytest.raises(WalletError):
            bad_sig = b"x" + signature[1:]
            verify = await wallet.verify_message(
                message_bin, bad_sig, info.verkey, KeyType.BLS12381G2
            )

        with pytest.raises(WalletError):
            await wallet.verify_message(
                message_bin, signature, self.test_target_verkey, KeyType.BLS12381G2
            )

        with pytest.raises(WalletError):
            await wallet.sign_message(message_bin, self.missing_verkey)

        with pytest.raises(WalletError) as excinfo:
            await wallet.sign_message(None, self.missing_verkey)
        assert "Message not provided" in str(excinfo.value)

        with pytest.raises(WalletError) as excinfo:
            await wallet.sign_message(message_bin, None)
        assert "Verkey not provided" in str(excinfo.value)

        with pytest.raises(WalletError) as excinfo:
            await wallet.verify_message(
                message_bin, signature, None, KeyType.BLS12381G2
            )
        assert "Verkey not provided" in str(excinfo.value)

        with pytest.raises(WalletError) as excinfo:
            await wallet.verify_message(
                message_bin, None, info.verkey, KeyType.BLS12381G2
            )
        assert "Signature not provided" in str(excinfo.value)

        with pytest.raises(WalletError) as excinfo:
            await wallet.verify_message(
                None, message_bin, info.verkey, KeyType.BLS12381G2
            )
        assert "Message not provided" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_pack_unpack(self, wallet: InMemoryWallet):
        await wallet.create_local_did(
            DIDMethod.SOV, KeyType.ED25519, self.test_seed, self.test_sov_did
        )

        packed_anon = await wallet.pack_message(
            self.test_message, [self.test_ed25519_verkey]
        )
        unpacked_anon, from_verkey, to_verkey = await wallet.unpack_message(packed_anon)
        assert unpacked_anon == self.test_message
        assert from_verkey is None
        assert to_verkey == self.test_ed25519_verkey

        with pytest.raises(WalletError) as excinfo:
            await wallet.pack_message(None, [])
        assert "Message not provided" in str(excinfo.value)

        await wallet.create_local_did(
            DIDMethod.SOV, KeyType.ED25519, self.test_target_seed, self.test_target_did
        )
        packed_auth = await wallet.pack_message(
            self.test_message, [self.test_target_verkey], self.test_ed25519_verkey
        )
        unpacked_auth, from_verkey, to_verkey = await wallet.unpack_message(packed_auth)
        assert unpacked_auth == self.test_message
        assert from_verkey == self.test_ed25519_verkey
        assert to_verkey == self.test_target_verkey

        with pytest.raises(WalletError):
            unpacked_auth, from_verkey, to_verkey = await wallet.unpack_message(b"bad")
        with pytest.raises(WalletError):
            unpacked_auth, from_verkey, to_verkey = await wallet.unpack_message(b"{}")
        with pytest.raises(WalletError):
            await wallet.unpack_message(None)

    @pytest.mark.asyncio
    async def test_signature_round_trip(self, wallet: InMemoryWallet):
        key_info = await wallet.create_signing_key(KeyType.ED25519)
        msg = {"test": "signed field"}
        timestamp = int(time.time())
        sig = await SignatureDecorator.create(msg, key_info.verkey, wallet, timestamp)
        verified = await sig.verify(wallet)
        assert verified
        msg_decode, ts_decode = sig.decode()
        assert msg_decode == msg
        assert ts_decode == timestamp

    @pytest.mark.asyncio
    async def test_set_did_endpoint_x_not_sov(self, wallet: InMemoryWallet):
        info = await wallet.create_local_did(
            DIDMethod.KEY,
            KeyType.ED25519,
        )
        with pytest.raises(WalletError) as context:
            await wallet.set_did_endpoint(
                info.did,
                "https://google.com",
                {},
            )
        assert "Setting DID endpoint is only allowed for did:sov DIDs" in str(
            context.value
        )
