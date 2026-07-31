"""Tests for the IPv8 message payloads (the on-the-wire envelope layer).

These guard a specific regression: IPv8's ``DataClassPayload`` builds its
serialization ``format_list`` lazily, the first time a message is *constructed*.
A process that only ever *receives* a given message therefore used to unpack it
with an empty format and raise ``TypeError: __init__() missing 1 required
positional argument`` (famously the ``marker`` of a fork-sync request a node
answers but never sends). :mod:`network.community` finalizes every payload's
format at import time to prevent that, and these tests pin the behaviour.

They exercise the real IPv8 serializer directly (pack -> unpack), which is the
same code path ``ez_send`` / ``@lazy_wrapper`` drive on a live network.
"""

import unittest

from ipv8.messaging.serialization import default_serializer

from network.community import (
    BlockMessage,
    ChainRequestMessage,
    ChainResponseMessage,
    TransactionMessage,
)

ALL_MESSAGES = (
    TransactionMessage,
    BlockMessage,
    ChainRequestMessage,
    ChainResponseMessage,
)


class MessagePayloadFormatTests(unittest.TestCase):
    def test_format_is_finalized_at_import(self):
        """Every payload's IPv8 format is populated by import alone.

        This is the crux of the fix: no message may depend on having been
        *constructed* (i.e. sent) before it can be deserialized, or a
        receive-only node cannot decode it. Merely importing the module must
        leave a non-empty ``format_list``/``names`` on each class.
        """
        for cls in ALL_MESSAGES:
            with self.subTest(message=cls.__name__):
                self.assertTrue(cls.format_list, f"{cls.__name__} has empty format_list")
                self.assertTrue(cls.names, f"{cls.__name__} has empty names")


class MessagePayloadRoundTripTests(unittest.TestCase):
    def test_block_message_round_trips_through_serializer(self):
        """A BlockMessage survives pack -> unpack with its wire payload intact."""
        wire = '{"index":1,"transactions":[],"hash":"abc"}'
        packed = default_serializer.pack_serializable(BlockMessage(wire))
        restored, _ = default_serializer.unpack_serializable(BlockMessage, packed)
        self.assertEqual(restored.wire, wire)

    def test_chain_request_marker_round_trips(self):
        """The fork-sync request (the ``marker`` regression) round-trips.

        Reproduces the receive-only path exactly: the payload is unpacked from
        raw bytes without this class ever having been constructed first.
        """
        packed = default_serializer.pack_serializable(ChainRequestMessage("sync"))
        restored, _ = default_serializer.unpack_serializable(ChainRequestMessage, packed)
        self.assertEqual(restored.marker, "sync")

    def test_all_messages_round_trip(self):
        """Every message type survives a full pack -> unpack cycle."""
        cases = [
            (TransactionMessage, "wire", "tx-json"),
            (BlockMessage, "wire", "block-json"),
            (ChainRequestMessage, "marker", "sync"),
            (ChainResponseMessage, "wire", "chain-json"),
        ]
        for cls, field, value in cases:
            with self.subTest(message=cls.__name__):
                packed = default_serializer.pack_serializable(cls(value))
                restored, _ = default_serializer.unpack_serializable(cls, packed)
                self.assertEqual(getattr(restored, field), value)


if __name__ == "__main__":
    unittest.main()
