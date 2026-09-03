"""
Unit tests for Crypta Feature 3 — Bitwise LSB Operations & Image Pixel Embedding.
"""

import unittest
from PIL import Image
from crypta.steganography.lsb import (
    bytes_to_bits,
    bits_to_bytes,
    embed_bits_in_image,
    extract_bits_from_image,
)


class TestLSBOperations(unittest.TestCase):
    """Test suite for MSB-first bit order, LSB spatial embedding, and Alpha preservation."""

    def test_msb_first_bit_conversions(self):
        """Test byte to bit and bit to byte conversions using MSB-first ordering."""
        original_bytes = b"\xA5\x5A\x00\xFF\x12\x34"
        bits = bytes_to_bits(original_bytes)

        # 0xA5 is 10100101
        self.assertEqual(bits[:8], [1, 0, 1, 0, 0, 1, 0, 1])

        reconstructed_bytes = bits_to_bytes(bits)
        self.assertEqual(reconstructed_bytes, original_bytes)

    def test_rgb_lsb_embedding_and_extraction(self):
        """Test LSB embedding and extraction in RGB PNG image."""
        img = Image.new("RGB", (10, 10), color=(128, 128, 128))
        test_bytes = b"Hello, LSB!"
        bits = bytes_to_bits(test_bytes)

        stego_img = embed_bits_in_image(img, bits)
        extracted_bits = extract_bits_from_image(stego_img, max_bits=len(bits))
        extracted_bytes = bits_to_bytes(extracted_bits)

        self.assertEqual(extracted_bytes, test_bytes)

    def test_rgba_alpha_channel_preservation(self):
        """Test Alpha channel is strictly preserved in RGBA image."""
        img = Image.new("RGBA", (10, 10), color=(100, 150, 200, 77))
        original_pixels = list(img.getdata())

        test_bytes = b"ALPHA_TEST_DATA_BYTES"
        bits = bytes_to_bits(test_bytes)

        stego_img = embed_bits_in_image(img, bits)
        stego_pixels = list(stego_img.getdata())

        for orig_px, stego_px in zip(original_pixels, stego_pixels):
            # Alpha channel (index 3) must be 100% identical
            self.assertEqual(orig_px[3], stego_px[3])
            self.assertEqual(stego_px[3], 77)

            # R, G, B channels must differ by at most 1 (LSB change only)
            self.assertLessEqual(abs(orig_px[0] - stego_px[0]), 1)
            self.assertLessEqual(abs(orig_px[1] - stego_px[1]), 1)
            self.assertLessEqual(abs(orig_px[2] - stego_px[2]), 1)

    def test_original_image_unmodified(self):
        """Test embed_bits_in_image returns new Image copy without mutating original."""
        img = Image.new("RGB", (10, 10), color=(200, 200, 200))
        orig_pixels = list(img.getdata())

        bits = bytes_to_bits(b"TEST_MUTATION")
        stego_img = embed_bits_in_image(img, bits)

        # Original image pixels must be unchanged
        self.assertEqual(list(img.getdata()), orig_pixels)
        self.assertNotEqual(list(stego_img.getdata()), orig_pixels)


if __name__ == "__main__":
    unittest.main()
