import unittest
from stegokit import StegoKit
from unittest.mock import patch

class TestStegoKit(unittest.TestCase):
    def setUp(self):
        self.stego = StegoKit()

    @patch('stegokit.Image')
    def test_steg_hide_image(self, mock_image):
        # Test hiding a message in an image
        self.stego.steg_hide('input.png', 'secret', 'output.png')
        # ... assertions ...

    @patch('stegokit.Image')
    def test_steg_reveal_image(self, mock_image):
        # Test revealing a message from an image
        mock_image.open.return_value = mock_image
        result = self.stego.steg_reveal('input.png')
        # ... assertions ...

    @patch('stegokit.wave')
    def test_audio_steg_hide(self, mock_wave):
        # Test hiding a message in audio
        self.stego.audio_steg_hide('input.wav', 'secret', 'output.wav')
        # ... assertions ...

    @patch('stegokit.wave')
    def test_audio_steg_reveal(self, mock_wave):
        # Test revealing a message from audio
        result = self.stego.audio_steg_reveal('input.wav')
        # ... assertions ...

    @patch('stegokit.cv2')
    def test_video_steg_hide(self, mock_cv2):
        # Test hiding a message in video
        self.stego.video_steg_hide('input.mp4', 'secret', 'output.mp4')
        # ... assertions ...

    @patch('stegokit.cv2')
    def test_video_steg_reveal(self, mock_cv2):
        # Test revealing a message from video
        result = self.stego.video_steg_reveal('input.mp4')
        # ... assertions ...

if __name__ == '__main__':
    unittest.main() 