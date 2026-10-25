import json
import os
from pathlib import Path
import tempfile
import unittest

from input_limits import MAX_BYTES, json_document, read_text, toml_file


class InputLimits(unittest.TestCase):
    def test_json_rejects_deep_and_large_documents_before_parsing(self):
        for value in ['[' * 129 + '0' + ']' * 129, ' ' * (MAX_BYTES + 1)]:
            with self.assertRaises(ValueError):
                json_document(value)
        with self.assertRaises(ValueError):
            json_document('😀' * (MAX_BYTES // 4 + 1))
        value = {'text': '\\"[]{}' * 256}
        self.assertEqual(json_document(json.dumps(value)), value)

    def test_file_limits_and_nonregular_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            with path.open('wb') as stream:
                stream.truncate(MAX_BYTES + 1)
            with self.assertRaises(ValueError):
                read_text(path)
            with self.assertRaises(ValueError):
                read_text(directory)
            if hasattr(os, 'mkfifo'):
                fifo = Path(directory) / 'fifo'
                os.mkfifo(fifo)
                with self.assertRaises(ValueError):
                    read_text(fifo)
            path.write_text('{"ok": true}')
            self.assertEqual(json_document(read_text(path)), {'ok': True})

    def test_toml_limits_and_valid_package_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'Cargo.toml'
            for text in ['#' * (65536 + 1), '.'.join(['a'] * 129) + '=1',
                         'a=' + '[' * 129 + '1' + ']' * 129]:
                path.write_text(text)
                with self.assertRaises(ValueError):
                    toml_file(path)
            path.write_text('[package]\nversion="1.2.3"\n')
            self.assertEqual(toml_file(path)['package']['version'], '1.2.3')


if __name__ == '__main__':
    unittest.main()
