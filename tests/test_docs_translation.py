"""Ensure full-translation checks detect structural and executable omissions."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('check_docs', Path(__file__).resolve().parents[1] / 'tools/check_docs.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TranslationChecks(unittest.TestCase):
    def test_translated_prose_preserves_contract(self):
        english = '# Guide\n\nText.\n\n## Setup\n\n```sh\nhangang --check\n```\n'
        korean = '# 안내\n\n설명입니다.\n\n## 설정\n\n```sh\nhangang --check\n```\n'
        self.assertEqual(module.translation_structure(english), module.translation_structure(korean))
        self.assertNotEqual(module.translation_structure(english), module.translation_structure(korean.replace('## 설정\n', '')))
        self.assertNotEqual(module.translation_structure(english), module.translation_structure(korean.replace('--check', '--about')))

    def test_table_omission_and_fake_headings_in_code(self):
        text = '# Guide\n\n| A | B |\n|---|---|\n| x | y |\n\n```sh\n# shell comment\n```\n'
        signature = module.translation_structure(text)
        self.assertEqual(signature[0], [1])
        self.assertEqual(signature[2], [3])
        self.assertNotEqual(signature, module.translation_structure(text.replace('| x | y |\n', '')))


if __name__ == '__main__':
    unittest.main()
