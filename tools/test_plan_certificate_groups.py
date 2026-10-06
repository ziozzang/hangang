import unittest
from plan_certificate_groups import group_domains


class CertificateGroups(unittest.TestCase):
    def test_www_and_wildcard_share_base_without_merging_other_services(self):
        groups = group_domains(['foo.com', 'www.foo.com', '*.foo.com', 'api.foo.com', 'other.com'])
        self.assertEqual([g['domains'] for g in groups], [['foo.com', 'www.foo.com', '*.foo.com'], ['api.foo.com'], ['other.com']])
        self.assertEqual([g['requires_dns01'] for g in groups], [True, False, False])

    def test_live_jioh_names_partition_into_four_groups(self):
        groups = group_domains(['dev.jioh.net', '*.dev.jioh.net', 'dify.jioh.net', 'llm-api.jioh.net', 'local.jioh.net', '*.local.jioh.net'])
        self.assertEqual(len(groups), 4)
        self.assertEqual([g['domain'] for g in groups], ['dev.jioh.net', 'dify.jioh.net', 'llm-api.jioh.net', 'local.jioh.net'])

    def test_tanzania_www_is_one_group_and_no_unrequested_name_is_added(self):
        self.assertEqual(group_domains(['aiotanzania.org', 'www.aiotanzania.org'])[0]['domains'], ['aiotanzania.org', 'www.aiotanzania.org'])
        self.assertEqual(group_domains(['api.foo.com'])[0]['domains'], ['api.foo.com'])

    def test_bad_names_and_canonical_duplicates_are_rejected(self):
        for domains in [[], ['foo.com', 'FOO.COM.'], ['foo.*.com'], ['foo..com'], [' foo.com'], ['https://foo.com'], ['localhost'], ['foo.com:443'], ['127.0.0.1']]:
            with self.subTest(domains=domains), self.assertRaises(ValueError):
                group_domains(domains)
