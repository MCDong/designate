"""
Copyright 2015 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from functionaltests.api.v2.security_utils import FuzzFactory
from functionaltests.common import utils
from functionaltests.common import datagen

from functionaltests.api.v2.base import DesignateV2Test
from functionaltests.api.v2.clients.blacklist_client import BlacklistClient
# from functionaltests.api.v2.clients.zone_client import ZoneClient
from six import string_types
from six.moves.urllib.parse import quote_plus

fuzzer = FuzzFactory()


@utils.parameterized_class
class BlacklistFuzzTest(DesignateV2Test):
    def setUp(self):
        super(BlacklistFuzzTest, self).setUp()
        self.increase_quotas(user='admin')
        self.client = BlacklistClient.as_user('admin')

    def _create_blacklist(self, blacklist_model, user='admin'):
        resp, model = BlacklistClient.as_user(user).post_blacklist(
            blacklist_model)
        self.assertEqual(resp.status, 201)
        return resp, model

    header_params = ['accept', 'content-type']

    @utils.parameterized(fuzzer.get_param_datasets(
        header_params, ['content_types', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_fuzzed_blacklist_header(self, parameter, fuzz_type, payload):
        model = datagen.random_blacklist_data()
        headers = {
            'content-type': 'application/json',
            'accept': ''
        }
        headers[parameter] = payload.encode('utf-8')
        result = fuzzer.verify_tempest_exception(
            self.client.post_blacklist, fuzz_type, model, headers=headers)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    blacklist_params = [
        'pattern', 'description', 'created_at', 'updated_at', 'id', 'links'
    ]

    @utils.parameterized(fuzzer.get_param_datasets(
        blacklist_params, ['huge', 'date', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_blacklist_fuzzed(self, parameter, fuzz_type, payload):
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        model = datagen.random_blacklist_data()
        model.__dict__[parameter] = payload
        result = fuzzer.verify_tempest_exception(
            self.client.post_blacklist, fuzz_type, model)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    @utils.parameterized(fuzzer.get_param_datasets(
        blacklist_params, ['huge', 'date', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_update_blacklist_fuzzed(self, parameter, fuzz_type, payload):
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        resp, old_model = self._create_blacklist(
            datagen.random_blacklist_data())
        patch_model = old_model
        patch_model.__dict__[parameter] = payload
        result = fuzzer.verify_tempest_exception(
            self.client.patch_blacklist, fuzz_type, old_model.id, patch_model)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    @utils.parameterized(fuzzer.get_datasets(
        ['number', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_get_blacklist_fuzzed_uuid(self, fuzz_type, payload):
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        resp, test_model = self._create_blacklist(
            datagen.random_blacklist_data())
        result = fuzzer.verify_tempest_exception(
            self.client.get_blacklist, fuzz_type, payload)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    filters = [
        'limit', 'marker', 'sort_dir', 'type', 'name', 'ttl', 'data',
        'description', 'status'
    ]

    @utils.parameterized(fuzzer.get_param_datasets(
        filters, ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_list_blacklists_fuzzed_filter(self, parameter,
                                           fuzz_type, payload):
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        result = fuzzer.verify_tempest_exception(
            self.client.list_blacklists, fuzz_type,
            filters={parameter: payload})
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    @utils.parameterized(fuzzer.get_datasets(
        ['number', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_delete_blacklist_fuzzed_uuid(self, fuzz_type, payload):
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        resp, test_model = self._create_blacklist(
            datagen.random_blacklist_data())
        result = fuzzer.verify_tempest_exception(
            self.client.delete_blacklist, fuzz_type, payload)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    # def test_blacklist_regex_ddos(self):
    #     blacklist_model = datagen.random_blacklist_data()
    #     blacklist_model.pattern = "(([a-z])+.)+[A-Z]([a-z])+$"
    #     self.client.post_blacklist(blacklist_model)

    #     zone_model = datagen.random_zone_data()
    #     zone_model.name =\
    #         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com."
    #     resp, model = ZoneClient.as_user('default').post_zone(zone_model)
    #     ZoneClient.as_user('default').wait_for_zone(model.id)
