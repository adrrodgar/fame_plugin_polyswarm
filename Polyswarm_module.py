import os
import hashlib

try:
    from polyswarm_api.api import PolyswarmAPI
    from polyswarm_api.exceptions import NoResultsException
    HAVE_POLYSWARM = True
except ImportError:
    HAVE_POLYSWARM = False

from fame.common.utils import tempdir
from fame.common.exceptions import ModuleInitializationError, ModuleExecutionError
from fame.core.module import ProcessingModule

class Polyswarm_module(ProcessingModule):

    name = "polyswarm"
    description = "Get report from Polyswarm platform."
    config = [
        {
            'name': 'api_key',
            'type': 'string',
            'description': 'API Key needed to use the Polyswarm Public API 2.0',
        }
    ]

    def initialize(self):
        if not HAVE_POLYSWARM:
            raise ModuleInitializationError(self, 'Missing dependency: polyswarm_api')

        return True

    def each_with_type(self, target, file_type):
        self.results = dict()

        poly = PolyswarmAPI(key=self.api_key)

        if file_type == 'url' or file_type == 'msg' or file_type == 'eml':
            pass
        else:
            positives = 0
            total = 0
            sha256 = None
            if file_type == "hash":
                sha256 = target.lower()
            else:
                sha256 = hashlib.sha256(open(target, 'r').read()).hexdigest()
                try:
                    response = poly.search(sha256)
                    self.results['scans'] = list()
                    for result in response:
                        if result.assertions:
                            for assertion in result.assertions:
                                if assertion.verdict:
                                    self.results['scans'].append({'av': assertion.author_name, 'veredict': 'Malware'})
                                    positives += 1
                                total += 1

                            self.results['total'] = "{0}/{1}".format(positives, total)
                            self.results['positives'] = positives
                            self.results['PolyScore'] = result.polyscore
                            self.results['permalink'] = result.permalink
                            self.results['message'] = "Hash found"
                            return True
                        else:
                            return False
                except NoResultsException:
                    return False
                except Exception as error:
                    return False
