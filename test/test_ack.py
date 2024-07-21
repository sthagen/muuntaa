import logging

from lxml import objectify

from muuntaa.ack import Acknowledgments
from muuntaa.document import Leafs

CFG = {
    'csaf_version': '2.0',
    'fix_insert_current_version_into_revision_history': 'true',
}

HAS_TL_ACKS_XML = """\
<?xml version='1.0'?>
<cvrfdoc xmlns:cpe="http://cpe.mitre.org/language/2.0"
   xmlns:cvrf="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf"
   xmlns:cvrf-common="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/common"
   xmlns:cvssv2="http://scap.nist.gov/schema/cvss-v2/1.0"
   xmlns:cvssv3="https://www.first.org/cvss/cvss-v3.0.xsd"
   xmlns:dc="http://purl.org/dc/elements/1.2/"
   xmlns:ns0="http://purl.org/dc/elements/1.1/"
   xmlns:prod="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/prod"
   xmlns:scap-core="http://scap.nist.gov/schema/scap-core/1.0"
   xmlns:sch="http://purl.oclc.org/dsdl/schematron"
   xmlns:vuln="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xmlns="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf">

   <!-- Document wide context information -->
   <DocumentTitle xml:lang="en">Acme Security Advisory for foo on bar - March 2017 - CSAF CVRF</DocumentTitle>
   <DocumentType xml:lang="en">Acme Security Advisory</DocumentType>
   <Acknowledgments>
      <Acknowledgment>
         <Name>Some One (not to be named explicitly)</Name>
         <Name>Some One Else</Name>
         <Organization>Acme Inc.</Organization>
         <Description>Ja ja</Description>
         <URL>https://example.com</URL>
      </Acknowledgment>
      <Acknowledgment>
         <Name>Jane Employee</Name>
         <Organization>Acme Inc.</Organization>
         <Description>Ja ja</Description>
         <URL>https://example.com/1</URL>
         <URL>https://example.com/2</URL>
         <URL>https://example.com/3</URL>
      </Acknowledgment>
   </Acknowledgments>
</cvrfdoc>
"""

ROOT_HAS_TL_ACKS = objectify.fromstring(HAS_TL_ACKS_XML)


def test_tl_acknowledgements(caplog):
    expected = {
        'document': {
            'acknowledgments': [
                {
                    'names': [
                        'Some One (not to be named explicitly)',
                        'Some One Else',
                    ],
                    'organization': 'Acme Inc.',
                    'summary': 'Ja ja',
                    'urls': [
                        'https://example.com',
                    ],
                },
                {
                    'names': [
                        'Jane Employee',
                    ],
                    'organization': 'Acme Inc.',
                    'summary': 'Ja ja',
                    'urls': [
                        'https://example.com/1',
                        'https://example.com/2',
                        'https://example.com/3',
                    ],
                },
            ],
        },
    }

    acks = Acknowledgments(lc_parent_code='cvrf')
    caplog.set_level(logging.WARNING)
    # raise OSError(lmxl_dump(ROOT_HAS_TL_ACKS))
    acks.load(ROOT_HAS_TL_ACKS.Acknowledgments)
    assert acks.dump() == expected
    assert not caplog.text


def test_document_with_tl_acks(caplog):
    expected_dle = {
        'document': {
            'csaf_version': '2.0',
            'category': 'Acme Security Advisory',
            'title': 'Acme Security Advisory for foo on bar - March 2017 - CSAF CVRF',
        }
    }
    dle = Leafs(CFG)
    caplog.set_level(logging.INFO)
    dle.load(ROOT_HAS_TL_ACKS)
    assert dle.dump() == expected_dle
    assert 'ingesting sometimes present element' in caplog.text

    expected_ack = {
        'document': {
            'acknowledgments': [
                {
                    'names': [
                        'Some One (not to be named explicitly)',
                        'Some One Else',
                    ],
                    'organization': 'Acme Inc.',
                    'summary': 'Ja ja',
                    'urls': [
                        'https://example.com',
                    ],
                },
                {
                    'names': [
                        'Jane Employee',
                    ],
                    'organization': 'Acme Inc.',
                    'summary': 'Ja ja',
                    'urls': [
                        'https://example.com/1',
                        'https://example.com/2',
                        'https://example.com/3',
                    ],
                },
            ],
        },
    }
    acks = Acknowledgments(lc_parent_code='cvrf')
    caplog.set_level(logging.WARNING)
    acks.load(ROOT_HAS_TL_ACKS.Acknowledgments)
    assert acks.dump() == expected_ack
    assert 'ingesting sometimes present element' in caplog.text

    expected_doc = {
        'document': {
            'acknowledgments': [
                {
                    'names': [
                        'Some One (not to be named explicitly)',
                        'Some One Else',
                    ],
                    'organization': 'Acme Inc.',
                    'summary': 'Ja ja',
                    'urls': [
                        'https://example.com',
                    ],
                },
                {
                    'names': [
                        'Jane Employee',
                    ],
                    'organization': 'Acme Inc.',
                    'summary': 'Ja ja',
                    'urls': [
                        'https://example.com/1',
                        'https://example.com/2',
                        'https://example.com/3',
                    ],
                },
            ],
            'category': 'Acme Security Advisory',
            'csaf_version': '2.0',
            'title': 'Acme Security Advisory for foo on bar - March 2017 - CSAF CVRF',
        },
    }
    doc = {'document': dle.dump()['document'] | acks.dump()['document']}
    assert doc == expected_doc
