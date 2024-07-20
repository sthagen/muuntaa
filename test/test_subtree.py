import logging
from typing import Any

from lxml import etree, objectify

import muuntaa.subtree as subtree

CFG = {'csaf_version': '2.0'}
CFG_TOO = {
    'publisher_name': 'Publisher Name',
    'publisher_namespace': 'https://example.com',
}

EXAMPLE_A_XML = """\
<cvrfdoc
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:cpe="http://cpe.mitre.org/language/2.0"
  xmlns:cvrf="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf"
  xmlns:cvrf-common="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/common"
  xmlns:cvssv2="http://scap.nist.gov/schema/cvss-v2/1.0"
  xmlns:cvssv3="https://www.first.org/cvss/cvss-v3.0.xsd"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:ns0="http://purl.org/dc/elements/1.1/"
  xmlns:prod="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/prod"
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/1.0"
  xmlns:sch="http://purl.oclc.org/dsdl/schematron"
  xmlns:vuln="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf"
  >
  <!-- Document wide context information -->
  <DocumentTitle>AppY Stream Control Transmission Protocol</DocumentTitle>
  <DocumentType>Security Advisory</DocumentType>
  <DocumentPublisher Type="Vendor">
      <ContactDetails>Emergency Support: ...</ContactDetails>
      <IssuingAuthority>... Team (PSIRT)....</IssuingAuthority>
  </DocumentPublisher>
  <DocumentTracking>
    <Identification>
      <ID>vendorix-sa-20170301-abc</ID>
    </Identification>
    <Status>Final</Status>
    <Version>1.0</Version>
    <RevisionHistory>
      <Revision>
        <Number>1.0</Number>
        <Date>2017-03-01T14:58:48</Date>
        <Description>Initial public release.</Description>
      </Revision>
    </RevisionHistory>
    <InitialReleaseDate>2017-03-01T16:00:00</InitialReleaseDate>
    <CurrentReleaseDate>2017-03-01T14:58:48</CurrentReleaseDate>
    <Generator>
      <Engine>TVCE</Engine>
    </Generator>
  </DocumentTracking>
  <DocumentNotes>
    <Note Title="Summary" Type="General" Ordinal="1">A vulnerability...</Note>
    <Note Title="CVSS 3.0 Notice" Type="Other" Ordinal="2">... </Note>
  </DocumentNotes>
  <DocumentReferences>
    <Reference Type="Self">
      <URL>https://example.com/sec/vendorix-sa-20170301-abc</URL>
      <Description>Vendorix Foo AppY...</Description>
    </Reference>
  </DocumentReferences>
</cvrfdoc>
"""

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

HAS_TL_NOTES_XML = """\
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
   <DocumentNotes>
      <Note Audience="All" Ordinal="1" Title="Summary" Type="Summary" xml:lang="en">
         This document contains descriptions of Acme product security vulnerabilities with details on impacted ...
         Additional information regarding ... be found at the Acme sites referenced in this document.</Note>
   </DocumentNotes>
</cvrfdoc>
"""

HAS_TL_REFERENCES_XML = """\
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
   <DocumentReferences>
     <Reference Type="Self">
     <URL>https://example.com/sec/vendorix-sa-20170301-abc</URL>
     <Description>Vendorix Foo AppY...</Description>
     </Reference>
   </DocumentReferences>
</cvrfdoc>
"""

HAS_TL_PUBLISHER_XML = """\
<cvrfdoc
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:cpe="http://cpe.mitre.org/language/2.0"
  xmlns:cvrf="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf"
  xmlns:cvrf-common="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/common"
  xmlns:cvssv2="http://scap.nist.gov/schema/cvss-v2/1.0"
  xmlns:cvssv3="https://www.first.org/cvss/cvss-v3.0.xsd"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:ns0="http://purl.org/dc/elements/1.1/"
  xmlns:prod="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/prod"
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/1.0"
  xmlns:sch="http://purl.oclc.org/dsdl/schematron"
  xmlns:vuln="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf"
  >
  <!-- Document wide context information -->
  <DocumentTitle>AppY Stream Control Transmission Protocol</DocumentTitle>
  <DocumentType>Security Advisory</DocumentType>
  <DocumentPublisher Type="Vendor">
      <ContactDetails>Emergency Support: ...</ContactDetails>
      <IssuingAuthority>... Team (PSIRT)....</IssuingAuthority>
  </DocumentPublisher>
</cvrfdoc>
"""

ROOT_EXAMPLE_A = objectify.fromstring(EXAMPLE_A_XML)
ROOT_HAS_TL_ACKS = objectify.fromstring(HAS_TL_ACKS_XML)
ROOT_HAS_TL_NOTES = objectify.fromstring(HAS_TL_NOTES_XML)
ROOT_HAS_TL_REFERENCES = objectify.fromstring(HAS_TL_REFERENCES_XML)
ROOT_HAS_TL_PUBLISHER = objectify.fromstring(HAS_TL_PUBLISHER_XML)


def test_document_leafs(caplog):
    expected = {
        'document': {
            'csaf_version': '2.0',
            'category': 'Security Advisory',
            'title': 'AppY Stream Control Transmission Protocol',
        }
    }
    dle = subtree.DocumentLeafs(CFG)
    caplog.set_level(logging.INFO)
    dle.load(ROOT_EXAMPLE_A)
    assert dle.dump() == expected
    assert 'ingesting sometimes present element' in caplog.text


# raise OSError(lmxl_dump(ROOT_HAS_TL_ACKS))
def lmxl_dump(el: Any) -> str:
    encoded: bytes = etree.tostring(el, encoding='utf-8', pretty_print=True, xml_declaration=True)
    return encoded.decode('utf-8')


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

    acks = subtree.Acknowledgments(lc_parent_code='cvrf')
    caplog.set_level(logging.WARNING)
    # raise OSError(lmxl_dump(ROOT_HAS_TL_ACKS))
    acks.load(ROOT_HAS_TL_ACKS.Acknowledgments)
    assert acks.dump() == expected
    assert not caplog.text


def test_tl_notes(caplog):
    expected = {
        'document': {
            'notes': [
                {
                    'text': (
                        '\n'
                        '         This document contains descriptions of Acme product security vulnerabilities with'
                        ' details on impacted ...\n'
                        '         Additional information regarding ... be found at the Acme sites referenced in'
                        ' this document.'
                    ),
                    'category': 'summary',
                    'audience': 'All',
                    'title': 'Summary',
                }
            ],
        },
    }

    part = subtree.Notes(lc_parent_code='cvrf')
    caplog.set_level(logging.ERROR)
    part.load(ROOT_HAS_TL_NOTES.DocumentNotes)
    assert not part.has_errors()
    assert part.dump() == expected
    assert not caplog.text


def test_tl_references(caplog):
    expected = {
        'document': {
            'references': [
                {
                    'category': 'self',
                    'summary': 'Vendorix Foo AppY...',
                    'url': 'https://example.com/sec/vendorix-sa-20170301-abc',
                }
            ],
        },
    }

    part = subtree.References(config=CFG, lc_parent_code='cvrf')
    caplog.set_level(logging.INFO)
    part.load(ROOT_HAS_TL_REFERENCES.DocumentReferences)
    assert not part.has_errors()
    assert part.dump() == expected
    assert not caplog.text


def test_tl_publisher(caplog):
    expected = {
        'document': {
            'publisher': {
                'category': 'vendor',
                'contact_details': 'Emergency Support: ...',
                'issuing_authority': '... Team (PSIRT)....',
                'name': 'Publisher Name',
                'namespace': 'https://example.com',
            },
        },
    }

    part = subtree.Publisher(config=CFG_TOO)
    caplog.set_level(logging.INFO)
    part.load(ROOT_HAS_TL_PUBLISHER.DocumentPublisher)
    assert not part.has_errors()
    assert part.dump() == expected
    assert not caplog.text


def test_document_with_tl_acks(caplog):
    expected_dle = {
        'document': {
            'csaf_version': '2.0',
            'category': 'Security Advisory',
            'title': 'AppY Stream Control Transmission Protocol',
        }
    }
    dle = subtree.DocumentLeafs(CFG)
    caplog.set_level(logging.INFO)
    dle.load(ROOT_EXAMPLE_A)
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
    acks = subtree.Acknowledgments(lc_parent_code='cvrf')
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
            'category': 'Security Advisory',
            'csaf_version': '2.0',
            'title': 'AppY Stream Control Transmission Protocol',
        },
    }
    doc = {'document': dle.dump()['document'] | acks.dump()['document']}
    assert doc == expected_doc
