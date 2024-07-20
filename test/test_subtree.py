import logging
from typing import Any

from lxml import etree, objectify

import muuntaa.subtree as subtree

CFG = {'csaf_version': '2.0'}


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
   <DocumentPublisher Type="Vendor"/>
   <DocumentTracking>
      <Identification>
         <ID>acme-2017-42</ID>
      </Identification>
      <Status>Final</Status>
      <Version>1.0</Version>
      <RevisionHistory>
         <Revision>
            <Number>1.0</Number>
            <Date>2017-03-17T12:34:56-06:00</Date>
            <Description>Initial Distribution</Description>
         </Revision>
         <Revision>
            <Number>1.1</Number>
            <Date>2017-03-18T01:23:45-06:00</Date>
            <Description>Corrected Distribution</Description>
         </Revision>
      </RevisionHistory>
      <InitialReleaseDate>2017-01-17T12:34:56-06:00</InitialReleaseDate>
      <CurrentReleaseDate>2017-01-18T01:23:34-06:00</CurrentReleaseDate>
   </DocumentTracking>
   <DocumentNotes>
      <Note Audience="All" Ordinal="1" Title="Summary" Type="Summary" xml:lang="en">
         This document contains descriptions of Acme product security vulnerabilities with details on impacted ...
         Additional information regarding ... be found at the Acme sites referenced in this document.</Note>
   </DocumentNotes>
   <DocumentDistribution>This document ... at: https://acme.example.com/sa/acme-2017-42-1-1.xml</DocumentDistribution>
   <DocumentReferences>
      <Reference Type="External">
         <URL>https://acme.example.com/sa/acme-2017-42-1-1.json</URL>
         <Description>URL to JSON version of Advisory</Description>
      </Reference>
   </DocumentReferences>
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

   <!-- Product tree section -->
   <ProductTree xmlns="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/prod">
      <Branch Name="Acme" Type="Vendor">
         <Branch Name="Acme Things" Type="Product Family">
            <Branch Name="Things On bar" Type="Product Name">
               <Branch Name="1.9" Type="Product Version">
                  <FullProductName ProductID="AC-FOO-1.9-on-bar">Foo 1.9 on bar</FullProductName>
               </Branch>
               <Branch Name="2.1" Type="Product Version">
                  <FullProductName ProductID="AC-FOO-2.1-on-bar">Foo 2.1 on bar</FullProductName>
               </Branch>
            </Branch>
            <Branch Name="Things On baz" Type="Product Name">
               <Branch Name="1.9" Type="Product Version">
                  <FullProductName ProductID="AC-FOO-1.9-on-baz">Foo 1.9 on baz</FullProductName>
               </Branch>
               <Branch Name="2.1" Type="Product Version">
                  <FullProductName ProductID="AC-FOO-2.1-on-baz">Foo 2.1 on baz</FullProductName>
               </Branch>
            </Branch>
         </Branch>
       </Branch>
   </ProductTree>

   <!-- Vulnerability sections -->
   <Vulnerability Ordinal="1" xmlns="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln">
      <Title>Vulnerability in the TCP component of Acme foo (CVE-2017-99999)</Title>
      <Notes>
         <Note Audience="All" Ordinal="1" Title="Details" Type="Details">
            Vulnerability in the TCP component of Acme foo.
            Supported versions that are affected are 1.9, and 2.0 when installed on bar but not affected when on baz.
            Easily exploitable ... access via a single 0x42 value payload byte to compromise Acme foo.
            Successful attacks of this vulnerability ... of service (DOS) of Acme foo.
            CVSS 3.0 Base Score 9.8 (Confidentiality and Availability impacts).
            CVSS Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).</Note>
      </Notes>
      <Involvements>
         <Involvement Party="Vendor" Status="Completed">
            <Description>Fix has been released</Description>
         </Involvement>
      </Involvements>
      <CVE>CVE-2017-99999</CVE>
      <ProductStatuses>
         <Status Type="Known Affected">
            <ProductID>AC-FOO-1.9-on-bar</ProductID>
            <ProductID>AC-FOO-2.1-on-bar</ProductID>
         </Status>
         <Status Type="Known Not Affected">
            <ProductID>AC-FOO-1.9-on-baz</ProductID>
            <ProductID>AC-FOO-2.1-on-baz</ProductID>
         </Status>
      </ProductStatuses>
      <CVSSScoreSets>
         <ScoreSetV3>
            <BaseScoreV3>9.8</BaseScoreV3>
            <VectorV3>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</VectorV3>
         </ScoreSetV3>
      </CVSSScoreSets>
      <Remediations>
         <Remediation Type="Vendor Fix">
            <Description>acme-2017-42</Description>
            <Entitlement xml:lang="it">Tutte le persone su questo pianeta</Entitlement>
            <URL>https://acme.example.com/sa/acme-2017-42-1-1.html</URL>
            <ProductID>AC-FOO-1.9-on-bar</ProductID>
            <ProductID>AC-FOO-2.1-on-bar</ProductID>
         </Remediation>
      </Remediations>
   </Vulnerability>
   <!-- No more elements to follow -->
</cvrfdoc>
"""

ROOT_EXAMPLE_A = objectify.fromstring(EXAMPLE_A_XML)
ROOT_HAS_TL_ACKS = objectify.fromstring(HAS_TL_ACKS_XML)


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
    # raise OSError(lmxl_dump(ROOT_HAS_TL_ACKS))
    acks.load(ROOT_HAS_TL_ACKS.Acknowledgments)
    assert acks.dump() == expected_ack
    assert 'ingesting sometimes present element' in caplog.text

    expected_doc = {
        'csaf_version': '2.0',
        'category': 'Security Advisory',
        'title': 'AppY Stream Control Transmission Protocol',
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
    doc = {**dle.dump(), **acks.dump()}
