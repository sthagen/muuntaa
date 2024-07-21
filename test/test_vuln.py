import logging

from lxml import objectify

from muuntaa.vuln import Vulnerabilities

CFG = {
    'csaf_version': '2.0',
    'default_CVSS3_version': '3.0',
    'fix_insert_current_version_into_revision_history': 'true',
    'remove_CVSS_values_without_vector': 'false',
}

HAS_VULNS_XML = """\
<?xml version="1.0"?>
<cvrfdoc
  xmlns:cpe="http://cpe.mitre.org/language/2.0"
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
  <!-- Product tree section -->
  <ProductTree xmlns="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/prod">
    <Branch Name="Vendorix" Type="Vendor">
      <Branch Name="... Appliances" Type="Product Name">
        <Branch Name="1.0" Type="Product Version">
          <Branch Name=".0" Type="Service Pack">
                <FullProductName ProductID="CVRFPID-223152">...
                  AppY 1.0.0</FullProductName>
          </Branch>
          <Branch Name="(2)" Type="Service Pack">
                <FullProductName ProductID="CVRFPID-223153">...
                  AppY 1.0(2)</FullProductName>
          </Branch>
        </Branch>
        <Branch Name="1.1" Type="Product Version">
          <Branch Name=".0" Type="Service Pack">
                <FullProductName ProductID="CVRFPID-223155">...
                  AppY 1.1.0</FullProductName>
          </Branch>
              <Branch Name="(1)" Type="Service Pack">
                <FullProductName ProductID="CVRFPID-223156">...
                  AppY 1.1(1)</FullProductName>
              </Branch>
        </Branch>
      </Branch>
    </Branch>
  </ProductTree>
  <!-- Vulnerability section -->
  <Vulnerability Ordinal="1"
   xmlns="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln">
    <Title>... Transmission Protocol  ...</Title>
    <ID SystemName="Vendorix Bug ID">VDXvc83320</ID>
    <Notes>
      <Note Title="Summary" Type="Summary" Ordinal="1">A vuln ...</Note>
      <Note Title="Vendorix Bug IDs" Type="Other" Ordinal="3">
        VDXvc83320</Note>
    </Notes>
    <CVE>CVE-2017-3826</CVE>
    <ProductStatuses>
      <Status Type="Known Affected">
        <ProductID>CVRFPID-223152</ProductID>
        <ProductID>CVRFPID-223153</ProductID>
        <ProductID>CVRFPID-223155</ProductID>
        <ProductID>CVRFPID-223156</ProductID>
      </Status>
    </ProductStatuses>
    <CVSSScoreSets>
      <ScoreSetV3>
        <BaseScoreV3>7.5</BaseScoreV3>
        <VectorV3>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</VectorV3>
         </ScoreSetV3>
      </CVSSScoreSets>
    <Remediations>
      <Remediation Type="Workaround">
        <Description>There are no workarounds that ...</Description>
          </Remediation>
        </Remediations>
    <References>
      <Reference Type="Self">
        <URL>https://example.com/sec/vendorix-sa-20170301-abc</URL>
        <Description>... AppY Stream ...</Description>
      </Reference>
    </References>
  </Vulnerability>
  <!-- No more elements to follow -->
</cvrfdoc>
"""

ROOT_HAS_VULNS = objectify.fromstring(HAS_VULNS_XML)


def test_products(caplog):
    expected = {'vulnerabilities': []}  # TODO: Find the bug or a sample that results in vulnerabilities
    vln = Vulnerabilities(config=CFG)
    caplog.set_level(logging.INFO)
    vln.load(ROOT_HAS_VULNS)
    assert vln.dump() == expected
    assert 'ingesting sometimes present element' in caplog.text
