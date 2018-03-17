<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:output method="xml" encoding="UTF-8"  indent="yes"/>
<xsl:strip-space elements="*"/>
<xsl:template match="/">
<rpc message-id="1" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
<edit-config>
  <target>
    <running />
  </target>
  <config>
    <cfg-network-security-control xmlns="http://skku.edu/nsf-facing-interface" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <policy>
        <policy-id>1</policy-id>
        <policy-name>i2nsf-firewall</policy-name>
        <rules nc:operation="replace">
          <rule-id><xsl:value-of select="I2NSF/Policy_enterprise/Rule_id"/></rule-id>
          <rule-name><xsl:value-of select="I2NSF/Policy_enterprise/Rule_name"/></rule-name>
        </rules>
      </policy>
    </cfg-network-security-control>
  </config>
</edit-config>
</rpc>
</xsl:template>

</xsl:stylesheet>
