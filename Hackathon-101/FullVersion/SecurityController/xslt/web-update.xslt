<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:output method="xml" encoding="UTF-8" indent="yes"/>
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
          <policy-id>2</policy-id>
          <policy-name>i2nsf-web-filter</policy-name>
          <rules nc:operation="replace">
            <rule-id><xsl:value-of select="i2nsf/rule/rule-id"/></rule-id>
            <rule-name><xsl:value-of select="i2nsf/rule/rule-name"/></rule-name>
            <condition>
              <packet-security-condition>
                <packet-security-ipv4-condition>
                  <pkt-sec-cond-ipv4-src><xsl:value-of select="i2nsf/rule/condition/source"/></pkt-sec-cond-ipv4-src>
                </packet-security-ipv4-condition>
              </packet-security-condition>
              <packet-payload-security-condition>
                <pkt-payload-content><xsl:value-of select="i2nsf/rule/condition/destination"/></pkt-payload-content>
              </packet-payload-security-condition>
              <generic-context-condition>
                <schedule>
                  <start-time><xsl:value-of select="i2nsf/rule/event/time-information/start-time"/></start-time>
                  <end-time><xsl:value-of select="i2nsf/rule/event/time-information/end-time"/></end-time>
                </schedule>
              </generic-context-condition>
            </condition>
            <action>
              <ingress-action-type><xsl:value-of select="i2nsf/rule/action/action-name"/></ingress-action-type>
            </action>
          </rules>
        </policy>
      </cfg-network-security-control>
    </config>
  </edit-config>
</rpc>
</xsl:template>
</xsl:stylesheet>
