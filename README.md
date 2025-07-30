/var/ossec/framework/python/bin/pip3 install iocextract
 sudo chown -R root:wazuh /var/ossec/framework/python/lib/python3.10/site-packages/
 sudo chmod -R u=rwX,g=rX,o= /var/ossec/framework/python/lib/python3.10/site-packages/
---
<!-- misp it at your will.-->
 <integration>
  <name>custom-misp</name>
  <alert_format>json</alert_format>
  <level>3</level>
</integration> 
---
<!-- Modify it at your will. -->

<group name="misp,">
  <!-- Base MISP rule - EXACT format from original repository -->
  <rule id="100620" level="10">
    <field name="integration">misp</field>
    <description>MISP Events</description>
  </rule>
  
  <!-- MISP connection error - EXACT format from original repository -->
  <rule id="100621" level="5">
    <if_sid>100620</if_sid>
    <field name="misp.error">\.+</field>
    <description>MISP - Error connecting to API</description>
   
    <group>misp_error,</group>
  </rule>
  
  <!-- MISP IoC found - EXACT format from original repository -->
  <rule id="100622" level="12">
    <field name="misp.category">\.+</field>
    <description>MISP - IoC found in Threat Intel - Category: $(misp.category), Attribute: $(misp.value)</description>
    
    <group>misp_alert,</group>

</group>
