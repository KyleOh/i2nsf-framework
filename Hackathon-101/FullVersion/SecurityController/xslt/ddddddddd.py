import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element,SubElement, dump
from xml.etree import ElementTree
from xml.etree.ElementTree import ElementTree

index =""
tree=ET.parse('./web.xml')
root=tree.getroot()

rule_id = str(root[0][1].text).replace('\t','').strip('\n')
rule_name = str(root[0][0].text).replace('\t','').strip('\n')
position = str(root[0][5][0].text).replace('\t','').strip('\n')
website = str(root[0][5][1].text).replace('\t','').strip('\n')
start_time =str(root[0][4][0][0].text).replace('\t','').strip('\n')
end_time =str(root[0][4][0][1].text).replace('\t','').strip('\n')
action=str(root[0][3][0].text).replace('\t','').strip('\n')

root[0][1].text=rule_id
root[0][0].text=rule_name
root[0][5][0].text=position
root[0][5][1].text=website
root[0][4][0][0].text=start_time
root[0][4][0][1].text=end_time
root[0][3][0].text=action
dump(root)
print rule_id
print rule_name
print position
print website
print start_time
print end_time
print action
tree.write('data.xml')
