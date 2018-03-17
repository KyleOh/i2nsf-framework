import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element,SubElement, dump
from xml.etree import ElementTree
from xml.etree.ElementTree import ElementTree

index =""
tree=ET.parse('./web.xml')
root=tree.getroot()

for src in root.iter('rule'):
	index=str(src.find('rule-case').text).replace('\t','').strip('\n')
print index