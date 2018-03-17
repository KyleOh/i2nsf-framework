linecnt=0
f_temp = open("web-create-data.xml","r")
while True:
    line=f_temp.readline()
    if not line: break
    linecnt+=1


f_temp_ns=open("web-create-data.xml","r")
f_temp=open("data.xml","w")
for i in range(1,linecnt+1):
    if i!=2 and i!=linecnt:
        line=f_temp_ns.readline()
    elif i==2:
        line=f_temp_ns.readline()
        line="<i2nsf>\n"
    elif i==linecnt:
        line=f_temp_ns.readline()
        line="</i2nsf>"
    f_temp.write(line)
f_temp.close()
f_temp_ns.close()
