#!/system/bin/sh
# usage: kill "/full/command/line -with arguments"
for file in /proc/[0-9]* ; do

 	 cmd=$(cat $file/cmdline)	 
 	 iseq=${cmd%$1}
 	 
 	 if ! ( (echo ${cmd:?}) > /dev/null 2>&1) ; then
 	    continue
 	 fi
 	   	 
    if ! ( (echo ${iseq:?}) > /dev/null 2>&1 ) ; then
    	kill -9 ${file#/proc/}
    fi
 
done
