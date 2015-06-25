ADB="../../adt-bundle-linux-x86_64/sdk/platform-tools/adb"
APPS="killall reset_nfc"
TMPDIR="/data/data/tmp/"

echo "Creating $TMPDIR..."
$ADB shell "su -c 'mkdir $TMPDIR'"
$ADB shell "su -c 'chmod 777 $TMPDIR'"

for A in $APPS
do
	echo "Uploading $TMPDIR$A..."
	$ADB push $A $TMPDIR$A
	echo "Chmodding $TMPDIR$A..."
	$ADB shell "su -c ' chmod 777 $TMPDIR$A'"
done
