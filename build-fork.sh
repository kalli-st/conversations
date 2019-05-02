#!/bin/sh

echo "rename folders"

for folder in $(find -type d -name "siacs"); do
	newfolder="$(echo $folder | sed "s/siacs/sum7/")";
	echo "$folder -> $newfolder"
	mv "$folder" "$newfolder"
done

echo "fix packageing"
for file in $(find -type f -name "*.xml" -or -name "*.java"); do
	sed -i "s/eu.siacs./eu.sum7./" "$file"
	echo "$file: $?"
done

sed -i "s/eu.siacs./eu.sum7./" "proguard-rules.pro"
