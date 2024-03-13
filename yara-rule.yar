rule Malicious_XML {
    strings:
        $malicious_xml = /<file name="netapi32.dll" loadFrom="%SystemRoot%\\system32\\" \/>|<file name="netutils.dll" loadFrom="%SystemRoot%\\system32\\" \/>|<file name="textshaping.dll" loadFrom="%SystemRoot%\\system32\\" \/>/

    condition:
        $malicious_xml
}
