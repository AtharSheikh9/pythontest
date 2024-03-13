import pefile
import re
import yara

def extract_strings_from_exe(exe_file_path):
    try:
        pe = pefile.PE(exe_file_path)
        
        strings_list = []
        for section in pe.sections:
            strings = section.get_data()
            strings_list.extend(strings.split(b'\x00'))
        
        return [string.decode('utf-8', errors='ignore') for string in strings_list if string]
    
    except Exception as e:
        print(f"Error: {e}")
        return []

def save_strings_to_file(strings, output_file):
    with open(output_file, 'w', encoding='utf-8') as file:
        for string in strings:
            file.write(f"{string}\n")

def extract_iocs_from_strings(strings_output):
    ip_addresses = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', strings_output)
    domain_names = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', strings_output)
    return ip_addresses, domain_names

def load_yara_rules(rule_file):
    try:
        rules = yara.compile(rule_file)
        return rules
    except yara.Error as e:
        print(f"Error loading YARA rules: {e}")
        return None

def scan_strings_against_rules(strings, rules):
    results = {}
    for string in strings:
        matches = rules.match(data=string)
        if matches:
            results[string] = [match.rule for match in matches]
    return results

def main():
    exe_path = 'tg.exe'  # Update with the path to your dummy executable
    output_file = 'extracted_strings.txt'
    yara_rule_file = 'yara-rule.yar'  # Update with the path to your YARA rule file

    # Extract strings from the executable file
    extracted_strings = extract_strings_from_exe(exe_path)

    # Save extracted strings to a file
    save_strings_to_file(extracted_strings, output_file)
    print(f"Extracted strings saved to '{output_file}'")

    # Extract IOCs from the strings
    iocs = extract_iocs_from_strings(' '.join(extracted_strings))
    ip_addresses, domain_names = iocs

    # Load YARA rules
    rules = load_yara_rules(yara_rule_file)
    if not rules:
        return

    # Scan extracted strings against YARA rules
    results = scan_strings_against_rules(extracted_strings, rules)

    # Output results
    print("Strings matched against YARA rules:")
    for string, matched_rules in results.items():
        print(f"String: {string}")
        print("Matched YARA rules:")
        for rule in matched_rules:
            print(f"- {rule}")

if __name__ == "__main__":
    main()
