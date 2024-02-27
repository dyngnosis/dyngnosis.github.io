---
layout: research
title: Overcoming VirusTotal's Shadow DOM with Selenium and PyShadow
---
# Overcoming VirusTotal's Shadow DOM with Selenium and PyShadow
For cybersecurity practitioners, VirusTotal (VT) is a critical tool for the analysis and scanning of files and URLs. However, automating interactions with VT can be challenging due to its advanced anti-automation measures, including the use of Shadow DOM to encapsulate and hide crucial data and controls. This technical guide discusses the implementation of Selenium alongside PyShadow to navigate VT's Shadow DOM, enabling automated data extraction for file details and behavioral analysis.

### Understanding the Shadow DOM and Its Impact on Automation
The Shadow DOM is a web technology that allows developers to encapsulate HTML, CSS, and JavaScript, preventing styles and scripts from interfering with the main document. While this improves web application modularity and maintainability, it poses significant barriers to automation tools like Selenium, which are designed to interact with the main DOM. As a result, elements within the Shadow DOM are inaccessible to Selenium, making automation efforts ineffective without additional tools.

### Disclaimer: 
This guide is crafted with the spirit of academic curiosity and is aimed at aiding cybersecurity students and enthusiasts in their educational pursuits. It's important to note that any commercial application of these methods for accessing VirusTotal (or any service) without proper authorization not only flirts with the boundaries of terms of service agreements but almost certainly crosses them. In simpler terms, if you're thinking about using this for your day job or any commercial venture, think again. Not only is it likely against the rules, but it might also earn your IP address a spot on the naughty list (read: banned). So, let's keep this in the realm of learning and exploration, shall we? After all, it's all fun and games until someone gets IP banned. Proceed with both caution and a healthy dose of common sense.

### The Challenge of Automating VirusTotal
Automating VT lookups and analysis without official API access necessitates navigating its anti-automation defenses. Options for accessing VT data are limited to expensive premium API access or the restrictive community API. Selenium, equipped with a headless browser, initially seems like a viable solution for automation; however, VT's use of the Shadow DOM renders much of its content unreachable, requiring a different approach.  


The following code demonstrates the Selenium failure case where no clickable links can be found in the browser DOM object.



```python
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import re
import pprint
import time
from selenium.webdriver.common.by import By

chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument('--headless')  # Run in headless mode, remove this line if you want to see the browser window
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('--disable-dev-shm-usage')

# Setup service to manage ChromeDriver
service = Service(ChromeDriverManager().install())

# Initialize the Chrome driver with the specified options and service
driver = webdriver.Chrome(service=service, options=chrome_options)

# Specify the target hash
target_hash = 'da7f43a0af25d93cf194369d0fe96ce462d23e527156ffd3e6fcbb573bf3a857'

# Go to a webpage
driver.get(f"https://www.virustotal.com/gui/file/{target_hash}/details")
links = driver.find_elements(By.TAG_NAME, "a")
if links == []:
    print("no links found")
else:
    print(links)
    # Iterate through the list of links
    for link in links:
        print(link)
        # Get the href attribute (URL)
        href = link.get_attribute("href")
        # Get the text of the link
        text = link.text
        print(f"Link: {href}, Text: '{text}'")
        
```

    no links found


### Incorporating PyShadow for Enhanced Access
To overcome the limitations imposed by the Shadow DOM on automation efforts, we introduce PyShadow, a Python library designed to work seamlessly with Selenium for navigating and interacting with elements hidden within the Shadow DOM. By leveraging PyShadow, cybersecurity professionals can extend the capabilities of Selenium, enabling it to "see" and interact with elements that were previously inaccessible due to encapsulation on
Utilizing PyShadow in conjunction with Selenium allows for the automation of data extraction from the "file details" element within VirusTotal, a critical component for comprehensive file analysis. The code snippet provided earlier demonstrates the challenge of accessing elements hidden by the Shadow DOM. However, with PyShadow, accessing these elements becomes straightforward:


```python
from pyshadow.main import Shadow
# Other imports remain the same

# Initialize the Chrome driver and Shadow as before
driver = webdriver.Chrome(service=service, options=chrome_options)
shadow = Shadow(driver)
target_url = f"https://www.virustotal.com/gui/file/{target_hash}/details"
print(target_url)
# Navigate to the VirusTotal page for the specified file hash
driver.get(target_url)

# Use PyShadow to find elements within the Shadow DOM
details_link = shadow.find_elements("a")
for link in details_link:
    if link.text.upper() == "DETAILS":  # Check if the link text matches "DETAILS"
        href = link.get_attribute("href")
        print(f"Found and clicked the Details link: {href}")
        link.click()  # Click on the link to navigate to the details section

```

    https://www.virustotal.com/gui/file/da7f43a0af25d93cf194369d0fe96ce462d23e527156ffd3e6fcbb573bf3a857/details
    Found and clicked the Details link: https://www.virustotal.com/gui/file/da7f43a0af25d93cf194369d0fe96ce462d23e527156ffd3e6fcbb573bf3a857/details


Now that we've successfully clicked the "Details" tab of the analysis we're ready to extract the raw data using PyShadow.  We find the hidden `vt-ui-file-details` which contains a messy, unstructured chunk of data.  We use `parse_vt_ui_file_details_text` structure the file detail and implement  `parse_section_details` as an example of how to rebuild the Sections data a a list of dictionaries.

### Structuring the Data with Python

#### The `parse_section_details` Function
The `parse_section_details` function takes a list of strings (`section_lines`), which represents lines of text from a specific section within the "file details" part of VT. This function is designed to parse these lines into a structured format. Assuming the first line contains headers and the subsequent lines contain corresponding values, the function splits these lines, maps the values to their respective headers, and fills in any missing values with 'N/A'. This structured approach allows for a more efficient analysis of the data, ensuring that each entry is correctly associated with its header.

#### The `parse_vt_ui_file_details_text` Function
The `parse_vt_ui_file_details_text` function demonstrates a more complex parsing operation. It takes a large block of text, which includes various details about a file analyzed by VT, and parses it into a structured dictionary. By identifying key sections within the text (such as "MD5", "SHA-256", "File type", etc.), the function systematically organizes the data under these keys. For sections that contain multiple lines of data, the information is stored as a list under the respective key. This function also includes special handling for certain keys, such as "Header", where additional parsing is applied to further structure the data.

### Application Example
An application example of these functions is shown in the final code snippet, where the text extracted from the "file details" section of VT (using PyShadow and Selenium) is parsed into a structured format. This format is invaluable for cybersecurity analysts who need to programmatically analyze file characteristics and behaviors based on VT's reports.  The use of Python dictionaries and lists to structure the data ensures that it is easily accessible and can be further processed, analyzed, or stored in a database for long-term analysis trends. 


```python
def parse_section_details(section_lines):
    sections = []
    if not section_lines:
        return sections  # Return an empty list if there are no lines to process
    
    headers = section_lines[0].split()  # Assuming the first line contains headers
    for line in section_lines[1:]:  # Skipping the headers line
        values = line.split()
        # Ensure values list is as long as headers list, filling missing values with 'N/A'
        values += ['N/A'] * (len(headers) - len(values))
        section = {headers[i]: values[i] for i in range(len(headers))}
        sections.append(section)
    return sections

def parse_vt_ui_file_details_text(text):
    # Define the keys (identifiers) to look for in the text
    keys = [
        "MD5", "SHA-1", "SHA-256", "Vhash", "Authentihash", "Imphash", "SSDEEP", "TLSH",
        "File type", "Magic", "TrID", "DetectItEasy", "File size", "PEiD packer",
        "Creation Time", "First Seen In The Wild", "First Submission", "Last Submission",
        "Last Analysis", "Signature Verification", "File Version Information", "Header",
        "Imports", "Contained Resources By Type", "Contained Resources By Language",
        "Contained Resources", "Common Language Runtime metadata version", "CLR version",
        "Assembly name", "Metadata header", "Assembly flags", "Streams", "External Assemblies",
        "Assembly Data", "Type Definitions", "External Modules", "Unmanaged Method List", "Compiler Products"
    ]

    parsed_data = {}
    current_key = None
    lines = text.split('\n')

    for line in lines:
        if line in keys:
            current_key = line
            parsed_data[current_key] = []
        elif current_key:
            parsed_data[current_key].append(line)

    for key in parsed_data:
        if len(parsed_data[key]) == 1:
            parsed_data[key] = parsed_data[key][0]
        elif key == "Header":  # Special handling for 'Header'
            header_lines = parsed_data[key]
            sections_start_index = header_lines.index('Sections') + 1
            header_info = header_lines[:sections_start_index - 1]  # Exclude 'Sections'
            section_details = header_lines[sections_start_index:]
            parsed_data[key] = {
                "Info": dict(zip(header_info[::2], header_info[1::2])),
                "Sections": parse_section_details(section_details)
            }

    return parsed_data
file_details = parse_vt_ui_file_details_text(shadow.find_element("vt-ui-file-details").text)
pprint.pprint(file_details)
```

    {'Authentihash': '008044aaeb42e68783f57eb4d70b542b60854ebe6dfdae705d889275227cd6b6',
     'Compiler Products': ['id: 259, version: 29395 count=14',
                           'id: 261, version: 29395 count=171',
                           'id: 260, version: 29395 count=22',
                           'id: 257, version: 29395 count=3',
                           '[---] Unmarked objects count=131',
                           'id: 260, version: 31823 count=17',
                           'id: 259, version: 31823 count=21',
                           'id: 261, version: 31823 count=84',
                           'id: 265, version: 31937 count=1',
                           'id: 255, version: 31937 count=1'],
     'Contained Resources': ['SHA-256 File Type Type Language Entropy Chi2',
                             '4bb79dcea0a901f7d9eac5aa05728ae92acb42e0cb22e5dd14134f4421a3d8df '
                             'XML RT_MANIFEST ENGLISH US 4.91 4031.47'],
     'Contained Resources By Language': ['ENGLISH US', '1'],
     'Contained Resources By Type': ['RT_MANIFEST', '1'],
     'Creation Time': '2023-09-14 02:11:34 UTC',
     'DetectItEasy': 'PE32   Compiler: EP:Microsoft Visual C/C++ (2017 v.15.5-6) '
                     '[EXE32]   Compiler: Microsoft Visual C/C++ (2022 v.17.4)',
     'File size': '742.50 KB (760320 bytes)',
     'File type': ['Win32 EXE', 'executable', 'windows', 'win32', 'pe', 'peexe'],
     'First Submission': '2023-09-14 02:14:31 UTC',
     'Header': {'Info': {'Compilation Timestamp': '2023-09-14 02:11:34 UTC',
                         'Contained Sections': '6',
                         'Entry Point': '40527',
                         'Target Machine': 'Intel 386 or later processors and '
                                           'compatible processors'},
                'Sections': [{'Address': '137099',
                              'Chi2': 'N/A',
                              'Entropy': 'N/A',
                              'MD5': 'N/A',
                              'Name': '.text',
                              'Raw': '57f33b3062adb051753b57700ab2c988',
                              'Size': '673159.19',
                              'Virtual': '137216'},
                             {'Address': '53186',
                              'Chi2': 'N/A',
                              'Entropy': 'N/A',
                              'MD5': 'N/A',
                              'Name': '.rdata',
                              'Raw': 'c19a0df2a18dc153259f078d105329f8',
                              'Size': '2110509.75',
                              'Virtual': '53248'},
                             {'Address': '8232',
                              'Chi2': 'N/A',
                              'Entropy': 'N/A',
                              'MD5': 'N/A',
                              'Name': '.data',
                              'Raw': 'cff8bfe7a1966b794ca460b80a41044a',
                              'Size': '362479.62',
                              'Virtual': '4096'},
                             {'Address': '556048',
                              'Chi2': 'N/A',
                              'Entropy': 'N/A',
                              'MD5': 'N/A',
                              'Name': '.bsp',
                              'Raw': 'd03a6b60175492721be46a3da3267690',
                              'Size': '392341.59',
                              'Virtual': '556544'},
                             {'Address': '480',
                              'Chi2': 'N/A',
                              'Entropy': 'N/A',
                              'MD5': 'N/A',
                              'Name': '.rsrc',
                              'Raw': '485e8ed8b860706f5089de5f4f806a30',
                              'Size': '9292',
                              'Virtual': '512'}]},
     'Imphash': ['35646f486d46399590ccfc4635584429',
                 'Rich PE header hash',
                 'da5bf9ef311ba6afcde2cd36c4b11e26'],
     'Imports': 'KERNEL32.dll',
     'Last Analysis': '2023-09-14 02:14:31 UTC',
     'Last Submission': '2023-09-14 02:14:31 UTC',
     'MD5': '4a77af71a8c9736e70b00ed57c0301b7',
     'Magic': 'PE32 executable (console) Intel 80386, for MS Windows',
     'SHA-1': 'fc8974e151296687a45f2f9cfd1d327edea5f98d',
     'SHA-256': 'da7f43a0af25d93cf194369d0fe96ce462d23e527156ffd3e6fcbb573bf3a857',
     'SSDEEP': '12288:lB//yfYb5BIQZVtbTBoW4A64QjBDsmy0CdcHs/2eOx73vD6TtTAXjjOLEVhuXo9Z:HiuBtZvBoWl64QhsN/PO1wcXfOLEDuuZ',
     'TLSH': 'T1AFF40112F1C54473E5B32D3609D8EAB42A3DF82007AD59EF1B980B6E4B752F1FA32951',
     'TrID': 'Win32 Executable MS Visual C++ (generic) (47.3%)   Win64 Executable '
             '(generic) (15.9%)',
     'Vhash': '075066655d1d75556az5-z'}


### Enhancing Robustness with Error Handling in Automation Scripts
Modern w web pag are dynamic with variable load times.sE elements can often change state or position, leading to challenges such as th`e StaleElementReferenceExcepti`on during automation tasks. This exception occurs when an element that a script interacts with has been altered or removed from the document object model (DOM) since it was last accessedWe handle these issues and look for the dynamic analysis tab.s.

`The find_and_click_behavior_` incorporatesting a retry mechanism, the function attempts to locate and click on the "Behavior" link within a web page. This method is particularly useful in scenarios where web page elements may not be immediately accessible or may change due to asynchronous content loading:


```python
from selenium.common.exceptions import StaleElementReferenceException
import time

def find_and_click_behavior_link(shadow, max_retries=3):
    retries = 0
    while retries < max_retries:
        try:
            beh_link = shadow.find_elements("a")
            for blink in beh_link:
                if blink.text.upper() == "BEHAVIOR":
                    print("FOUND")
                    blink.click()
                    return True  # Successfully clicked, exit function
        except StaleElementReferenceException:
            print("Encountered a stale element, retrying...")
            retries += 1
            time.sleep(3)  # Wait a bit for the DOM to stabilize

    print("Failed to click on the 'Behavior' link after retries.")
    return False  # Failed after retries

# Usage example
find_and_click_behavior_link(shadow)
```

    FOUND





    True



### Extracting Structured Data from Unstructured Text with Regex

This codeblock demonstrates a powerful technique for extracting structured information from unstructured text data using regular expressions (regex). It defines a function, 'extract_info_individual_patterns', which takes a block of text as input and searches for specific patterns to isolate and retrieve relevant data segments. This approach is particularly useful for parsing and analyzing text that follows a semi-structured format, such as logs, reports, or any document where information is systematically arranged but not in a format readily accessible by conventional data extraction tools.

The function employs a dictionary named 'patterns', where each key represents a category of information to extract, and the corresponding value is a regex pattern designed to match that information within the text. The regex patterns are crafted to capture text between known markers or headings, enabling the precise extraction of data segments like "HTTP Requests", "IP Traffic", "Files Written", and various other categories relevant to the text's context.

Upon finding a match for each pattern, the function stores the extracted data in a results dictionary, associating it with the appropriate category. If no match is found, it assigns 'None' to indicate the absence of data for that category. This method ensures that the output is a structured representation of the input text, making it easier to process and analyze further.

The usage of 're.search' with the 're.DOTALL' flag allows the '.' character in regex patterns to match newline characters as well, ensuring that multi-line text segments are fully captured without breaking the pattern. This feature is crucial for accurately extracting information from complex text structures.


```python
import re

def extract_info_individual_patterns(text):
    patterns = {
        "Matches rule": r"Matches rule (.*)HTTP Requests\n",
        "HTTP Requests": r"\nHTTP Requests\n(.*?)\nIP Traffic\n",
        "IP Traffic": r"\nIP Traffic\n(.*?)\nMemory Pattern Urls\n",
        "Memory Pattern Urls": r"\nMemory Pattern Urls\n(.*?)\nMemory Pattern Urls\n",
        "Memory Pattern IPs": r"\nMemory Pattern IPs\n(.*?)\nC2AE\n",
        "C2AE": r"\nC2AE\n(.*?)\n",
        "CAPA": r"CAPA\n(.*?)\n",
        "Microsoft Sysinternals": r"Microsoft Sysinternals\n(.*?)\n",
        "VenusEye Sandbox": r"VenusEye Sandbox\n(.*?)\n",
        "VirusTotal Jujubox": r"VirusTotal Jujubox\n(.*?)\n",
        "Zenbox": r"Zenbox\n(.*?)\n",
        "Files Written": r"\nFiles Written\n(.*)Files Deleted\n",
        "Files Deleted": r"\nFiles Deleted\n(.*)Files With Modified Attributes\n",
        "Files With Modified Attributes": r"Files With Modified Attributes\n(.*)Files Dropped\n",
        "Files Dropped": r"Files Dropped\n(.*)Registry Keys Opened\n",
        "Registry Keys Opened": r"\nRegistry Keys Opened\n(.*)Registry Keys Set\n", #nRegistry Keys Deleted
        "Registry Keys Set": r"\nRegistry Keys Set\n(.*)Registry Keys Deleted\n", # Processes Terminated
        "Registry Keys Deleted": r"\nRegistry Keys Deleted\n(.*)Processes Created\n", # Processes Terminated
        "Processes Terminated": r"\nProcesses Terminated\n(.*)Processes Tree\n", #Processes Tree
        "Processes Tree": r"\nProcesses Tree\n(.*)Mutexes Created\n", #Processes Tree
        "Mutexes Created":r"\nMutexes Created\n(.*)Mutexes Opened\n",
        "Mutexes Opened": r"\nMutexes Opened\n(.*)Signals Observed\n", #Mutexes Opened
        "Signals Observed": r"\nSignals Observed\n(.*)Signals Hooked\n", #Signals Observed
        "Signals Hooked": r"\nSignals Hooked\n(.*)Runtime Modules\n", #Signals Hooked
        "Runtime Modules": r"\nRuntime Modules\n(.*)Invoked Methods\n", #Runtime Modules
        "Cryptographical Algorithms Observed": r"\nCryptographical Algorithms Observed\n(.*)Cryptographical Keys Observed\n", #Cryptographical Algorithms Observed
        "Cryptographical Keys Observed": r"\nCryptographical Keys Observed\n(.*)Cryptographical Plain Text\n", #Cryptographical Keys Observed
        "Cryptographical Plain Text": r"\nCryptographical Plain Text\n(.*)Encoding Algorithms Observed\n", #Cryptographical Plain Text
        "Encoding Algorithms Observed": r"\nEncoding Algorithms Observed\n(.*)Decoded Text\n", #Encoding Algorithms Observed
        "Decoded Text": r"\nDecoded Text\n(.*)Highlighted Text\n", #Decoded Text
        "Highlighted Text": r"\nHighlighted Text\n(.*)System Property Lookups\n", #Highlighted Text
        "System Property Lookups": r"\nSystem Property Lookups\n(.*)System Property Sets\n", #System Property Lookups
        "System Property Sets": r"\nSystem Property Sets\n(.*)Shared Preferences Lookups\n", #System Property Sets
        "Shared Preferences Lookups": r"\nShared Preferences Lookups\n(.*)Shared Preferences Sets\n", #Shared Preferences Lookups
        "Shared Preferences Sets": r"\nShared Preferences Sets\n(.*)Content Model Observers\n", #Shared Preferences Sets
        "Content Model Observers": r"\nContent Model Observers\n(.*)Content Model Sets\n", #Content Model Observers
        "Content Model Sets": r"\nContent Model Sets\n(.*)Databases Opened\n", #Content Model Sets
        "Databases Opened": r"\nDatabases Opened\n(.*)Databases Deleted\n", #Databases Opened
        "Databases Deleted": r"\nDatabases Deleted\n(.*)" #Databases Deleted
    }
    
    results = {}
    for key, pattern in patterns.items():
        # Use re.DOTALL to make '.' match newlines as well
        match = re.search(pattern, text, re.DOTALL)
        if match:
            results[key] = match.group(1).strip()
        else:
            results[key] = None  # or '' if you prefer to store an empty string for no match
    
    return results

pprint.pprint(extract_info_individual_patterns(shadow.find_element("vt-ui-behaviour").text))
```

    {'C2AE': '9e411d62280afb7057d25590a6c82d7d',
     'CAPA': 'b0d7e654070f02a850859c7c07eed321',
     'Content Model Observers': '',
     'Content Model Sets': '',
     'Cryptographical Algorithms Observed': '',
     'Cryptographical Keys Observed': '',
     'Cryptographical Plain Text': '',
     'Databases Deleted': None,
     'Databases Opened': None,
     'Decoded Text': '{"C2 url": "77.91.124.82:19071", "Bot Id": "moner"}',
     'Encoding Algorithms Observed': '',
     'Files Deleted': '%USERPROFILE%\\AppData\\Local\\Temp\\4375vtb45tv8225nv4285n2.txt\n'
                      '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\o5013569.exe\n'
                      '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\y2116283.exe\n'
                      '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\m7744779.exe\n'
                      '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\n2165894.exe\n'
                      'C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER5455.tmp.WERInternalMetadata.xml\n'
                      'C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER5639.tmp.csv\n'
                      'C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER5669.tmp.txt\n'
                      'C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER816F.tmp.WERInternalMetadata.xml\n'
                      'C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER8181.tmp.csv',
     'Files Dropped': '',
     'Files With Modified Attributes': '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\o5013569.exe\n'
                                       '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\y2116283.exe\n'
                                       '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\m7744779.exe\n'
                                       '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\n2165894.exe',
     'Files Written': 'C:\\Users\\user\\AppData\\Local\\Microsoft\\CLR_v4.0_32\\UsageLogs\\n2165894.exe.log\n'
                      'C:\\Users\\user\\AppData\\Local\\Microsoft\\Windows\\History\n'
                      'C:\\Users\\user\\AppData\\Local\\Microsoft\\Windows\\INetCache\n'
                      'C:\\Users\\user\\AppData\\Local\\Microsoft\\Windows\\INetCookies\n'
                      'C:\\Users\\user\\AppData\\Local\\SystemCache\n'
                      'C:\\Users\\user\\AppData\\Local\\Temp\\4375vtb45tv8225nv4285n2.txt\n'
                      'C:\\Users\\user\\AppData\\Local\\Temp\\IXP000.TMP\n'
                      'C:\\Users\\user\\AppData\\Local\\Temp\\IXP000.TMP\\TMP4351$.TMP\n'
                      'C:\\Users\\user\\AppData\\Local\\Temp\\IXP000.TMP\\o5013569.exe\n'
                      'C:\\Users\\user\\AppData\\Local\\Temp\\IXP000.TMP\\y2116283.exe',
     'HTTP Requests': 'http://5.42.92.211/loghub/master',
     'Highlighted Text': 'da7f43a0af25d93cf194369d0fe96ce462d23e527156ffd3e6fcbb573bf3a857.exe',
     'IP Traffic': '192.229.211.108:80 (TCP)\n'
                   '20.99.133.109:443 (TCP)\n'
                   '20.99.184.37:443 (TCP)\n'
                   '5.42.92.211:80 (TCP)\n'
                   '77.91.124.82:19071 (TCP)\n'
                   'a83f:8110:8795:ffff:e00:0:0:0:53 (UDP)',
     'Matches rule': 'POLICY-OTHER HTTP request by IPv4 address attempt\n'
                     'Matches rule PROTOCOL-DNS squid proxy dns PTR record '
                     'response denial of service attempt\n'
                     'Matches rule MALWARE-CNC Win.Trojan.Redline variant outbound '
                     'request detected\n'
                     'Matches rule ET INFO Microsoft net.tcp Connection '
                     'Initialization Activity\n'
                     'Matches rule ET MALWARE Redline Stealer TCP CnC Activity\n'
                     'Matches rule ET MALWARE [ANY.RUN] RedLine Stealer Related '
                     '(MC-NMF Authorization)\n'
                     'Matches rule ET MALWARE Redline Stealer TCP CnC - '
                     'Id1Response\n'
                     'Matches rule ET MALWARE Redline Stealer Activity (Response)\n'
                     'Matches rule ET MALWARE [ANY.RUN] Win32/Stealc Checkin '
                     '(POST)\n'
                     'Matches rule ET HUNTING GENERIC SUSPICIOUS POST to Dotted '
                     'Quad with Fake Browser 1\n'
                     'See all',
     'Memory Pattern IPs': '77.91.124.82\n77.91.124.82:19071',
     'Memory Pattern Urls': None,
     'Microsoft Sysinternals': '0f10ff58165fb61f585fcf77c1f8486b',
     'Mutexes Created': '\\Sessions\\1\\BaseNamedObjects\\DBWinMutex\n'
                        '\\Sessions\\1\\BaseNamedObjects\\Global\\7307EA4058801080557736ffffffff',
     'Mutexes Opened': '',
     'Processes Terminated': '%CONHOST% '
                             '"-1274700196-564857691714262915989059378182664897-1280491350-675597650-1448166811\n'
                             '%SAMPLEPATH%\n'
                             '%SAMPLEPATH%\\da7f43a0af25d93cf194369d0fe96ce462d23e527156ffd3e6fcbb573bf3a857.exe\n'
                             '%TEMP%\\IXP000.TMP\\y2116283.exe\n'
                             '%TEMP%\\IXP001.TMP\\m7744779.exe\n'
                             '%TEMP%\\IXP001.TMP\\n2165894.exe\n'
                             '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\o5013569.exe\n'
                             '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\y2116283.exe\n'
                             '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\m7744779.exe\n'
                             '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\n2165894.exe',
     'Processes Tree': '1084 - %windir%\\system32\\wbem\\wmiprvse.exe\n'
                       '1092 - '
                       'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe\n'
                       '1116 - '
                       'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe\n'
                       '1136 - C:\\Windows\\System32\\wuapihost.exe\n'
                       '1260 - '
                       'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe\n'
                       '132 - '
                       'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe\n'
                       '1380 - '
                       'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe\n'
                       '1516 - '
                       'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe\n'
                       '1604 - '
                       'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe\n'
                       '1868 - '
                       'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe',
     'Registry Keys Deleted': 'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup0\n'
                              'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup1',
     'Registry Keys Opened': 'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\.NETFramework\\XML\n'
                             'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet '
                             'Settings\n'
                             'HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet '
                             'Settings\n'
                             'HKEY_CURRENT_USER\\Software\n'
                             'HKEY_CURRENT_USER\\Software\\Classes\\Local '
                             'Settings\n'
                             'HKEY_CURRENT_USER\\Software\\Microsoft\\.NETFramework\n'
                             'HKEY_CURRENT_USER\\Software\\Microsoft\\Avalon.Graphics\n'
                             'HKEY_CURRENT_USER\\Software\\Microsoft\\CTF\\DirectSwitchHotkeys\n'
                             'HKEY_CURRENT_USER\\Software\\Microsoft\\Fusion\n'
                             'HKEY_CURRENT_USER\\Software\\Microsoft\\Internet '
                             'Explorer\\Download',
     'Registry Keys Set': 'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup0\n'
                          'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup1\n'
                          'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup0\n'
                          'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup1\n'
                          'HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup0\n'
                          'HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup1\n'
                          'HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet '
                          'Settings\\Connections\\SavedLegacySettings\n'
                          'HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet '
                          'Settings\\ProxyEnable\n'
                          'HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet '
                          'Settings\\ProxyServer',
     'Runtime Modules': '%SAMPLEPATH%\\da7f43a0af25d93cf194369d0fe96ce462d23e527156ffd3e6fcbb573bf3a857.exe\n'
                        '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\o5013569.exe\n'
                        '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\y2116283.exe\n'
                        '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\m7744779.exe\n'
                        '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\n2165894.exe\n'
                        'C:\\Windows\\SysWOW64\\wbem\\wmiutils.dll\n'
                        'KERNELBASE.dll\n'
                        'api-ms-win-appmodel-runtime-l1-1-2\n'
                        'api-ms-win-core-datetime-l1-1-1\n'
                        'api-ms-win-core-fibers-l1-1-0',
     'Shared Preferences Lookups': '',
     'Shared Preferences Sets': '',
     'Signals Hooked': '',
     'Signals Observed': '',
     'System Property Lookups': 'IWbemServices::Connect\n'
                                'IWbemServices::ExecQuery - ROOT\\SecurityCenter : '
                                'SELECT * FROM AntiSpyWareProduct\n'
                                'IWbemServices::ExecQuery - ROOT\\SecurityCenter : '
                                'SELECT * FROM AntivirusProduct\n'
                                'IWbemServices::ExecQuery - ROOT\\SecurityCenter : '
                                'SELECT * FROM FirewallProduct\n'
                                'IWbemServices::ExecQuery - ROOT\\SecurityCenter2 '
                                ': SELECT * FROM AntiSpyWareProduct\n'
                                'IWbemServices::ExecQuery - ROOT\\SecurityCenter2 '
                                ': SELECT * FROM AntivirusProduct\n'
                                'IWbemServices::ExecQuery - ROOT\\SecurityCenter2 '
                                ': SELECT * FROM FirewallProduct\n'
                                'IWbemServices::ExecQuery - root\\CIMV2 : SELECT * '
                                'FROM Win32_VideoController\n'
                                'IWbemServices::ExecQuery - root\\cimv2 : SELECT * '
                                'FROM Win32_DiskDrive\n'
                                'IWbemServices::ExecQuery - root\\cimv2 : SELECT * '
                                'FROM Win32_OperatingSystem',
     'System Property Sets': '',
     'VenusEye Sandbox': '8ea95b738d8b5e0d0d146ba224872ccf',
     'VirusTotal Jujubox': 'ed7708f3cc219e5cdec1055af74aab3d',
     'Zenbox': '99781b89f28ecc67f023329f5df6a771'}


### Simplifying and Cleaning Data Extraction from Text Elements

This snippet demonstrates a straightforward approach for processing and cleaning text data extracted from a web element using Selenium. 

1. **Extract Text Data**: Initially, the text content of a web element, identified by "vt-ui-expandable", is retrieved. This element is expected to contain a list of tags or keywords, each on a new line.

2. **Split Text into List**: The '.split('\n')' method is applied to divide the text into a list, where each list item corresponds to a line of text from the original content. This step converts the block of text into a more manageable list format.

3. **Refine and Clean List Items**: The list comprehension '[element.replace(" ", "") for element in tags.split("\n") if element.strip()]' serves multiple purposes:
   - It iterates over each line obtained from the split operation.
   - Uses '.strip()' to remove leading and trailing whitespace from each line, ensuring that only non-empty lines are considered.
   - Applies '.replace(" ", "")' to each line to remove all spaces, ensuring that the tags are cleaned of any internal whitespace. 


```python
tags = shadow.find_element("vt-ui-expandable").text
tags.split('\n')
tags_split_and_stripped = [element.replace(" ", "") for element in tags.split("\n") if element.strip()]
tags_split_and_stripped
```




    ['calls-wmi',
     'checks-disk-space',
     'checks-user-input',
     'detect-debug-environment',
     'long-sleeps',
     'persistence']



### Extracting and Structuring Sandbox Verdicts from Web Elements.

1. **Extract Text Data**: The text is retrieved from a web element identified by "vt-ui-sandbox-verdicts". This element is expected to contain verdicts from various sandbox environments, each verdict on a new line.

2. **Split Text into List**: By applying the `.split('\n')` method, the text is divided into a list where each item corresponds to a verdict from a different sandbox analysis. This step transforms the continuous text block into a structured list format, making it easier to iterate over and analyze each sandbox's verdict.

3. **List Content and Interpretation**: The resulting list contains strings where each string represents a sandbox's verdict on the analyzed file. For example:
   - `"The sandbox Zenbox flags this file as: MALWARE STEALER TROJAN EVADER"` indicates that the Zenbox sandbox has identified the file as malware with specific characteristics: it acts as a stealer, trojan, and has evasion capabilities.
   - `"The sandbox C2AE flags this file as: STEALER"` shows that the C2AE sandbox specifically flags the file for its data-stealing capied threats.


```python
tags = shadow.find_element("vt-ui-sandbox-verdicts").text
tags = tags.split('\n')
tags

```




    ['The sandbox Zenbox flags this file as: MALWARE STEALER TROJAN EVADER',
     'The sandbox C2AE flags this file as: STEALER']



### Extracting MITRE ATT&CK Framework Tactics and Techniques.

1. **Retrieve Text Data**: The text from a web element identified by "vt-ui-mitre-tree" is retrieved. This element is expected to contain a list of MITRE ATT&CK tactics and techniques, structured in a hierarchical format.

2. **Split Text into List**: By applying `.split('\n')`, the text block is divided into a list where each item corresponds to a line of text.

3. **Resulting List**: The final list, `tags`, pr  clear, line-by-line enumeration of the tactics and techniques as they were listed in the text content of the web element. This list starts with a title 'MITRE ATT&CK Tactics and Techniques' followed by pairs of tactic names and their respective identification codes (e.g., 'Execution', 'T  This should be enhanced to be built into a dict similar to the "Sections" function shown earlier.y efforts.


```python
#vt-ui-mitre-tree
tags = shadow.find_element("vt-ui-mitre-tree").text
tags = tags.split('\n')
tags
```




    ['MITRE ATT&CK Tactics and Techniques',
     'Execution',
     'TA0002',
     'Persistence',
     'TA0003',
     'Privilege Escalation',
     'TA0004',
     'Defense Evasion',
     'TA0005',
     'Credential Access',
     'TA0006',
     'Discovery',
     'TA0007',
     'Collection',
     'TA0009',
     'Command and Control',
     'TA0011']



### Parsing CAPA Signature Matches.

1. **Retrieve Text Data**: The first line retrieves text from a web element identified by `"vt-ui-capa-signature-matches"`. This element contains CAPA signature matches that describe various characteristics or actions related to the analyzed file.

2. **Split Text into List**: The `.split('\n')` method is used to divide the retrieved text into a list, with each element representing a line from the original text. This step is essential for isolating individual CAPA signatures.

3. **Resulting List**: The output, `tags`, is a list of strings where each string represents a CAPA signature match. The list includes signatures such as 'Data-Manipulation', 'Linking', 'Host-Interaction', 'Load-Code', and 'Executable'. Each of these signatures provides insight into the actions or characteristics identified in the analyzed file, which can be critical for detailed malware analysis and threat intelous files.


```python
tags = shadow.find_element("vt-ui-capa-signature-matches").text
tags = tags.split('\n')
tags
```




    ['Data-Manipulation', 'Linking', 'Host-Interaction', 'Load-Code', 'Executable']



### Extracting Sigma Analysis Results.

1. **Retrieve Sigma Analysis Text**: Initially, the text content is retrieved from a web element identified by `"vt-ui-sigma-analysis"`. This element is expected to contain Sigma analysis results, including severity levels and matches against specific Sigma rules.

2. **Split Text into Lines**: The retrieved text is split into a list where each element corresponds to a line of the original text. This split operation facilitates the isolation and enumeration of individual Sigma analysis entries.

3. **Parsed Result**: The final list, `tags`, contains entries that represent the analysis results. It includes severity levels (CRITICAL, HIGH, MEDIUM, LOW) with their respective counts, followed by detailed descriptions of Sigma rule iperations.


```python
tags = shadow.find_element("vt-ui-sigma-analysis").text
tags = tags.split('\n')
tags
```




    ['CRITICAL 0',
     'HIGH 0',
     'MEDIUM 1',
     'LOW 1',
     'Matches rule Wow6432Node CurrentVersion Autorun Keys Modification by Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)',
     'Matches rule Creation of an Executable by an Executable by frack113']



### Parsing Intrusion Detection System Alerts.

1. **Retrieve IDS Alerts Text**: Initially, the text content, which comprises various IDS alerts, is fetched from a specific web element identified by `"vt-ui-ids-alerts"`. This element is presumed to contain a list of IDS alert descriptions.

2. **Split Text into Individual Alerts**: The extracted text is then split line by line, transforming it into a list where each element represents a distinct IDS alert. This operation facilitates the analysis of each alert separately.

3. **Parsed Alerts List**: The resulting list, `tags`, encapsulates individual IDS alerts, each described by the rule it matches. These descriptions include the type of activity detected (e.g., policy violations, malware communications, protocol anomalies) and specific identifiers like malware names or suspicious behavior p
   on System.


```python
tags = shadow.find_element("vt-ui-ids-alerts").text
tags = tags.split('\n')
tags

```




    ['Matches rule POLICY-OTHER HTTP request by IPv4 address attempt',
     'Matches rule PROTOCOL-DNS squid proxy dns PTR record response denial of service attempt',
     'Matches rule MALWARE-CNC Win.Trojan.Redline variant outbound request detected',
     'Matches rule ET INFO Microsoft net.tcp Connection Initialization Activity',
     'Matches rule ET MALWARE Redline Stealer TCP CnC Activity',
     'Matches rule ET MALWARE [ANY.RUN] RedLine Stealer Related (MC-NMF Authorization)',
     'Matches rule ET MALWARE Redline Stealer TCP CnC - Id1Response',
     'Matches rule ET MALWARE Redline Stealer Activity (Response)',
     'Matches rule ET MALWARE [ANY.RUN] Win32/Stealc Checkin (POST)',
     'Matches rule ET HUNTING GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 1',
     'See all']






```python
tags = shadow.find_element("network-communication").text
tags = tags.split('\n')
tags

```




    ['HTTP Requests',
     'http://5.42.92.211/loghub/master',
     'IP Traffic',
     '192.229.211.108:80 (TCP)',
     '20.99.133.109:443 (TCP)',
     '20.99.184.37:443 (TCP)',
     '5.42.92.211:80 (TCP)',
     '77.91.124.82:19071 (TCP)',
     'a83f:8110:8795:ffff:e00:0:0:0:53 (UDP)',
     'Memory Pattern Urls',
     'http://77.91.124.82:19071',
     'tcp://77.91.124.82:19071',
     'Memory Pattern IPs',
     '77.91.124.82',
     '77.91.124.82:19071']



### Analyzing File System Actions

The provided code snippet and its output detail a series of file system actions performed by an application or process. This data is crucial for understanding how a specific piece of software interacts with the file system, which can be particularly relevant in the context of malware analysis, forensic investigations, or general security assessments. Let's break down the types of actions reported
1. **Files Opened**: This section lists the files accessed by the application. It includes executable files for popular web browsers (Firefox, Chrome, Internet Explorer) and specific Windows Defender DLL files. Accessing these files could indicate normal operations, such as web browsing or checking for antivirus updates, but in a malicious context, it might suggest attempts to bypass security measures or monitor user activity.

2. **Files Written**: Details files created or modified by the process. This includes logs, cache files, cookies, and temporary files, some of which are executables. Writing to these locations is common for applications to store data, but malicious software may also create or modify files in these directories to execute payloads, store harvested data, or maintain persistence on a system.

3. **Files Deleted**: Lists files removed by the application. Deleting files, especially executables in temporary folders or system logs, can be a tactic used by malicious software to cover its tracks and reduce the chances of detection or forensic analysis.

4. **Files With Modified Attributes**: This action indicates the modification of file properties, which could be used by software for various legitimate purposes, such as updating file status or permissions. However, in the context of malware, changing file attributes can be a method to hide malicious files (making them hidden or system files) or alter their execution behavior.

5. **Files Dropped**: While not detailed in the output, this category would typically list files that the application has placed on the system, which could include additional payloads, configuration files, or tools needed by the software to perform its intended or malicious functions.



```python
tags = shadow.find_element("file-system-actions").text
tags = tags.split('\n')
tags
```




    ['Files Opened',
     'C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe',
     'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
     'C:\\Program Files\\Internet Explorer\\en-US\\iexplore.exe.mui',
     'C:\\Program Files\\Internet Explorer\\iexplore.exe',
     'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2102.4-0\\MsMpLics.dll',
     'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2102.4-0\\X86\\MPCLIENT.DLL',
     'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2102.4-0\\X86\\MpOav.dll',
     'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2102.4-0\\X86\\MsMpLics.dll',
     'C:\\Users\\user\\AppData\\Local\\360Browser\\Browser\\User Data\\',
     'C:\\Users\\user\\AppData\\Local\\7Star\\7Star\\User Data\\',
     'Files Written',
     'C:\\Users\\user\\AppData\\Local\\Microsoft\\CLR_v4.0_32\\UsageLogs\\n2165894.exe.log',
     'C:\\Users\\user\\AppData\\Local\\Microsoft\\Windows\\History',
     'C:\\Users\\user\\AppData\\Local\\Microsoft\\Windows\\INetCache',
     'C:\\Users\\user\\AppData\\Local\\Microsoft\\Windows\\INetCookies',
     'C:\\Users\\user\\AppData\\Local\\SystemCache',
     'C:\\Users\\user\\AppData\\Local\\Temp\\4375vtb45tv8225nv4285n2.txt',
     'C:\\Users\\user\\AppData\\Local\\Temp\\IXP000.TMP',
     'C:\\Users\\user\\AppData\\Local\\Temp\\IXP000.TMP\\TMP4351$.TMP',
     'C:\\Users\\user\\AppData\\Local\\Temp\\IXP000.TMP\\o5013569.exe',
     'C:\\Users\\user\\AppData\\Local\\Temp\\IXP000.TMP\\y2116283.exe',
     'Files Deleted',
     '%USERPROFILE%\\AppData\\Local\\Temp\\4375vtb45tv8225nv4285n2.txt',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\o5013569.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\y2116283.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\m7744779.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\n2165894.exe',
     'C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER5455.tmp.WERInternalMetadata.xml',
     'C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER5639.tmp.csv',
     'C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER5669.tmp.txt',
     'C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER816F.tmp.WERInternalMetadata.xml',
     'C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER8181.tmp.csv',
     'Files With Modified Attributes',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\o5013569.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\y2116283.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\m7744779.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\n2165894.exe',
     'Files Dropped']



### Understanding Registry Actions in Application Behavior.

1. **Registry Keys Opened**: This section lists registry keys that the application has accessed but not necessarily modified. Access to certain keys, such as those related to internet settings or .NETFramework, can be legitimate for applications requiring configuration information. However, frequent or unusual access might signal attempts to gather information or change settings without user consent.

2. **Registry Keys Set**: Indicates registry keys that have been created or modified by the application. The presence of multiple entries related to `RunOnce` suggests attempts to execute additional software automatically after a reboot, a common technique for ensuring malware persistence or completing installation processes. Modifications to internet settings and proxy configurations can also indicate efforts to redirect internet traffic or mask network communications.

3. **Registry Keys Deleted**: Lists registry entries that the application has removed. Deleting `RunOnce` keys after they have been used is a technique to clean up traces of an installation or persistence mechanism, often seen in both legitimate software setups and malicious payloads to avoid detection or avelopment.


```python
tags = shadow.find_element("registry-actions").text
tags = tags.split('\n')
tags
```




    ['Registry Keys Opened',
     'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\.NETFramework\\XML',
     'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
     'HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
     'HKEY_CURRENT_USER\\Software',
     'HKEY_CURRENT_USER\\Software\\Classes\\Local Settings',
     'HKEY_CURRENT_USER\\Software\\Microsoft\\.NETFramework',
     'HKEY_CURRENT_USER\\Software\\Microsoft\\Avalon.Graphics',
     'HKEY_CURRENT_USER\\Software\\Microsoft\\CTF\\DirectSwitchHotkeys',
     'HKEY_CURRENT_USER\\Software\\Microsoft\\Fusion',
     'HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Download',
     'Registry Keys Set',
     'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup0',
     'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup1',
     'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup0',
     'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup1',
     'HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup0',
     'HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup1',
     'HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections\\SavedLegacySettings',
     'HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyEnable',
     'HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer',
     'Registry Keys Deleted',
     'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup0',
     'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\wextract_cleanup1']



### Analyzing Process and Service Actions.

1. **Processes Created**: Lists executable paths for processes initiated by the application. Notably, several processes originate from temporary directories (`%USERPROFILE%\\AppData\\Local\\Temp`) and the .NET Framework directory. Processes launched from temporary locations often raise security concerns, as this is a common tactic used by malware to execute payloads discretely.

2. **Shell Commands**: Details commands executed via the shell, including paths to executables similar to those listed under processes created. This section provides insight into the specific actions an application or script is performing, which can include launching additional software, modifying system settings, or executing malicious activities.

3. **Processes Terminated**: Enumerates processes that have been stopped or killed. Terminating processes, especially those related to system or security functions, can be a red flag for malicious behavior intended to evade detection, disable security measures, or interrupt system operations.

4. **Processes Tree**: Provides a hierarchical view of process relationships, showing parent and child processes. This information is valuable for understanding how processes are related and can help in identifying root processes responsible for initiating a chain of potentially malicious aied threats.


```python
tags = shadow.find_element("process-and-service-actions").text
tags = tags.split('\n')
tags
```




    ['Processes Created',
     '%SAMPLEPATH%\\da7f43a0af25d93cf194369d0fe96ce462d23e527156ffd3e6fcbb573bf3a857.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\o5013569.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\y2116283.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\m7744779.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\n2165894.exe',
     'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe',
     'C:\\Windows\\System32\\wuapihost.exe',
     'Shell Commands',
     '"%SAMPLEPATH%\\da7f43a0af25d93cf194369d0fe96ce462d23e527156ffd3e6fcbb573bf3a857.exe"',
     '"C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe"',
     '%SAMPLEPATH%',
     '%TEMP%\\IXP000.TMP\\y2116283.exe',
     '%TEMP%\\IXP001.TMP\\m7744779.exe',
     '%TEMP%\\IXP001.TMP\\n2165894.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\o5013569.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\y2116283.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\m7744779.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\n2165894.exe',
     'Processes Terminated',
     '%CONHOST% "-1274700196-564857691714262915989059378182664897-1280491350-675597650-1448166811',
     '%SAMPLEPATH%',
     '%SAMPLEPATH%\\da7f43a0af25d93cf194369d0fe96ce462d23e527156ffd3e6fcbb573bf3a857.exe',
     '%TEMP%\\IXP000.TMP\\y2116283.exe',
     '%TEMP%\\IXP001.TMP\\m7744779.exe',
     '%TEMP%\\IXP001.TMP\\n2165894.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\o5013569.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP000.TMP\\y2116283.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\m7744779.exe',
     '%USERPROFILE%\\AppData\\Local\\Temp\\IXP001.TMP\\n2165894.exe',
     'Processes Tree',
     '1084 - %windir%\\system32\\wbem\\wmiprvse.exe',
     '1092 - C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe',
     '1116 - C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe',
     '1136 - C:\\Windows\\System32\\wuapihost.exe',
     '1260 - C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe',
     '132 - C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe',
     '1380 - C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe',
     '1516 - C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe',
     '1604 - C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe',
     '1868 - C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe']


