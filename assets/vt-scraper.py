import argparse
import csv
import json
import os
import pprint
import random
import re
import time
from typing import List, Dict

from bs4 import BeautifulSoup
from pyshadow.main import Shadow
from selenium import webdriver
from selenium.common.exceptions import ElementNotVisibleException, NoSuchElementException, StaleElementReferenceException
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager


def parse_section_details(section_lines: List[str]) -> List[Dict[str, str]]:
    """
    Parses a list of strings representing section lines into a list of dictionaries.
    
    Each dictionary represents a section, with keys derived from the headers in the first line,
    and values from the subsequent lines. Missing values are filled with 'N/A'.
    
    Args:
        section_lines (List[str]): A list of strings, where the first string contains headers 
                                   separated by spaces and the subsequent strings contain values 
                                   separated by spaces.

    Returns:
        List[Dict[str, str]]: A list of dictionaries where each dictionary maps headers to their 
                              corresponding values for that section. If a line has fewer values than 
                              headers, 'N/A' is used as the value for missing headers.
    """
    sections = []
    if not section_lines:
        return sections  # Early return for empty input

    headers = section_lines[0].split()  # Extract headers from the first line
    for line in section_lines[1:]:  # Process each line after the headers
        values = line.split()
        # Fill missing values with 'N/A'
        values.extend(['N/A'] * (len(headers) - len(values)))
        # Pair headers with values using zip and create a dictionary
        section = dict(zip(headers, values))
        sections.append(section)

    return sections

def parse_vt_ui_file_details_text(text):
    """
    Parses the detailed text from a VirusTotal UI file analysis report into a structured dictionary.
    
    This function extracts information related to various file characteristics such as hashes (MD5, SHA-1, SHA-256, etc.),
    file type, magic, size, and other specific metadata that might be present in a VirusTotal report text. It organizes
    this data into a dictionary where each key represents a category (e.g., "MD5", "File type"), and the associated value
    is either a string (for single line values) or a list (for multi-line values). Special handling is applied to the
    "Header" section, which is parsed into a more structured sub-dictionary including "Info" and "Sections" keys.
    
    Args:
    - text (str): A string containing the raw text of a file details section from VirusTotal's UI.
    
    Returns:
    - dict: A dictionary where each key is a category from the VirusTotal report, and the value is the extracted information
      for that category. For most categories, this will be a simple string or a list of strings. For the "Header" category,
      the value is a dictionary with "Info" (containing general header information) and "Sections" (containing parsed
      section details).
    
    Example of use:
    text = "MD5\n123456789abcdef\nSHA-1\nabcdef123456789\nFile type\nexecutable\n..."
    parsed_data = parse_vt_ui_file_details_text(text)
    """

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

def find_and_click_behavior_link(shadow, max_retries=3):
    """
    Attempts to find and click the "Behavior" link within a shadow DOM element, with a specified number of retries.

    This function iterates over all anchor elements within a shadow DOM, attempting to find the one with the text "BEHAVIOR".
    If found, it attempts to click on this link. If the link is not immediately clickable due to the element being stale
    (e.g., the DOM is updating), it retries up to a specified maximum number of retries, with a delay between each attempt
    to allow the DOM to stabilize.

    Parameters:
    - shadow: The shadow DOM element to search within for the "Behavior" link.
    - max_retries (int, optional): The maximum number of retries if the first attempt fails due to a stale element. Defaults to 3.

    Returns:
    - bool: True if the "Behavior" link was successfully found and clicked, False otherwise.

    Example of use:
    shadow = driver.execute_script('return document.querySelector("my-element").shadowRoot')
    if find_and_click_behavior_link(shadow):
        print("Successfully clicked on the 'Behavior' link.")
    else:
        print("Failed to find or click on the 'Behavior' link.")
    """
    retries = 0
    while retries < max_retries:
        try:
            beh_link = shadow.find_elements("a")
            for blink in beh_link:
                #print(blink.text.upper())
                if blink.text.upper() == "BEHAVIOR":
                    print("FOUND")
                    blink.click()
                    return True  # Successfully clicked, exit function
                
        except StaleElementReferenceException:
            print("Encountered a stale element, retrying...")
            retries += 1
            exit()
            time.sleep(3)  # Wait a bit for the DOM to stabilize
        time.sleep(3)  # Wait a bit for the DOM to stabilize
        print("Retrying...")
        retries += 1


    print("Failed to click on the 'Behavior' link after retries.")
    return False  # Failed after retries


def setup_driver(headless=True):
    """
    Configures and initializes a Selenium WebDriver with Chrome, optionally running headless.

    This function sets up a Selenium WebDriver for Chrome with specific options to optimize performance and compatibility
    in automated or headless environments. It suppresses unnecessary logging, enables running without a GUI (if headless),
    and applies other configurations to avoid common issues in containerized or resource-restricted environments. It also
    initializes an instance of `Shadow`, which is presumably a utility for interacting with shadow DOM elements, though
    it's not defined within this code snippet.

    Parameters:
    - headless (bool, optional): Determines whether the Chrome driver should run in headless mode, without a GUI.
      Defaults to True.

    Returns:
    - tuple: A tuple containing the initialized `Shadow` object and the `webdriver.Chrome` instance.

    Usage:
    shadow, driver = setup_driver(headless=True)
    """
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])  # Suppresses DevTools listening on ws...

    if headless:
        chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--log-level=3')  # Suppresses most console logs, higher numbers suppress more
    service = Service(ChromeDriverManager().install(), service_log_path=os.devnull)
    driver = webdriver.Chrome(service=service, options=chrome_options)
    shadow = Shadow(driver)
    return shadow, driver


def process_csv(csv_path, shadow, driver):
    """
    Processes each row in a CSV file, assuming each row contains a hash value as its first element. For each hash,
    it checks if a corresponding JSON file already exists in a 'browser_dump' directory. If not, it processes the hash
    using a provided `process_hash` function (not defined in this snippet) that presumably interacts with a web page
    using Selenium and potentially shadow DOM elements.

    Parameters:
    - csv_path (str): The file path to the CSV file to be processed.
    - shadow: A shadow DOM handling utility or object associated with the web driver.
    - driver: The Selenium WebDriver instance being used for web interactions.

    Notes:
    The function uses a random delay between processing of each hash to reduce the risk of being detected as a bot
    by the target website. It assumes the existence of a `process_hash` function which takes a hash value, a shadow DOM
    object, and a Selenium WebDriver instance to perform specific actions on a web page.
    """
    with open(csv_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row:  # Check if row is not empty
                target_hash = row[0]  # Extract target_hash from the row
                file_path = f'browser_dump/{target_hash}.json'  # Define the file path for the current hash
                
                # Check if the file already exists
                if os.path.exists(file_path):
                    print(f"File for hash {target_hash} already exists. Skipping...")
                    continue  # Skip to the next row (hash) if the file already exists
                
                time.sleep(random.randint(3, 9))  # Add a random delay before processing the next hash
                process_hash(target_hash, shadow, driver)  # Process the hash

def save_report(target_hash, file_details):
    """
    Saves the file details dictionary for a given target hash as a JSON file in a specified directory.

    This function ensures the directory 'browser_dump' exists and then writes the details contained in
    the 'file_details' dictionary to a JSON file named after the target hash. The JSON file is formatted
    with an indentation of 4 spaces for readability.

    Parameters:
    - target_hash (str): The hash value of the target file. This value is used to name the output JSON file.
    - file_details (dict): A dictionary containing details about the file that need to be saved.

    Example usage:
    target_hash = "123abc"
    file_details = {"MD5": "123abc", "SHA-1": "456def"}
    save_report(target_hash, file_details)
    """
    # Ensure the directory exists
    os.makedirs('browser_dump', exist_ok=True)            
    # Dumping the file_details dict to a JSON file
    # Define the file path
    file_path = f'browser_dump/{target_hash}.json'
    with open(file_path, 'w') as json_file:
        json.dump(file_details, json_file, indent=4)


def extract_info_individual_patterns(text):
    """
    Extracts specific sections of information from a given text based on predefined regular expression patterns.
    Each pattern corresponds to a different section within the text, such as "HTTP Requests", "IP Traffic",
    "Memory Pattern Urls", etc. The function applies these patterns to the input text, capturing the content
    of each section if present.

    Parameters:
    - text (str): The input text from which information is to be extracted.

    Returns:
    - dict: A dictionary where each key is the name of a section (e.g., "HTTP Requests") and the corresponding
      value is the extracted text for that section. If a section is not found in the input text, its value
      will be None.

    Note:
    This function is designed to process a very specific format of text, likely related to malware analysis
    or similar fields. The regular expressions are tailored to capture sections separated by specific headings
    and are sensitive to the exact structure of the input text.
    """
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

def get_vt_file_details(target_hash, shadow, driver, retries=30, sleep_time=120):
    """
    Attempts to retrieve file details from VirusTotal for a given target hash, with retries on failure.

    This function navigates to the VirusTotal details page for the specified hash using a Selenium WebDriver. It tries
    to extract the file details text from a 'vt-ui-file-details' element within a shadow DOM (handled by a provided
    shadow utility object). If the element is not immediately available or if any error occurs, it retries the operation,
    with a specified delay between attempts.

    Parameters:
    - target_hash (str): The hash of the file for which details are to be retrieved from VirusTotal.
    - shadow: A utility object for handling interactions with shadow DOM elements.
    - driver: The Selenium WebDriver instance used to navigate and interact with web pages.
    - retries (int, optional): The maximum number of attempts to retrieve the file details. Defaults to 30.
    - sleep_time (int, optional): The time to wait between retries in seconds. Defaults to 120.

    Returns:
    - dict: A dictionary containing the parsed file details if successful; otherwise, an empty dictionary.

    Note:
    - The function relies on 'parse_vt_ui_file_details_text', a separate function that must be defined elsewhere,
      to parse the retrieved file details text into a structured dictionary.
    - The function uses randomized sleep durations between retries to mimic human behavior and potentially avoid detection.
    """

    details_url = f"https://www.virustotal.com/gui/file/{target_hash}/details"
    for attempt in range(retries):
        try:
            print(f"Attempt {attempt+1}: Getting details from {details_url}")
            driver.get(details_url)
            time.sleep(random.randint(3, 14))  # Wait for page elements to load
            
            # Attempt to find and parse the file details
            file_details_text = shadow.find_element("vt-ui-file-details").text
            file_details = parse_vt_ui_file_details_text(file_details_text)            
            return file_details

        except (NoSuchElementException, ElementNotVisibleException) as e:
            print(f"Error encountered: {e}. Retrying after {sleep_time} seconds...")
            time.sleep(sleep_time)
    
    print("Failed to retrieve file details after multiple attempts.")
    return {}

def process_hash(target_hash, shadow, driver):
    """
    Processes a given hash by retrieving its file details and behavior analysis from VirusTotal.

    This function first attempts to retrieve the file details for the specified hash using the
    `get_vt_file_details` function. If successful, it prints the file details and attempts to navigate
    to the behavior analysis section of the VirusTotal page for further information. It then combines
    these file details with the behavior analysis into a single report and saves this report using the
    `save_report` function. If the behavior analysis section is not visible or accessible, it saves
    only the file details.

    Parameters:
    - target_hash (str): The hash of the file to be processed.
    - shadow: A utility object for handling interactions with shadow DOM elements.
    - driver: The Selenium WebDriver instance used to navigate and interact with web pages.

    Note:
    - This function relies on several other functions (`get_vt_file_details`, `find_and_click_behavior_link`,
      `extract_info_individual_patterns`, `save_report`) which must be defined elsewhere in the codebase.
    - A delay is included at the end of the function to ensure that all elements have loaded before proceeding.
    """
    file_details = get_vt_file_details(target_hash, shadow, driver)
    print(f"File details for {target_hash}:")
    print(json.dumps(file_details, indent=4))
    if file_details == {}:
        print(f"Failed to retrieve file details for {target_hash}. Skipping...")
        return
    else:
        try:
            find_and_click_behavior_link(shadow)        
            beh_text = shadow.find_element("vt-ui-behaviour").text
            beh_dict = extract_info_individual_patterns(beh_text)
            combined_details = {**beh_dict, **file_details}
            #pprint.pprint(combined_details)
            save_report(target_hash, combined_details)
        except ElementNotVisibleException as e:
            print(f"Error encountered: {e}. Saving one...")
            save_report(target_hash, file_details)
            return


    
    # parse_behavior(shadow)
    time.sleep(5)  # Wait for page elements to load


def main():
    parser = argparse.ArgumentParser(description='Scrape and parse details from VirusTotal.')
    parser.add_argument('--hash', help='Target hash for scraping')
    parser.add_argument('--csv', help='Path to CSV file containing hashes in the first column')
    args = parser.parse_args()
    shadow, driver = setup_driver()

    if args.csv:
        process_csv(args.csv, shadow, driver)
    elif args.hash:
        process_hash(args.hash, shadow, driver)
    else:
        print("Please provide a target hash or a CSV file path.")

if __name__ == "__main__":
    main()
