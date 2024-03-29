---
layout: research
title: Formulating a Knowledge Network from Malware Analysis Reports
---

<img src="/assets/MWKG_banner_single.png" style="width:100%; height: auto;">

*Illustration of a knowledge network constructed from malware reports*
Explore the interactive network here: https://rau.richards.ai/mwkg/mw_reports_test_index.html

To see a much larger graph for vidar ransomware that includes information collected from 27 unique documents check out  (prepare to wait 10+ min for graph to compose):
<img src="/assets/MWKG_banner.png" style="width:100%;">

<a href="https://rau.richards.ai/mwkg/vidar_reports_mistral7b.html">Cybersecurity Knowledge Network Visualization</a>

<a href="https://rau.richards.ai/mwkg/vidar_reports_index_yi34b.html">The same large graph created with Yi-34b as the extraction model</a>



## The Role of Knowledge Graphs in Cybersecurity Analysis
A knowledge graph in the field of cybersecurity is an intricate map of cyber threats, including malware families, threat actors, and their campaigns. It serves to elucidate the complex web of connections among various cybersecurity threats and their characteristics. Stored and managed within graph databases, these networks facilitate advanced analysis, including the discovery (prediction) of new connections.

## Generating a Knowledge Graph from Malware Reports
1. Refine the corpus of malware reports to eliminate noise.
2. Detect and categorize cybersecurity concepts, threat actors, and malware families.
3. Uncover and map the relationships between these entities.
4. Construct a graph schema to accurately model these interactions.
5. Populate the graph with nodes representing the entities and edges denoting their relationships.
6. Visualize the graph to enable analyst exploration of the data.

The visualization step, while discretionary, offers significant analytical value, presenting the data in a form that highlights relationships and patterns not immediately apparent in textual form.

## Advantages of Graphs in Malware Relationship Analysis
Employing a knowledge graph for malware analysis serves multiple strategic functions. It enables the identification of connections between malware families, drawing parallels and distinguishing traits that can be crucial for threat intelligence. Furthermore, it links threat actors to their respective malware and campaigns, offering insights into the tactics, techniques, and procedures (TTPs) employed.

Through **Graph Retrieval Augmented Generation (GRAG)**, analysts can delve deeper into the data, surpassing traditional **Retrieval Augmented Generation (RAG)** methods by utilizing the graph as a dynamic retrieval tool.

---

## Project Synopsis
This initiative focuses on the creation of a comprehensive knowledge graph from detailed malware analysis reports. This graph not only categorizes malware instances but also connects them to related threat actors and campaigns, revealing the broader narrative of cyber threats.

The process begins with the segmentation of the reports' text. Each segment undergoes a meticulous examination to extract and link cybersecurity concepts, utilizing a language model tailored for cybersecurity lexicon.

It's posited that concepts detailed in close textual proximity signify an inherent relationship. Each connection in the graph signifies a segment of text where related concepts, actors, or malware families are mentioned together.

Once the nodes (entities) and edges (relationships) are defined, the graph is assembled using dedicated libraries. The project is configured for easy local execution, removing reliance on costly cloud-based processing. Using the Mistral 7B openorca instruct model, set up through Ollama, the construction of the knowledge graph is economical.

To craft a graph tailored to malware analysis reports, adapt the following notebook:

**[extract_graph.ipynb](extract_graph.ipynb)**

The notebook executes the strategy showcased in the following flowchart.

<img src="/assets/Method.png"/>

1. Partition the text of malware reports into segments, assigning a unique ID to each.
2. In each segment, extract cybersecurity concepts, threat actors, and malware families, alongside their semantic interrelations, weighting these initial connections as W1.
3. Presume that concepts sharing a segment suggest a contextual association, with a subsequent weight of W2. It's important to note that the same pairs may be mentioned multiple times across the corpus.
4. Collate matching pairs, combine their weights, and fuse their multiple relationships into a composite, heavily weighted edge.

The notebook further computes each node's Degree and Community affiliations, which are then used to determine the visual prominence and groupings of nodes within the graph.

# Usage: tool.py

## Introduction
This tool is designed to process malware analysis reports and generate knowledge graphs from them. It utilizes an LLM to extract information, identify relationships.  To visually represent these relationships in the form of a graph NetworkX and Pyvis are used. This script is particularly useful in understanding and visualizing the contextual proximity of different terms within a set of documents.

## Prerequisites
Before running the script, ensure that you have the following prerequisites installed:
- Python 3.x
- Pandas (TODO: CuDF)
- CuPy (for GPU acceleration in parts of the script)
- NetworkX
- PyVis

Additionally, the script relies on custom helper functions and the `langchain` package for document loading and text splitting.

## Installation
1. **Clone the Repository:**
   ```
   git clone https://github.com/binaryninja/Malware-Knowledge-Graph.git
   cd Malware-Knowledge-Graph
   ```

2. **Install Required Libraries:**
   Use pip or conda to install the required libraries. For example:
   ```
   pip install pandas cupy networkx seaborn pyvis
   ```

   For GPU support (optional), ensure you have a CUDA-compatible environment set up.

## Usage

Prep the data_input dir with the textfiles that match the keywords you are interested in eg:
`mkdir -p data_input/mimic_reports && grep -l ' mimic ransomware' data_input/mw_reports/* | xargs -I {} cp {} mimic_report_test`

Run the script by providing the data_files dir containing the documents you wish to process.  The files should exist in ./data_input/`data_diles`` directory:

```
python tool.py vidar_reports
INFO:root:Starting the process with the following arguments:
INFO:root:Namespace(documents='mimic_report_test')
INFO:root:Processing documents...
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00,  2.08it/s]
Number of chunks =  11
(11, 3)
 [
 {
 "node_1": "Mimic ransomware",
 "node_2": "Everything API abuse",
 "edge": "malware_technique"
 }, {
 "node_1": "Ransomware",
 "node_2": "Encryption process",
 "edge": "process_feature"
 }] [
 {
 "node_1": "Mimic",
 "node_2": "ransomware",
 "edge": "entity_relationship"
 }, {
 "node_1": "Everything (tool)",
 "node_2": "legitimate tool abused by Mimic ransomware",
 "edge": "victim-malware_abuse"
 },{
 "node_1": "Mimic Ransomware",
 "node_2": "Connected to Conti builder",
 "edge": "technique"
 },
 {...},
 ]
```

### Arguments
- `documents`: Path to the directory containing the documents to be processed.

## Components
- `process_documents`: This function processes the documents located at the given path, splits them into manageable chunks, and creates a data frame representing these chunks.
- `contextual_proximity`: Calculates contextual proximity between terms within the same text chunk and forms a data frame representing these relationships.
- `merge_graphs`: Combines different graph data into a single graph.
- `calc_networkx_graph`: Calculates a graph using the NetworkX library.
- `make_network_x_graph`: Visualizes the graph using PyVis.
- `colors2Community`: Assigns colors to different communities within the graph for better visualization.


## More Graphs:
```
mkdir -p data_input/Akira_reports && grep -l 'Akira' data_input/mw_reports/* | xargs -I {} cp {} Akira_report_test
mkdir -p data_input/AlphV_BlackCat_reports && grep -l 'AlphV BlackCat' data_input/mw_reports/* | xargs -I {} cp {} AlphV_BlackCat_report_test
mkdir -p data_input/AlphV_Sphynx_reports && grep -l 'AlphV Sphynx' data_input/mw_reports/* | xargs -I {} cp {} AlphV_Sphynx_report_test
mkdir -p data_input/AsyncRat_reports && grep -l 'AsyncRat' data_input/mw_reports/* | xargs -I {} cp {} AsyncRat_report_test
mkdir -p data_input/Blacksuit_reports && grep -l 'Blacksuit' data_input/mw_reports/* | xargs -I {} cp {} Blacksuit_report_test
mkdir -p data_input/BruteRatel_reports && grep -l 'BruteRatel' data_input/mw_reports/* | xargs -I {} cp {} BruteRatel_report_test
mkdir -p data_input/Bumblebee_reports && grep -l 'Bumblebee' data_input/mw_reports/* | xargs -I {} cp {} Bumblebee_report_test
mkdir -p data_input/Cl0p_reports && grep -l 'Cl0p' data_input/mw_reports/* | xargs -I {} cp {} Cl0p_report_test
mkdir -p data_input/CobaltStrike_reports && grep -l 'CobaltStrike' data_input/mw_reports/* | xargs -I {} cp {} CobaltStrike_report_test
mkdir -p data_input/DCRat_reports && grep -l 'DCRat' data_input/mw_reports/* | xargs -I {} cp {} DCRat_report_test
mkdir -p data_input/Emotet_reports && grep -l 'Emotet' data_input/mw_reports/* | xargs -I {} cp {} Emotet_report_test
mkdir -p data_input/FormBook_reports && grep -l 'FormBook' data_input/mw_reports/* | xargs -I {} cp {} FormBook_report_test
mkdir -p data_input/GootLoader_reports && grep -l 'GootLoader' data_input/mw_reports/* | xargs -I {} cp {} GootLoader_report_test
mkdir -p data_input/GuLoader_reports && grep -l 'GuLoader' data_input/mw_reports/* | xargs -I {} cp {} GuLoader_report_test
mkdir -p data_input/Havoc_reports && grep -l 'Havoc' data_input/mw_reports/* | xargs -I {} cp {} Havoc_report_test
mkdir -p data_input/IcedID_reports && grep -l 'IcedID' data_input/mw_reports/* | xargs -I {} cp {} IcedID_report_test
mkdir -p data_input/Lockbit_reports && grep -l 'Lockbit' data_input/mw_reports/* | xargs -I {} cp {} Lockbit_report_test
mkdir -p data_input/Metasploit_reports && grep -l 'Metasploit' data_input/mw_reports/* | xargs -I {} cp {} Metasploit_report_test
mkdir -p data_input/NjRat_reports && grep -l 'NjRat' data_input/mw_reports/* | xargs -I {} cp {} NjRat_report_test
mkdir -p data_input/OrcusRat_reports && grep -l 'OrcusRat' data_input/mw_reports/* | xargs -I {} cp {} OrcusRat_report_test
mkdir -p data_input/P2PInfect_reports && grep -l 'P2PInfect' data_input/mw_reports/* | xargs -I {} cp {} P2PInfect_report_test
mkdir -p data_input/Phobos_reports && grep -l 'Phobos' data_input/mw_reports/* | xargs -I {} cp {} Phobos_report_test
mkdir -p data_input/Play_reports && grep -l 'Play' data_input/mw_reports/* | xargs -I {} cp {} Play_report_test
mkdir -p data_input/QuasarRat_reports && grep -l 'QuasarRat' data_input/mw_reports/* | xargs -I {} cp {} QuasarRat_report_test
mkdir -p data_input/RacoonStealer_reports && grep -l 'RacoonStealer' data_input/mw_reports/* | xargs -I {} cp {} RacoonStealer_report_test
mkdir -p data_input/Raspberry_Robin_reports && grep -l 'Raspberry Robin' data_input/mw_reports/* | xargs -I {} cp {} Raspberry_Robin_report_test
mkdir -p data_input/Redline_reports && grep -l 'Redline' data_input/mw_reports/* | xargs -I {} cp {} Redline_report_test
mkdir -p data_input/Remcos_reports && grep -l 'Remcos' data_input/mw_reports/* | xargs -I {} cp {} Remcos_report_test
mkdir -p data_input/SmokeLoader_reports && grep -l 'SmokeLoader' data_input/mw_reports/* | xargs -I {} cp {} SmokeLoader_report_test
mkdir -p data_input/SocGholish_FakeUpdates_reports && grep -l 'SocGholish FakeUpdates' data_input/mw_reports/* | xargs -I {} cp {} SocGholish_FakeUpdates_report_test
mkdir -p data_input/Symbiote_reports && grep -l 'Symbiote' data_input/mw_reports/* | xargs -I {} cp {} Symbiote_report_test
mkdir -p data_input/System BC_reports && grep -l 'System BC' data_input/mw_reports/* | xargs -I {} cp {} System BC_report_test
mkdir -p data_input/Truebot_reports && grep -l 'Truebot' data_input/mw_reports/* | xargs -I {} cp {} Truebot_report_test
mkdir -p data_input/Vidar_reports && grep -l 'Vidar' data_input/mw_reports/* | xargs -I {} cp {} Vidar_report_test
mkdir -p data_input/XWorm_reports && grep -l 'XWorm' data_input/mw_reports/* | xargs -I {} cp {} XWorm_report_test
```