import json
import os
import subprocess
import networkx as nx
from argparse import Namespace
from pathlib import Path
# from pagegraph_query.run import run_query
import hashlib
from collections import deque
from pprint import pprint
from dataclasses import asdict

import sys
sys.path.append('/root/breakages/pagegraph/pagegraph-query')
from pagegraph.commands.scripts import Command as ScriptCommand
# from pagegraph.types import PageGraphId, PageGraphNodeId
from pagegraph.commands import Result as CommandResult

EDGE_KEYS = [
        "attr name", "before", "edge type", "headers", "is style",
        "key", "parent", "resource type", "response hash",
        "size", "status", "value"
    ]

NODE_KEYS = [
    "url", "source", "text", "script type", "method", "tag name", "node type"
    ]

class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)

def get_keyword(site):
    return site.split('://')[-1].split('/')[0]

def compute_hash(attributes):
    """Generate a unique hash for a script when missing."""
    relevant_attrs = [attributes.get(attr, '') for attr in ["url", "source", "text", "script type", "method", "tag name", "node type"]]
    hash_input = "|".join(relevant_attrs)
    return hashlib.md5(hash_input.encode()).hexdigest()  # MD5 for simplicity


def build_lookup(report):
    """Build lookup of (url, hash) -> node_id."""
    lookup = {}
    for node in report:
        script_info = node.get("script", {})
        frame_info = node.get("frame", {})
        script_hash = script_info.get("hash")
        if not script_hash:
            continue
        frame_url = frame_info.get("url", "unknown")
        lookup[(frame_url, script_hash)] = script_info.get("id")
    return lookup

def get_scripts(report): # return list of (frame['url'], script['hash'])
    scripts = set()
    
    for node in report:
        script_info = node.get("script", {})
        frame_info = node.get("frame", {})

        # Skip if no script hash
        script_hash = script_info.get("hash")
        if not script_hash:
            continue

        frame_url = frame_info.get("url", "unknown")
        scripts.add((frame_url, script_hash))

    return scripts

def run_scripts(input_graphml, lookup=0):
    """Run PageGraph 'scripts' command logic and extract scripts from a GraphML file."""
    cmd = ScriptCommand(
        input_path=Path(input_graphml),
        frame_nid=None,
        pg_id=None,
        include_source=False,
        omit_executors=False,
        debug=False
    )

    cmd.validate()
    result: CommandResult = cmd.execute()
    # print(type(result.report))
    report = [asdict(r) for r in result.report]  # convert Pydantic models to dicts

    if lookup:
        return build_lookup(report)
    else:
        return get_scripts(report)

def find_script_intersection(site, extn):
    """Compute the intersection of scripts across multiple crawls."""
    graphml_files = [
        f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}/{f}'
        for f in os.listdir(f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}')
        if f.endswith('graphml')
    ]
    print(graphml_files)
    
    script_set = run_scripts(graphml_files[0])
    for file in graphml_files[1:]:
        script_set &= run_scripts(file)
    
    with open(f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}/script_intersection.json', 'w') as f:
        json.dump(list(script_set), f)

def find_script_diff(site, extn='ublock'):
    """Compute differences between control and adblock scripts."""
    ctrl = set(tuple(lst) for lst in json.load(open(f'pagegraph-crawl/data_run1/control/{get_keyword(site)}/script_intersection.json', 'r')))
    adb = set(tuple(lst) for lst in json.load(open(f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}/script_intersection.json', 'r')))

    diff_ctrl_adb = ctrl - adb  # Scripts in control but not in adblock
    diff_adb_ctrl = adb - ctrl  # Scripts in adblock but not in control

    with open(f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}/script_diff_ctrl_adb.json', 'w') as f:
        json.dump(list(diff_ctrl_adb), f, cls=SetEncoder)
    
    with open(f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}/script_diff_adb_ctrl.json', 'w') as f:
        json.dump(list(diff_adb_ctrl), f, cls=SetEncoder)
    
    return diff_ctrl_adb, diff_adb_ctrl

# def extract_execution_tree(graph, root_node_id):
#     """Extract execution subgraph from a given script node using attribute-based matching."""
#     sub_nodes = set()
#     sub_edges = set()
#     visited = set()
#     queue = deque([(root_node_id, 0)])  # BFS queue, storing (node attributes, level)

#     while queue:
#         node_id, level = queue.popleft()
#         if node_id in visited:
#             continue
#         visited.add(node_id)
#         sub_nodes.add((node_id, level))

#         for successor in graph.successors(node_id):
#             queue.append((successor, level + 1))
#             sub_edges.add(((node_id, level), (successor, level + 1)))

#     return sub_nodes, sub_edges

# def compare_node_attrs(attrs1, attrs2):
#     return all(attrs1.get(k) == attrs2.get(k) for k in NODE_KEYS)

def extract_first_divergent_node(graph1, graph2, root1, root2):
    visited = set()
    queue = deque([(None, root1, root2, 0)])

    def get_signature(graph, parent, node):
        node_attrs = graph.nodes[node]
        edge_attrs = graph.get_edge_data(parent, node, default={}) if parent else {}
        node_tuple = tuple(node_attrs.get(attr, '') for attr in NODE_KEYS)
        edge_tuple = tuple(edge_attrs.get(attr, '') for attr in EDGE_KEYS)
        return (node_tuple, edge_tuple)

    while queue:
        # print(len(queue))
        parent1, parent2, node1, node2, level = queue.popleft()

        if (node1, node2, level) in visited:
            continue

        visited.add((node1, node2, level))

        sig1 = get_signature(graph1, parent1, node1)
        sig2 = get_signature(graph2, parent2, node2)

        if sig1 != sig2:
            return {
                "level": level,
                "control_signature": sig1,
                "adblock_signature": sig2
            }

        # print(attrs1)
        # print('*'*15)
        # print(attrs2)
        # print('*'*50)

        # if not compare_node_attrs(attrs1, attrs2):
        #     return {
        #         "level": level,
        #         # "control_node": {k: attrs1.get(k) for k in attrs1},
        #         # "adblock_node": {k: attrs2.get(k) for k in attrs2}
        #         "control_node": [attrs1.get(attr, '') for attr in ["url", "script type", "method", "tag name", "node type"]],
        #         "adblock_node": [attrs2.get(attr, '') for attr in ["url", "script type", "method", "tag name", "node type"]]
        #     }

        children1 = list(graph1.successors(node1))
        children2 = list(graph2.successors(node2))

        if len(children1) != len(children2):
            sigs1 = set(get_signature(graph1, node1, c) for c in children1)
            sigs2 = set(get_node_signature(graph2, node2,  c) for c in children2)

            only_in_adblock = sigs2 - sigs1
            only_in_control = sigs1 - sigs2

            return {
                "level": level,
                "control_children_count": len(children1),
                "adblock_children_count": len(children2),
                "parent_node": [attrs1.get(attr, '') for attr in NODE_KEYS],
                "only_in_adblock": only_in_adblock,
                "only_in_control": only_in_control 
            }

        # for c1, c2 in zip(children1, children2):
        #     queue.append((c1, c2, level + 1))
        def get_edge_hash(graph, parent, child):
            edge_attrs = graph.get_edge_data(parent, child, default={})
            return hashlib.md5("|".join(str(edge_attrs.get(k, '')) for k in EDGE_KEYS).encode()).hexdigest()

        child_map1 = {get_edge_hash(graph1, node1, c): c for c in children1}
        child_map2 = {get_edge_hash(graph2, node2, c): c for c in children2}

        common_hashes = set(child_map1.keys()) & set(child_map2.keys())
        only_ctrl = set(child_map1.keys()) - common_hashes
        only_adb = set(child_map2.keys()) - common_hashes

        for h in common_hashes:
            queue.append((node1, node2, child_map1[h], child_map2[h], level + 1))

        if only_ctrl or only_adb:
            return {
                "level": level,
                "unmatched_control_children": [graph1.nodes[child_map1[h]] for h in only_ctrl],
                "unmatched_adblock_children": [graph2.nodes[child_map2[h]] for h in only_adb]
            }

    return None    

def find_execution_differences(site, extn='ublock'):
    """Compute node and edge differences for common scripts (C ∩ A)."""
    # ctrl_scripts = set(tuple(lst) for lst in json.load(open(f'pagegraph-crawl/data_run1/control/{get_keyword(site)}/script_intersection.json', 'r')))
    # adb_scripts = set(tuple(lst) for lst in json.load(open(f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}/script_intersection.json', 'r')))
    
    # common_scripts = ctrl_scripts & adb_scripts  # Only process common scripts
    # print('common_scripts:', common_scripts)
    
    control_path = f'pagegraph-crawl/data_run1/control/{get_keyword(site)}'
    extn_path = f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}'
    
    control_graphml = [f'{control_path}/{f}' for f in os.listdir(control_path) if f.endswith('.graphml')][0]
    extn_graphml = [f'{extn_path}/{f}' for f in os.listdir(extn_path) if f.endswith('.graphml')][0]

    control_scripts = run_scripts(control_graphml)
    adb_scripts = run_scripts(extn_graphml)
    common_scripts = control_scripts & adb_scripts


    ctrl_lookup = run_scripts(control_graphml, 1)
    extn_lookup = run_scripts(extn_graphml, 1)

    control_graph = nx.read_graphml(control_graphml)
    extn_graph = nx.read_graphml(extn_graphml)

    node_diff_results = {}

    for frame_url, script_hash in common_scripts:
        ctrl_id = ctrl_lookup.get((frame_url, script_hash))
        extn_id = extn_lookup.get((frame_url, script_hash))
        if not ctrl_id or not extn_id:
            pprint(common_scripts)
            print('*'*50)
            pprint(ctrl_lookup)
            print('*'*50)
            pprint(extn_lookup)
            print('*'*50)
            print('NEED TO CHECK!!!', site, extn)
            break

        divergence = extract_first_divergent_node(control_graph, extn_graph, ctrl_id, extn_id)
        if divergence:
            node_diff_results[script_hash] = divergence

    with open(f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}/execution_differences_timestamp.json', 'w') as f:
        json.dump(node_diff_results, f, cls=SetEncoder)

def generate_graphml(site):
# def generate_graphml(site):
    """Run a crawl and store the GraphML output."""
    current_dir = os.getcwd()
    os.chdir('./pagegraph-crawl')
        # url = 'https://www.google.com'
    # subprocess.run(['npm', 'run', 'crawl', '--', f'-o=control/{get_keyword(url)}', f'-u={url}', f'-b=/usr/bin/brave-browser-nightly', f'-t=10', f'--extensions-path=control', '--screenshot'])
    subprocess.run([
        'python3', 'generate_parallel_graphml.py', '--url', site])
    os.chdir(current_dir)

if __name__ == "__main__":
    # urls = open('pagegraph-crawl/try.txt', 'r').read().splitlines()
    urls = open('pagegraph-crawl/try.txt', 'r').read().splitlines()
    extns = ['control', 'ublock']
    # extns = ['control']

    for url in urls:
        # generate_graphml(url)
        # for extn in extns:
        #     try:
        #         print(url)
        #         find_script_intersection(url, extn)
        #     except Exception as e:
        #         print(e, extn, url)
        #         continue
        
        try:
            # find_script_diff(url)
            find_execution_differences(url)
        except Exception as e:
            print(e, url)
            continue