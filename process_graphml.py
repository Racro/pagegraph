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
import time

import sys
# sys.path.append('/root/breakages/pagegraph/pagegraph-query')
# from pagegraph.commands.scripts import Command as ScriptCommand
# from pagegraph.types import PageGraphId, PageGraphNodeId
# from pagegraph.commands import Result as CommandResult

EDGE_KEYS = [
        "attr name", "before", "edge type", "headers", "is style",
        "key", "parent", "resource type", "response hash",
        "size", "status", "value"
    ]

NODE_KEYS = [
    "url", "source", "text", "script type", "method", "tag name", "node type"
    ]
STRIPPED_NODE_KEYS = [
    "url", "script type", "method", "tag name", "node type"
]

# Global set to store node type tuples per URL
global_node_types = set()

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
    try:
        result = subprocess.run([
            'python3', 'pagegraph-query/run.py', 'scripts', Path(input_graphml)], capture_output=True, text=True, check=True)
    except Exception as e:
        print(e)
        return set()


    try:
        output = json.loads(result.stdout)
        # print(output.keys())
        # sys.exit(0)
        # print('+'*50)
        # print(output['report'])
        # print('+'*50)
        # report = [asdict(r) for r in output['report']]  # convert Pydantic models to dicts
    except Exception as e:
        print(e)
        sys.exit(0)

    if lookup:
        return build_lookup(output['report'])
    else:
        return get_scripts(output['report'])

def find_script_intersection(site, extn):
    """Compute the intersection of scripts across multiple crawls."""
    graphml_files = [
        f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}/{f}'
        for f in os.listdir(f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}') if f.endswith('graphml')
    ]
    # print(graphml_files)
    
    script_set = run_scripts(graphml_files[0])
    for file in graphml_files[1:]:
        script_set &= run_scripts(file)
        # print(script_set)
        # print('*'*25)
        # input()

    with open(f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}/script_intersection.json', 'w') as f:
        json.dump(script_set, f, cls=SetEncoder)

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

def extract_first_divergent_node(graph1, graph2, root1, root2, global_node_types):
    # visited = set()
    queue = deque([(None, None, root1, root2)])
    level_dict = {(root1, root2): 0}

    divergent_behavior = []
    divergent_behavior_all = []

    def get_signature(graph, parent, node):
        node_attrs = graph.nodes[node]
        edge_attrs = graph.get_edge_data(parent, node, default={}) if parent else {}
        node_tuple = tuple(node_attrs.get(attr, '') for attr in NODE_KEYS)
        edge_tuple = tuple(edge_attrs.get(attr, '') for attr in EDGE_KEYS)
        # print(node_tuple, edge_tuple)
        return (node_tuple, edge_tuple)
    
    def get_node(graph, node):
        return [graph.nodes[node].get(attr, '') for attr in NODE_KEYS]

    def get_stripped_node(graph, node):
        return [graph.nodes[node].get(attr, '') for attr in STRIPPED_NODE_KEYS]

    def get_node_type_tuple(graph, node):
        attrs = graph.nodes[node]
        return (attrs.get("url", ''), attrs.get("source", ''), attrs.get("text", ''), attrs.get("tag name", ''), attrs.get("node type", ''))

    def collect_descendants(graph, node):
        visited = set()
        stack = [(node, [f"{graph.nodes[node].get('tag name', '')}|{graph.nodes[node].get('node type', '')}"])]
        chains = []
        while stack:
            current, path = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            node_type_tuple = get_node_type_tuple(graph, current)
            if node_type_tuple[-1] != 'script':
                global_node_types.add((node_type_tuple, tuple(path)))
            
            children = list(graph.successors(current))
            if not children:
                chains.append(tuple(path))
                break
            else:
                for child in children:
                    stack.append((child, path + [f"{graph.nodes[child].get('tag name', '')}|{graph.nodes[child].get('node type', '')}"]))
        # print(chains)
        # input()
        return chains

    while queue:
        print(time.time(), len(queue))
        parent1, parent2, node1, node2 = queue.popleft()
        level = level_dict[(node1, node2)]

        # if (node1, node2, level) in visited:
        #     continue

        # visited.add((node1, node2, level))

        sig1 = get_signature(graph1, parent1, node1)
        sig2 = get_signature(graph2, parent2, node2)

        if sig1 != sig2:
            chains1 = collect_descendants(graph1, node1)
            chains2 = collect_descendants(graph2, node2)
            divergent_behavior.append(
                {
                    "reason": 'different nodes',
                    "level": level,
                    "control_signature": list(sig1[0][:1] + sig1[0][3:]),
                    "adblock_signature": list(sig2[0][:1] + sig2[0][3:]),
                    "control_chains": chains1,
                    "adblock_chains": chains2
                }
            )
            divergent_behavior_all.append(
                {
                    "reason": 'different nodes',
                    "level": level,
                    "control_signature": sig1,
                    "adblock_signature": sig2
                }
            )
            
            continue

        children1 = list(graph1.successors(node1))
        children2 = list(graph2.successors(node2))

        def get_edge_node_hash(graph, parent, child):
            (node_tuple, edge_tuple) = get_signature(graph, parent, child)
            node_tuple = list(node_tuple)
            node_tuple.extend(list(edge_tuple))

            return hashlib.md5("|".join(node_tuple).encode()).hexdigest()

        child_map1 = {}
        child_map2 = {}
        c1_tuples = []
        c2_tuples = []
        for c in children1:
            child_hash1 = get_edge_node_hash(graph1,
                                              node1, c)
            c1_tuples.append(child_hash1)
            if child_hash1 in child_map1:
                print('Duplicate child hash in child_map1:', child_hash1)
            child_map1[child_hash1] = c

        for c in children2:
            child_hash2 = get_edge_node_hash(graph2, node2, c)
            c2_tuples.append(child_hash2)
            if child_hash2 in child_map2:
                print('Duplicate child hash in child_map2:', child_hash2)
            child_map2[child_hash2] = c
        
        print(c1_tuples, c2_tuples)
        input()
        common_hashes = set(child_map1.keys()) & set(child_map2.keys())
        only_ctrl = set(child_map1.keys()) - common_hashes
        only_adb = set(child_map2.keys()) - common_hashes

        for h in common_hashes:
            if (child_map1[h], child_map2[h]) not in level_dict:
                level_dict[(child_map1[h], child_map2[h])] = level + 1
                queue.append((node1, node2, child_map1[h], child_map2[h]))
        

        if only_ctrl or only_adb:
            chains1 = []
            for h in set(only_ctrl):
                if graph1.nodes[child_map1[h]].get('node type', '') == 'script':
                    only_ctrl.remove(h)
                    continue
                chains1.extend(collect_descendants(graph1, child_map1[h]))
            chains2 = []
            for h in set(only_adb):
                if graph2.nodes[child_map2[h]].get('node type', '') == 'script':
                    only_adb.remove(h)
                    continue
                chains2.extend(collect_descendants(graph2, child_map2[h]))

            
            divergent_behavior.append(
                {
                    "reason": 'different children count',
                    "level": level,
                    "unmatched_control_children": [get_stripped_node(graph1, child_map1[h]) for h in only_ctrl],
                    "unmatched_adblock_children": [get_stripped_node(graph2, child_map2[h]) for h in only_adb],
                    "control_chains": chains1,
                    "adblock_chains": chains2
                }
            )
            divergent_behavior_all.append(
                {
                    "reason": 'different children count',
                    "level": level,
                    "unmatched_control_children": [get_node(graph1, child_map1[h]) for h in only_ctrl],
                    "unmatched_adblock_children": [get_node(graph2, child_map2[h]) for h in only_adb]
                }
            )

    return divergent_behavior, divergent_behavior_all

def find_execution_differences(site, global_node_types, extn='ublock'):
    """Compute node and edge differences for common scripts (C ∩ A)."""
    ctrl_scripts = set(tuple(lst) for lst in json.load(open(f'pagegraph-crawl/data_run1/control/{get_keyword(site)}/script_intersection.json', 'r')))
    adb_scripts = set(tuple(lst) for lst in json.load(open(f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}/script_intersection.json', 'r')))
    
    common_scripts = ctrl_scripts & adb_scripts  # Only process common scripts
    # print('common_scripts:', common_scripts)
    
    control_path = f'pagegraph-crawl/data_run1/control/{get_keyword(site)}'
    extn_path = f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}'
    
    control_graphml = [f'{control_path}/{f}' for f in os.listdir(control_path) if f.endswith('.graphml')][0]
    extn_graphml = [f'{extn_path}/{f}' for f in os.listdir(extn_path) if f.endswith('.graphml')][0]

    # control_scripts = run_scripts(control_graphml)
    # adb_scripts = run_scripts(extn_graphml)
    # common_scripts = control_scripts & adb_scripts

    ctrl_lookup = run_scripts(control_graphml, 1)
    extn_lookup = run_scripts(extn_graphml, 1)

    control_graph = nx.read_graphml(control_graphml)
    extn_graph = nx.read_graphml(extn_graphml)

    node_diff_results = {}
    node_diff_results_all = {}

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

        divergence, divergence_all = extract_first_divergent_node(control_graph, extn_graph, ctrl_id, extn_id, global_node_types)
        if divergence != []:
            node_diff_results[script_hash] = divergence
            node_diff_results_all[script_hash] = divergence_all

    print("WRITING TO THE FILES")
    with open(f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}/execution_differences.json', 'w') as f:
    #     json.dump(node_diff_results, f, cls=SetEncoder)
    # with open(f'pagegraph-crawl/data_run1/{extn}/{get_keyword(site)}/execution_differences_all.json', 'w') as f:
    #     json.dump(node_diff_results_all, f, cls=SetEncoder)

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
    urls = open('pagegraph-crawl/websites_1000.txt', 'r').read().splitlines()
    # urls = open('pagegraph-crawl/websites_1000.txt', 'r').read().splitlines()
    extns = ['control', 'ublock']
    # extns = ['control']

    global_node_types = set()

    for url in urls:
        # generate_graphml(url)
        print('*'*50)
    #     # for extn in extns:
    #     #     try:
    #     #         print(url)
    #     #         find_script_intersection(url, extn)
    #     #     except Exception as e:
    #     #         print(e, extn, url)
    #     #         continue
        
        try:
            # find_script_diff(url)
            find_execution_differences(url, global_node_types)
        except Exception as e:
            print(e, url)
            continue
    
    with open(f'pagegraph-crawl/all_nodes_chains_new.json', 'w') as f:
        json.dump(global_node_types, f, cls=SetEncoder)