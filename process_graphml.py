import json
import os
import subprocess
import networkx as nx
from argparse import Namespace
from pathlib import Path
# from pagegraph_query.run import run_query
import hashlib
from collections import deque

from dataclasses import asdict

import sys
sys.path.append('/home/ritik/work/pes/breakages/pagegraph/pagegraph_query')
from pagegraph.commands.scripts import Command as ScriptCommand
# from pagegraph.types import PageGraphId, PageGraphNodeId
from pagegraph.commands import Result as CommandResult

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
        f'pagegraph-crawl/data/{extn}/{get_keyword(site)}/{f}'
        for f in os.listdir(f'pagegraph-crawl/data/{extn}/{get_keyword(site)}')
        if f.endswith('graphml')
    ]
    
    script_set = run_scripts(graphml_files[0])
    for file in graphml_files[1:]:
        script_set &= run_scripts(file)
    
    with open(f'pagegraph-crawl/data/{extn}/{get_keyword(site)}/script_intersection.json', 'w') as f:
        json.dump(list(script_set), f)

def find_script_diff(site, extn='ublock'):
    """Compute differences between control and adblock scripts."""
    ctrl = set(tuple(lst) for lst in json.load(open(f'pagegraph-crawl/data/control/{get_keyword(site)}/script_intersection.json', 'r')))
    adb = set(tuple(lst) for lst in json.load(open(f'pagegraph-crawl/data/{extn}/{get_keyword(site)}/script_intersection.json', 'r')))

    diff_ctrl_adb = ctrl - adb  # Scripts in control but not in adblock
    diff_adb_ctrl = adb - ctrl  # Scripts in adblock but not in control

    with open(f'pagegraph-crawl/data/{extn}/{get_keyword(site)}/script_diff_ctrl_adb.json', 'w') as f:
        json.dump(list(diff_ctrl_adb), f, cls=SetEncoder)
    
    with open(f'pagegraph-crawl/data/{extn}/{get_keyword(site)}/script_diff_adb_ctrl.json', 'w') as f:
        json.dump(list(diff_adb_ctrl), f, cls=SetEncoder)
    
    return diff_ctrl_adb, diff_adb_ctrl

def extract_execution_tree(graph, root_node_id):
    """Extract execution subgraph from a given script node using attribute-based matching."""
    sub_nodes = set()
    sub_edges = set()
    visited = set()
    queue = deque([(root_node_id, 0)])  # BFS queue, storing (node attributes, level)

    while queue:
        node_id, level = queue.popleft()
        if node_id in visited:
            continue
        visited.add(node_id)
        sub_nodes.add((node_id, level))

        for successor in graph.successors(node_id):
            queue.append((successor, level + 1))
            sub_edges.add(((node_id, level), (successor, level + 1)))

    return sub_nodes, sub_edges

def compare_node_attrs(attrs1, attrs2):
    keys = ["url", "source", "text", "script type", "method", "tag name", "node type"]
    return all(attrs1.get(k) == attrs2.get(k) for k in keys)

def extract_first_divergent_node(graph1, graph2, root1, root2):
    visited1 = set()
    visited2 = set()
    queue = deque([(root1, root2, 0)])

    while queue:
        node1, node2, level = queue.popleft()

        if node1 in visited1 or node2 in visited2:
            continue

        visited1.add(node1)
        visited2.add(node2)

        attrs1 = graph1.nodes[node1]
        attrs2 = graph2.nodes[node2]

        # print(attrs1)
        # print('*'*15)
        # print(attrs2)
        # print('*'*50)

        if not compare_node_attrs(attrs1, attrs2):
            return {
                "level": level,
                "control_node": {k: attrs1.get(k) for k in attrs1},
                "adblock_node": {k: attrs2.get(k) for k in attrs2}
            }

        children1 = list(graph1.successors(node1))
        children2 = list(graph2.successors(node2))

        if len(children1) != len(children2):
            return {
                "level": level,
                "control_children_count": len(children1),
                "adblock_children_count": len(children2)
            }

        for c1, c2 in zip(children1, children2):
            queue.append((c1, c2, level + 1))

    return None    

def find_execution_differences(site, extn='ublock'):
    """Compute node and edge differences for common scripts (C ∩ A)."""
    ctrl_scripts = set(tuple(lst) for lst in json.load(open(f'pagegraph-crawl/data/control/{get_keyword(site)}/script_intersection.json', 'r')))
    adb_scripts = set(tuple(lst) for lst in json.load(open(f'pagegraph-crawl/data/{extn}/{get_keyword(site)}/script_intersection.json', 'r')))
    
    common_scripts = ctrl_scripts & adb_scripts  # Only process common scripts
    # print('common_scripts:', common_scripts)
    
    control_path = f'pagegraph-crawl/data/control/{get_keyword(site)}'
    extn_path = f'pagegraph-crawl/data/control/{get_keyword(site)}'
    
    control_graphml = [f'{control_path}/{f}' for f in os.listdir(control_path) if f.endswith('.graphml')][0]
    extn_graphml = [f'{extn_path}/{f}' for f in os.listdir(extn_path) if f.endswith('.graphml')][0]

    ctrl_lookup = run_scripts(control_graphml, 1)
    extn_lookup = run_scripts(extn_graphml, 1)

    control_graph = nx.read_graphml(control_graphml)
    extn_graph = nx.read_graphml(extn_graphml)

    node_diff_results = {}

    for frame_url, script_hash in common_scripts:
        ctrl_id = ctrl_lookup.get((frame_url, script_hash))
        extn_id = extn_lookup.get((frame_url, script_hash))
        if not ctrl_id or not extn_id:
            print('NEED TO CHECK!!!')
            continue

        divergence = extract_first_divergent_node(control_graph, extn_graph, ctrl_id, extn_id)
        if divergence:
            node_diff_results[script_hash] = divergence
        else:
            node_diff_results[script_hash] = {"no_difference": True}

        # control_attrs = {"url": frame_url, "hash": script_hash}
        # extn_attrs = {"url": frame_url, "hash": script_hash}
        
        # extn_nodes, extn_edges = extract_execution_tree(extn_graph, extn_id)
        # ctrl_nodes, ctrl_edges = extract_execution_tree(control_graph, ctrl_id)

        # # print(extn_nodes, extn_edges, ctrl_nodes, ctrl_edges)

        # node_diff = extn_nodes - ctrl_nodes
        # edge_diff = extn_edges - ctrl_edges

        # # Handle case where no attributes exist (None tuple at Level X)
        # if not node_diff and not edge_diff:
        #     node_diff_results[script_hash] = {"no_difference": True}
        # else:
        #     node_diff_results[script_hash] = {
        #         "node_diff": list(node_diff),
        #         "edge_diff": list(edge_diff)
        #     }

    with open(f'pagegraph-crawl/data/{extn}/{get_keyword(site)}/execution_differences.json', 'w') as f:
        json.dump(node_diff_results, f)

def generate_graphml(site):
# def generate_graphml(site):
    """Run a crawl and store the GraphML output."""
    current_dir = os.getcwd()
    os.chdir('/home/ritik/work/pes/breakages/pagegraph/pagegraph-crawl')
        # url = 'https://www.google.com'
    # subprocess.run(['npm', 'run', 'crawl', '--', f'-o=control/{get_keyword(url)}', f'-u={url}', f'-b=/usr/bin/brave-browser-nightly', f'-t=10', f'--extensions-path=control', '--screenshot'])
    subprocess.run([
        'python3', 'generate_parallel_graphml.py', '--url', site])
    os.chdir(current_dir)

if __name__ == "__main__":
    urls = open('pagegraph-crawl/websites_1000.txt', 'r').read().splitlines()
    extns = ['control', 'ublock']
    # extns = ['control']

    for url in urls:
        # generate_graphml(url)
        for extn in extns:
            try:
                find_script_intersection(url, extn)
            except Exception as e:
                print(e, extn, url)
                continue
        
        # try:
        #     find_script_diff(url)
        #     find_execution_differences(url)
        # except Exception as e:
        #     print(e, url)
        #     continue