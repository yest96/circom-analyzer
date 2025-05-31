import json
import os
import sys
import networkx as nx
import matplotlib.pyplot as plt

from fuzzer import load_variable_indices

def load_constraints(constraint_path):
    with open(constraint_path, 'r') as f:
        data = json.load(f)
    return data['constraints']

def load_variable_names(sym_path):
    with open(sym_path, 'r') as f:
        var_info = f.read().split()
    variables = {}
    for var in var_info:
        parts = var.split(',')
        if len(parts) == 4:
            variables[parts[1]] = parts[3]
    return variables

def build_constraint_graph(constraints, intervals):
    G = nx.Graph()
    for key in list(intervals.keys()):
        G.add_node(str(key))
    for constraint in constraints:
        involved_vars = set()
        for term in constraint:
            involved_vars.update(term.keys())
        for v1 in involved_vars:
            for v2 in involved_vars:
                if v1 != v2:
                    G.add_edge(v1, v2)
    return G

def detect_communities(graph):
    return nx.community.louvain_communities(graph)

def save_graph_image(graph, path="graph.png"):
    nx.draw(graph, with_labels=True, font_weight='bold')
    plt.savefig(path)
    plt.close()

def main(constraint_file, sym_file, output_image="graph.png"):
    intervals = load_variable_indices(sym_file)
    constraints = load_constraints(constraint_file)
    var_names = load_variable_names(sym_file)
    graph = build_constraint_graph(constraints, intervals)
    communities = detect_communities(graph)
    print("Detected subgraphs:")
#    for i, c in enumerate(communities):
#        print(f"Community {i+1}: {c}")
    save_graph_image(graph, output_image)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python fuzzer.py <circuit_name_or_path>")
        sys.exit(1)
    arg = sys.argv[1]
    circuit_name = os.path.splitext(os.path.basename(arg))[0]
    sym_path = os.path.join('constraints', f"{circuit_name}.sym")
    constraint_path = os.path.join('constraints', f"{circuit_name}_constraints.json")
    main(constraint_path, sym_path)
