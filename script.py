import sys
import os
import time
sys.path.append("/home/yest96/nir")
sys.path.append("/home/yest96/nir/cvc5/build/src/api/python")

from fuzzer import get_total_inputs, load_variable_indices, parse_input_signals, run_fuzzing_cycles
from graphing import save_graph_image, load_constraints, build_constraint_graph, load_variable_names, detect_communities
from smt import main as check_subgraph

import networkx as nx

def extract_subgraph_vars(community):
    """
    From graph (networkx) and a community (set of var_idx as strings),
    return a list of var_idx (as strings).
    """
    return [str(v) for v in community]

def main(circuit_name):
    field_modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    if len(sys.argv) != 2:
        print("Usage: python fuzzer.py <circuit_name_or_path>")
        sys.exit(1)
    arg = sys.argv[1]
    
    # Resolve path or name
    circuit_name = os.path.splitext(os.path.basename(arg))[0]
    circuit_js = f"{circuit_name}_js"
    wasm_file = f"{circuit_name}.wasm"
    sym_path = os.path.join('constraints', f"{circuit_name}.sym")
    # Prepare dirs
    os.makedirs('inputs', exist_ok=True)
    os.makedirs('witnesses', exist_ok=True)
    os.makedirs('stats', exist_ok=True)
    # Determine input count
    num_inputs, outputs = get_total_inputs(circuit_name)
    if num_inputs is None:
        sys.exit(1)
    # Parse input signals
    signals = parse_input_signals(sym_path, num_inputs, outputs)
    if not signals:
        print("[Error] No input signals detected via sym file. Check nPub/nPrv in R1CS JSON.")
        sys.exit(1)
    print(f"[Info] Detected input signals: {signals}")
    intervals = load_variable_indices(sym_path)
    start = time.time()
    # Generate and process
    witnesses = run_fuzzing_cycles(signals, intervals, circuit_js, wasm_file)
    fuzzing_stop = time.time()
    print(f'Fuzzing time: {fuzzing_stop - start}')
    # Load constraints and graphS
    constraint_file = os.path.join('constraints', f"{circuit_name}_constraints.json")
    constraints = load_constraints(constraint_file)
    var_names = load_variable_names(sym_path)
    graph = build_constraint_graph(constraints, intervals)
    communities = detect_communities(graph)
    graphing_stop = time.time()
    print(f'Graphing time: {graphing_stop - fuzzing_stop}')
    result = []
    for idx, group in enumerate(communities):
        subgraph_vars = extract_subgraph_vars(group)
        print(f"Checking subgraph {idx+1} with {len(subgraph_vars)} variables...")
        underconstrained = check_subgraph(intervals, subgraph_vars, constraint_file, witnesses, field_modulus)
        result += underconstrained
    end = time.time()
    print(f"All underconstrained variables: {[var_names[var] for var in result]}")
    print(f'Solving time: {end - graphing_stop}')
    print(f'Result time: {end - start}')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python check_circuit.py <circuit_name>")
        sys.exit(1)
    circuit = sys.argv[1]
    
    main(circuit)
    
