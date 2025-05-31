import subprocess
import json
import os
import sys
import random
import re
from itertools import product

# -----------------------------------------------------------------------------
# Fuzzer for Circom circuits: generates multiple inputs, collects witnesses,
# and computes min/max ranges per witness variable.
# Usage:
#   python fuzzer.py <circuit_name_or_path>
# -----------------------------------------------------------------------------

field_modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def get_total_inputs(circuit_name):
    """
    Use snarkjs to export .r1cs to JSON and retrieve nPubInputs + nPrvInputs.
    """
    r1cs_file = f"{circuit_name}.r1cs"
    json_file = f"{circuit_name}.r1cs.json"
    if not os.path.isfile(json_file):
        subprocess.run(['snarkjs', 'r1cs', 'export', 'json', r1cs_file, json_file],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not os.path.isfile(json_file):
        print(f"[Error] Failed to export {r1cs_file} to JSON.")
        return None
    with open(json_file, 'r') as f:
        data = json.load(f)
    nOut = data.get('nOutputs', 0)
    nPub = data.get('nPubInputs', 0)
    nPrv = data.get('nPrvInputs', 0)
    total = nPub + nPrv
    return total, nOut if total > 0 else None


def parse_input_signals(sym_path, num_inputs, num_outputs):
    """
    Fallback: in .sym, take all var_idx < total_inputs as inputs (excluding idx 0 constant).
    """
    inputs = []
    cur_list_len = 0
    list_check = ''
    with open(sym_path, 'r') as f:
        for line in f:
            parts = line.strip().split(',')
            local_idx_str, witness_idx_str, template_ind, fullname = parts
            idx = int(local_idx_str)
            if idx == 0:
                continue
            elif num_outputs < idx <= num_outputs + num_inputs:
                prev = list_check
                name = fullname.split('.')[-1]
                list_check = name.split('[')
                if len(list_check) == 1:
                    if cur_list_len == 0:
                        inputs.append(name)
                    else:
                        inputs.append(f'{prev[0]}[{cur_list_len}]')
                        cur_list_len = 0
                        inputs.append(name)
                else:
                    cur_list_len += 1
    if cur_list_len != 0:
        inputs.append(f'{list_check[0]}[{cur_list_len}]')
    return inputs


def load_variable_indices(sym_path):
    intervals = {}
    with open(sym_path, 'r') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) == 4:
                local_idx, var_idx, template_idx, _ = parts
                try:
                    idx = int(var_idx)
                    if idx == 0:
                        continue
                    elif idx == -1:
                        continue
                    else:
                        intervals[idx] = [field_modulus, 0]
                except ValueError:
                    continue
    return intervals


def run_fuzzing_cycles(signal_names, intervals, circuit_js, wasm_file):
    """
    Unified fuzzing: dynamic per-phase generation and immediate witness eval.
    signal_names: list of input names
    intervals: dict of var_idx -> [min,max]
    circuit_js, wasm_file: paths
    sym_path: .sym path for load_variable_indices
    total_inputs: number of inputs per get_total_inputs
    """
    # Helper to update open ranges per variable
    open_ranges = {name: 1 for name in signal_names}  # exponent of bits
    num_vars = len(signal_names)
    previous_vals = {}
    inp_path = os.path.abspath("inputs/input.json")
    wtns = os.path.abspath("witnesses/witness.wtns")
    jsn = os.path.abspath("witnesses/witness.json")
    # Phase 1: all combinations of 0/1 -> 2**num_vars
    idx_sample = 0
    for bits in product([0,1], repeat=num_vars):
        inp = dict(zip(signal_names, bits))
        with open(inp_path, 'w') as f:
            json.dump(inp, f)
        success = run_witness_generation(wasm_file, inp_path, os.path.basename(wtns), circuit_js)
        idx_sample += 1
        if success:
            export_witness_json(circuit_js, os.path.basename(wtns), jsn)
            with open(jsn,'r') as f: data = json.load(f)
            vals = data
            # update intervals
            for vidx, v in enumerate(vals):
                if vidx in intervals:
                    val = int(v)
                    intervals[vidx][0] = min(intervals[vidx][0], val)
                    intervals[vidx][1] = max(intervals[vidx][1], val)
            # update input ranges: each signal's open range remains bits range 1
        
    # Phase 2: for each variable, expand ranges sequentially
    bit_levels = [8,16,32,64,128,253]
    for var_i, name in enumerate(signal_names):
        for exp in bit_levels:
            if open_ranges[name] >= exp:
                continue  # already at this or higher range
            # try 100 random sets
            success_any = False
            for _ in range(100):
                # generate input for all vars: each in its open_range except current var in new exp
                inp = {}
                for nm in signal_names:
                    rng = open_ranges[nm]
                    if nm == name:
                        rng = exp
                    inp[nm] = random.randint(0, 2**rng - 1)
                with open(inp_path, 'w') as f:
                    json.dump(inp, f)
                idx_sample += 1
                success = run_witness_generation(wasm_file, inp_path, os.path.basename(wtns), circuit_js)
                if success:
                    export_witness_json(circuit_js, os.path.basename(wtns), jsn)
                    with open(jsn,'r') as f: data = json.load(f)
                    vals = data
                    for vidx, v in enumerate(vals):
                        if vidx in intervals:
                            val = int(v)
                            # Внутри цикла обработки witness:
                            prev = previous_vals.get(vidx)

                            # Сохраняем текущий перед обновлением
                            previous_vals[vidx] = val

                            # Проверка на переполнение по скачку вниз
                            if (
                                prev is not None and
                                val < (field_modulus >> 2) and
                                prev > (field_modulus >> 1)
                            ):
                                # Скачок вниз: считаем, что диапазон достиг максимума
                                intervals[vidx][1] = field_modulus - 1
                                continue  # не нужно обновлять обычным способом
                            intervals[vidx][0] = min(intervals[vidx][0], val)
                            intervals[vidx][1] = max(intervals[vidx][1], val)
                    success_any = True
            if success_any:
                open_ranges[name] = exp
            else:
                break  # stop further expansion for this var
    for signal in signal_names:
        inp = {nm: random.randint(0, 2**open_ranges[nm] - 1) for nm in signal_names}
        inp[signal] = -1
        with open(inp_path, 'w') as f:
            json.dump(inp, f)
        idx_sample += 1
        if run_witness_generation(wasm_file, inp_path, os.path.basename(wtns), circuit_js):
            export_witness_json(circuit_js, os.path.basename(wtns), jsn)
            with open(jsn,'r') as f: data = json.load(f)
            vals = data
            for vidx, v in enumerate(vals):
                if vidx in intervals:
                    val = int(v)
                    intervals[vidx][0] = min(intervals[vidx][0], val)
                    intervals[vidx][1] = max(intervals[vidx][1], val)

    # Phase 3: final 100 random within open_ranges
    witnesses = []
    for _ in range(100):
        inp = {nm: random.randint(0, 2**open_ranges[nm] - 1) for nm in signal_names}
        with open(inp_path, 'w') as f:
            json.dump(inp, f)
        idx_sample += 1
        if run_witness_generation(wasm_file, inp_path, os.path.basename(wtns), circuit_js):
            export_witness_json(circuit_js, os.path.basename(wtns), jsn)
            with open(jsn,'r') as f: data = json.load(f)
            vals = data
            witnesses.append(vals)
            for vidx, v in enumerate(vals):
                if vidx in intervals:
                    val = int(v)

                    intervals[vidx][0] = min(intervals[vidx][0], val)
                    intervals[vidx][1] = max(intervals[vidx][1], val)

    # Save final intervals
    with open(os.path.join('stats','intervals.json'),'w') as f:
        json.dump(intervals,f,indent=2)
    print(f"[Done] Fuzzed total inputs: {idx_sample}")

    return witnesses


def run_witness_generation(wasm_file, input_file, wtns_out, cwd):
    cmd = ['node', 'generate_witness.js', wasm_file, input_file, wtns_out]
    res = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return res.returncode == 0


def export_witness_json(cwd, wtns_file, json_file):
    cmd = ['snarkjs', 'wtns', 'export', 'json', wtns_file, json_file]
    res = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode != 0:
        print(f"[Error] Export JSON failed: {res.stderr.decode().strip()}")


def main():
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
    '''
    intervals = load_variable_indices(sym_path)
    # Generate and process
    run_fuzzing_cycles(signals, intervals, circuit_js, wasm_file)'''

if __name__=='__main__':
    main()
