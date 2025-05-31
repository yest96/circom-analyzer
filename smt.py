import os
import json
import random
import cvc5
from cvc5 import Kind

def load_constraints(constraint_json_path):
    with open(constraint_json_path, 'r') as f:
        data = json.load(f)
    return data['constraints']


def load_symbol_info(sym_path):
    """
    Parse .sym to map var_idx -> name
    Lines: local_idx,var_idx,_,fullname
    Returns dict var_idx(str) -> fullname
    """
    var_map = {}
    with open(sym_path, 'r') as f:
        for token in f.read().split():
            parts = token.split(',')
            if len(parts) == 4:
                _, var_idx, _, fullname = parts
                var_map[var_idx] = fullname
    return var_map


def filter_constraints(constraints, subgraph_vars):
    """
    Keep only those constraints that involve at least one var in subgraph_vars
    Each constraint is a triple of dicts; we flatten keys
    """
    filtered = []
    for c in constraints:
        involved = set()
        for part in c:
            involved.update(part.keys())
        if involved.intersection(subgraph_vars):
            filtered.append(c)
    return filtered


def select_witness_sample(witnesses):
    """
    Select a random witness 
    """
    return random.choice(witnesses)


def check_unboundedness(ranges, subgraph_vars, constraints, witness_vals, field_modulus, solver_opts=None):
    """
    For each var in subgraph_vars, check if it can exceed its max by asserting var not in interval.
    Other vars are fixed to witness_vals.
    Returns list of vars found unbounded.
    """
    unbounded = []
    # Initialize solver
    tm = cvc5.TermManager()
    slv = cvc5.Solver(tm)
    slv.setOption('produce-models', 'true')
    slv.setLogic("QF_FF")
    # Define finite field sort
    F = tm.mkFiniteFieldSort(str(field_modulus))
    # Pre-declare all variable terms
    var_terms = {}
    for idx, val in enumerate(witness_vals):
        vid = str(idx)
        if idx == 0:
            var_terms[vid] = tm.mkFiniteFieldElem('1', F)
            continue
        # For subgraph vars: declare symbolic constant
        if vid in subgraph_vars:
            var_terms[vid] = tm.mkConst(F, vid)
        else:
            # For others: fix to witness value
            var_terms[vid] = tm.mkFiniteFieldElem(str(val), F)
    # Assert all constraints
    for c in constraints:
        # each constraint c = [part0, part1, part2]
        terms = []
        for part in c:
            sum_terms = [tm.mkTerm(Kind.FINITE_FIELD_MULT, var_terms[var], tm.mkFiniteFieldElem(str(coeff), F))
             for var, coeff in part.items()]
            if not sum_terms:
                terms.append(tm.mkFiniteFieldElem('0', F))
            elif len(sum_terms) == 1:
                terms.append(sum_terms[0])
            else:
                terms.append(tm.mkTerm(Kind.FINITE_FIELD_ADD, *sum_terms))

        # equality: terms[0]*terms[1] == terms[2]
        eq = tm.mkTerm(Kind.EQUAL,
                       tm.mkTerm(Kind.FINITE_FIELD_MULT, terms[0], terms[1]),
                       terms[2])
        slv.assertFormula(eq)
    # Check each variable
    for vid in subgraph_vars:
        if vid == '0':
            continue
        max_val = ranges[int(vid)][1]
        min_val = ranges[int(vid)][0]
        # Create assertion var not in interval
        if max_val < field_modulus - 1:

            # Try several values
            not_accessed = field_modulus - max_val
            candidates = [max_val + 1 + i * not_accessed // 10 for i in range (10)] + [field_modulus - 1]
            for cv in candidates:
                slv.push()
                test_val = tm.mkFiniteFieldElem(str(cv), F)
                slv.assertFormula(tm.mkTerm(Kind.EQUAL, var_terms[vid], test_val))
                res = slv.checkSat()
                
                if res.isSat():
                    unbounded.append(vid)
                    break  # One success in enough
                slv.pop()
        if min_val > 0:

            # Try several values
            not_accessed = min_val
            candidates = [max_val - 1 - i * not_accessed // 10 for i in range (10)] + [0]
            for cv in candidates:
                slv.push()
                test_val = tm.mkFiniteFieldElem(str(cv), F)
                slv.assertFormula(tm.mkTerm(Kind.EQUAL, var_terms[vid], test_val))
                res = slv.checkSat()
                
                if res.isSat():
                    unbounded.append(vid)
                    break  # One success in enough
                slv.pop()
    return unbounded


def main(ranges, subgraph_vars, constraint_file, witnesses, field_modulus):
    all_constraints = load_constraints(constraint_file)
    filtered = filter_constraints(all_constraints, subgraph_vars)
    witness_vals = select_witness_sample(witnesses)
    unbd = check_unboundedness(ranges, subgraph_vars, filtered, witness_vals, field_modulus)
    print(f"Underconstrained variables: {unbd}")
    return unbd

if __name__ == '__main__':
    
    pass