from slither.slither import Slither

def get_cfg(file_path):
    slither = Slither(file_path)



    cfgs = {}

    for contract in slither.contracts:
        for function in contract.functions:
            cfgs[function.name] = function.nodes

    return cfgs