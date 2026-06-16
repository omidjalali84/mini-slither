# Mini-Slither

A static analyzer for Solidity smart contracts, modeled after [Slither](https://github.com/crytic/slither).  
Mini-Slither parses the compact-JSON AST produced by `solc` and runs a suite of detectors that flag common vulnerability patterns — with exact file, line, and column locations and clickable VS Code links in every finding.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Output Format](#output-format)
- [Detectors](#detectors)
  - [Reentrancy](#reentrancy)
  - [tx.origin Authentication](#txorigin-authentication)
  - [Centralized Fund Withdrawal](#centralized-fund-withdrawal)
  - [DOS via External Call in Loop](#dos-via-external-call-in-loop)
  - [Unchecked External Call](#unchecked-external-call)
  - [Delegatecall Risk](#delegatecall-risk)
  - [Self-Destruct Risk](#self-destruct-risk)
  - [Unbounded Loop](#unbounded-loop)
  - [Unused State Variable](#unused-state-variable)
- [Test Suite](#test-suite)
- [Project Structure](#project-structure)

---

## Overview

Mini-Slither is a Python-based static analyzer that detects security vulnerabilities and code quality issues in Solidity smart contracts without executing them. It works directly on the AST (Abstract Syntax Tree) emitted by the Solidity compiler, giving it precise structural insight into every function, modifier, loop, and expression in your contract.

**Key features:**

- **9 built-in detectors** covering the most critical Solidity vulnerability classes
- **Exact source locations** — every finding reports the file, line number, and column
- **Clickable links** — VS Code deep-links (`vscode://file/...`) let you jump to the vulnerable line instantly
- **JSON output** — machine-readable findings saved alongside terminal output for CI integration
- **No execution required** — pure static analysis, no node, no mainnet fork
- **Modular architecture** — each detector is an independent module; adding a new one takes ~50 lines

---

## Architecture

```
mini-slither/
├── main.py                   # Entry point — runs analysis and prints report
├── parser/
│   ├── ast_loader.py         # Invokes solc, parses compact-JSON AST
│   └── cfg_loader.py         # Invokes Slither to extract CFG (reserved)
├── core/
│   ├── engine.py             # Orchestrates all detectors, enriches findings
│   └── src_mapper.py         # Resolves solc src offsets → file:line:col + URLs
├── analyzer/
│   ├── reentrancy.py
│   ├── tx_origin.py
│   ├── centralization.py
│   ├── dos.py
│   ├── unchecked_call.py
│   ├── delegatecall.py
│   ├── self_destruct.py
│   ├── unbounded_loop.py
│   └── unused_state_var.py
└── tests/
    ├── reentrancy/
    ├── tx-origin/
    ├── centralization/
    ├── dos/
    ├── unchecked-call/
    ├── delegatecall/
    ├── selfdestruct/
    ├── unbounded-loop/
    ├── unused-state-var/
    └── src_mapper/
```

Each detector exports a single `check_*` function that accepts `(ast, cfg)` and returns a list of finding dicts. The engine calls them all, enriches results with source locations via `SrcMapper`, and passes them to the reporter.

---

## Installation

**Requirements:** Python 3.10+, `solc` on your PATH.

```bash
# 1. Clone the repo
git clone https://github.com/yourname/mini-slither.git
cd mini-slither

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install Python dependencies
pip install slither-analyzer pytest

# 4. Install solc (if not already installed)
pip install solc-select
solc-select install 0.8.0
solc-select use 0.8.0
```

---

## Usage

```bash
# Analyse a single contract
python main.py path/to/MyContract.sol

# Run all tests
python -m pytest tests/ -v
```

---

## Output Format

Mini-Slither prints a summary block followed by one section per finding, sorted by severity then by line number.

```
══════════════════════════════════════════════════════════════════════
  Mini-Slither  │  Vulnerable.sol
══════════════════════════════════════════════════════════════════════
  Found 3 issue(s).
  HIGH: 2  MEDIUM: 1
══════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────
  [1] 🔴  HIGH  │  Reentrancy vulnerability
──────────────────────────────────────────────────────────────────────
  Function  : withdraw
  Location  : tests/contracts/Vulnerable.sol:14:9
  VS Code   : vscode://file/…/Vulnerable.sol:14:9
  File URL  : file://…/Vulnerable.sol#L14

  State variable written AFTER .call() in 'withdraw'. An attacker can
  re-enter before the balance is updated and repeatedly drain funds.

  💡 Apply the Checks-Effects-Interactions pattern: update all state
     variables before any external call, or use a ReentrancyGuard.

  🔗 Docs: https://github.com/yourname/mini-slither#reentrancy
```

A JSON report is also written to `<ContractName>_findings.json` for use in CI pipelines or downstream tooling.

Each finding dict contains:

| Key              | Description                                         |
| ---------------- | --------------------------------------------------- |
| `severity`       | `HIGH`, `MEDIUM`, `LOW`, or `INFO`                  |
| `issue`          | Short label matching a detector section below       |
| `function`       | Function or modifier name where the issue was found |
| `details`        | Full human-readable explanation                     |
| `recommendation` | How to fix it                                       |
| `file`           | Relative path to the `.sol` file                    |
| `line`           | 1-based line number                                 |
| `col`            | 1-based column number                               |
| `vscode_url`     | `vscode://file/<path>:<line>:<col>`                 |
| `file_url`       | `file://<path>#L<line>`                             |
| `src`            | Raw solc src string `offset:length:fileIndex`       |

---

## Detectors

Each finding includes a `docs_url` field that links directly to the relevant section below.

---

### Reentrancy

**ID:** `reentrancy`  
**Severity:** 🔴 HIGH  
**Files:** `analyzer/reentrancy.py` · `tests/reentrancy/`

#### What it is

A reentrancy attack occurs when a contract makes an external call to an untrusted address before it has finished updating its own state. The callee can call back into the original contract mid-execution — before balances or flags have been updated — and repeat the withdrawal.

This is the vulnerability that drained **$60 million** from The DAO in 2016.

#### How Mini-Slither detects it

The detector flattens every function body into a source-ordered list of statements and looks for the pattern:

```
external_call()   →   state_variable = ...
```

It specifically handles `msg.sender.call{value: x}("")` (which solc encodes with an intermediate `FunctionCallOptions` node), and correctly skips cases where the state update comes _before_ the call.

#### Vulnerable example

```solidity
function withdraw() public {
    // ❌ external call BEFORE state update
    msg.sender.call{value: balance[msg.sender]}("");
    balance[msg.sender] = 0;   // too late — attacker already re-entered
}
```

#### Safe pattern (Checks-Effects-Interactions)

```solidity
function withdraw() public {
    uint256 amount = balance[msg.sender];
    balance[msg.sender] = 0;               // ✅ Effects first
    msg.sender.call{value: amount}("");    // ✅ Interactions last
}
```

#### References

- [SWC-107 — Reentrancy](https://swcregistry.io/docs/SWC-107)
- [The DAO Hack Explained](https://www.coindesk.com/learn/2016/06/25/understanding-the-dao-attack/)
- [OpenZeppelin ReentrancyGuard](https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard)

---

### tx.origin Authentication

**ID:** `tx-origin`  
**Severity:** 🔴 HIGH  
**Files:** `analyzer/tx_origin.py` · `tests/tx-origin/`

#### What it is

`tx.origin` always refers to the **original EOA** that initiated the outermost transaction — it never changes as the call propagates through contracts. Using it for authentication allows phishing attacks: a malicious contract can trick the owner into calling it, then forward the call to your contract where `tx.origin` still resolves to the victim's address.

#### How Mini-Slither detects it

The detector walks all `require()` calls, `if` conditions, and modifier bodies looking for `BinaryOperation` nodes where one operand is the `MemberAccess` `tx.origin` and the other is **not** `msg.sender` (the `tx.origin == msg.sender` EOA-only guard is a different pattern and is intentionally excluded to avoid false positives).

#### Vulnerable example

```solidity
function transferFunds(address payable dest, uint256 amount) public {
    require(tx.origin == owner, "Not owner");  // ❌ phishing-vulnerable
    dest.transfer(amount);
}
```

#### Safe pattern

```solidity
function transferFunds(address payable dest, uint256 amount) public {
    require(msg.sender == owner, "Not owner");  // ✅
    dest.transfer(amount);
}
```

#### References

- [SWC-115 — Authorization via tx.origin](https://swcregistry.io/docs/SWC-115)
- [Solidity docs — tx.origin](https://docs.soliditylang.org/en/latest/security-considerations.html#tx-origin)

---

### Centralized Fund Withdrawal

**ID:** `centralization`  
**Severity:** 🔴 HIGH  
**Files:** `analyzer/centralization.py` · `tests/centralization/`

#### What it is

When a single privileged address (owner, admin, deployer) has unchecked power to withdraw the contract's entire ETH or token balance, users must trust that key indefinitely. A compromised or malicious owner can drain all funds instantly with no recourse for users.

#### How Mini-Slither detects it

The detector looks for functions that satisfy **both** conditions:

1. **Auth gate** — has a privileged modifier (`onlyOwner`, `onlyAdmin`, …) or a `require(msg.sender == owner)` check
2. **Fund movement** — body contains `transfer`, `send`, `call`, `safeTransfer`, or `transferFrom`

Functions where users withdraw their _own_ balance (no auth gate) are not flagged.

#### Vulnerable example

```solidity
function drain() public onlyOwner {
    payable(owner).transfer(address(this).balance);  // ❌
}
```

#### Safer alternatives

- **Time-lock** — require a waiting period before large withdrawals execute
- **Multi-sig** — require M-of-N keyholders to approve
- **Decentralized governance** — put withdrawal logic behind a DAO vote

#### References

- [Trail of Bits — Not So Smart Contracts: Centralization](https://github.com/crytic/not-so-smart-contracts/tree/master/centralization)
- [SWC-106 — Unprotected SELFDESTRUCT](https://swcregistry.io/docs/SWC-106)

---

### DOS via External Call in Loop

**ID:** `dos`  
**Severity:** 🔴 HIGH  
**Files:** `analyzer/dos.py` · `tests/dos/`

#### What it is

Iterating over an array and making an external call (`.call`, `.transfer`, `.send`) to each element inside the loop creates a denial-of-service vector: if **any single recipient** is a contract that reverts on `receive()`, the entire loop reverts, permanently blocking the function for everyone.

#### How Mini-Slither detects it

The detector recursively walks the AST for `ForStatement` nodes and inspects the loop body for `FunctionCall` nodes whose string representation contains `call`, `transfer`, or `send`. Nested loops are handled — the inner loop is flagged independently.

#### Vulnerable example

```solidity
function distributeAll() public {
    for (uint256 i = 0; i < recipients.length; i++) {
        payable(recipients[i]).transfer(balances[recipients[i]]);  // ❌
    }
}
```

#### Safe pattern (Pull Payment)

```solidity
mapping(address => uint256) public balances;

// Users pull their own funds — one revert never blocks others
function withdraw() public {
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0;
    payable(msg.sender).transfer(amount);  // ✅
}
```

#### References

- [SWC-113 — DOS with Failed Call](https://swcregistry.io/docs/SWC-113)
- [OpenZeppelin — Pull Payment pattern](https://docs.openzeppelin.com/contracts/4.x/api/security#PullPayment)

---

### Unchecked External Call

**ID:** `unchecked-call`  
**Severity:** 🟡 MEDIUM  
**Files:** `analyzer/unchecked_call.py` · `tests/unchecked-call/`

#### What it is

`.call()`, `.send()`, and `.delegatecall()` return a `bool` indicating success. If this return value is ignored, a failed call silently continues execution — ETH may appear sent when it wasn't, or state may be updated after a silently failing operation, leaving the contract inconsistent.

`.transfer()` is **excluded** because it reverts automatically on failure.

#### How Mini-Slither detects it

The detector walks function bodies looking for `ExpressionStatement` nodes whose inner expression is directly a low-level call — meaning the return value was not assigned to any variable and not wrapped in `require()` or an `if` check. Tuple assignments (`(bool ok,) = addr.call(...)`) are correctly recognized as checked and not flagged.

#### Vulnerable example

```solidity
function sendEth(address payable dest, uint256 amount) public {
    dest.call{value: amount}("");   // ❌ return value discarded
}
```

#### Safe pattern

```solidity
function sendEth(address payable dest, uint256 amount) public {
    (bool ok, ) = dest.call{value: amount}("");
    require(ok, "Transfer failed");  // ✅
}
```

#### References

- [SWC-104 — Unchecked Call Return Value](https://swcregistry.io/docs/SWC-104)

---

### Delegatecall Risk

**ID:** `delegatecall`  
**Severity:** 🔴 HIGH  
**Files:** `analyzer/delegatecall.py` · `tests/delegatecall/`

#### What it is

`delegatecall` executes the **callee's bytecode** in the **caller's storage context**. The called code can read and overwrite any storage slot in your contract — including `owner`, balances, and all other state variables.

When the target address is a function parameter (user-controlled), an attacker can point the call at a malicious contract and take over your contract entirely. Even with a fixed target, storage layout mismatches between a proxy and its implementation can cause silent slot collisions.

#### How Mini-Slither detects it

The detector finds all `FunctionCall` nodes (unwrapping `FunctionCallOptions` wrappers) where the resolved callee is a `MemberAccess` with `memberName == "delegatecall"`. It then checks whether the call target resolves to a function parameter — and flags the finding with an extra "user-controlled" warning if so.

#### Vulnerable example

```solidity
// ❌ attacker can pass a malicious contract as `target`
function execute(address target, bytes calldata data) public {
    (bool ok, ) = target.delegatecall(data);
    require(ok, "failed");
}
```

#### Safe pattern

```solidity
address public immutable implementation;  // set once in constructor

fallback() external {
    // ✅ target is fixed and admin-controlled
    (bool ok, ) = implementation.delegatecall(msg.data);
    require(ok);
}
```

#### References

- [SWC-112 — Delegatecall to Untrusted Callee](https://swcregistry.io/docs/SWC-112)
- [OpenZeppelin Proxy pattern](https://docs.openzeppelin.com/contracts/4.x/api/proxy)

---

### Self-Destruct Risk

**ID:** `selfdestruct`  
**Severity:** 🔴 HIGH  
**Files:** `analyzer/self_destruct.py` · `tests/selfdestruct/`

#### What it is

`selfdestruct(recipient)` permanently destroys the contract and forwards its entire ETH balance to `recipient`. This is irreversible — the code and storage are wiped forever. If callable by a single privileged address (or by anyone), a compromised or malicious actor can instantly destroy the contract and steal all funds.

#### How Mini-Slither detects it

The detector walks function bodies for `FunctionCall` nodes where the callee identifier name is `selfdestruct` or the deprecated alias `suicide`. It additionally checks whether the function has an owner-auth gate (same heuristic as the centralization detector) and adjusts the details message accordingly — "privileged address can trigger destruction" vs "no access control — anyone may trigger it".

#### Vulnerable examples

```solidity
// ❌ owner-controlled — still dangerous if key is compromised
function destroy() public onlyOwner {
    selfdestruct(payable(owner));
}

// ❌ no access control — anyone can destroy the contract
function kill(address payable recipient) public {
    selfdestruct(recipient);
}
```

#### References

- [SWC-106 — Unprotected SELFDESTRUCT](https://swcregistry.io/docs/SWC-106)
- [Solidity docs — selfdestruct](https://docs.soliditylang.org/en/latest/units-and-global-variables.html#contract-related)

---

### Unbounded Loop

**ID:** `unbounded-loop`  
**Severity:** 🟡 MEDIUM  
**Files:** `analyzer/unbounded_loop.py` · `tests/unbounded-loop/`

#### What it is

A loop that iterates over a dynamically-sized storage array (`array.length`) that can grow without an upper bound will eventually consume more gas than the block gas limit allows. Once this happens, the function permanently reverts on every call — a gas-exhaustion denial-of-service.

#### How Mini-Slither detects it

The detector scans `ForStatement` and `WhileStatement` nodes and checks the loop condition for a `MemberAccess` node with `memberName == "length"`. Loops bounded by a constant or a function parameter are not flagged. Nested unbounded loops are each flagged independently.

#### Vulnerable example

```solidity
address[] public recipients;   // grows forever

function distributeAll() public {
    for (uint256 i = 0; i < recipients.length; i++) {  // ❌
        // ...
    }
}
```

#### Safe alternatives

```solidity
// Option 1 — paginate
function distribute(uint256 start, uint256 count) public {
    uint256 end = start + count < recipients.length
        ? start + count : recipients.length;
    for (uint256 i = start; i < end; i++) { ... }
}

// Option 2 — cap iteration
uint256 constant MAX_BATCH = 100;
for (uint256 i = 0; i < MAX_BATCH && i < recipients.length; i++) { ... }
```

#### References

- [SWC-128 — DOS with Block Gas Limit](https://swcregistry.io/docs/SWC-128)

---

### Unused State Variable

**ID:** `unused-state-var`  
**Severity:** ℹ️ INFO  
**Files:** `analyzer/unused_state_var.py` · `tests/unused-state-var/`

#### What it is

State variables that are declared but never read or written in any function or modifier body waste storage slots, increase deployment gas costs, and leave dead code in the contract that can confuse auditors.

#### How Mini-Slither detects it

The detector collects all `StateVariableDeclaration` nodes, then walks every `FunctionDefinition` and `ModifierDefinition` body collecting referenced `Identifier` names. Any state variable whose name never appears in a body is flagged. `public` variables are excluded because the compiler auto-generates a getter that constitutes usage.

#### Example

```solidity
contract Example {
    address internal owner;       // ✅ used in modifier below
    uint256 internal unusedLimit; // ❌ never referenced
    bool    internal deprecated;  // ❌ never referenced

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
}
```

#### References

- [Solidity docs — State Variables](https://docs.soliditylang.org/en/latest/contracts.html#state-variables)

---

## Test Suite

Every detector ships with both **integration tests** (real `.sol` files compiled with `solc`) and **unit tests** (hand-crafted AST dicts, no `solc` required).

```bash
# All tests
python -m pytest tests/ -v

# Single detector
python -m pytest tests/reentrancy/ -v

# Unit-only (no solc needed)
python -m pytest tests/ -v -k "Unit"

# Integration-only
python -m pytest tests/ -v -k "Integration"
```

| Detector         | Vulnerable contracts                                          | Safe contracts                                             |
| ---------------- | ------------------------------------------------------------- | ---------------------------------------------------------- |
| Reentrancy       | `vulnerable.sol`, `vulnerable2.sol`                           | `safe.sol`, `safe2.sol`                                    |
| tx.origin        | `TxOriginAuth.sol`, `TxOriginModifier.sol`                    | `MsgSenderAuth.sol`, `NoContractCaller.sol`                |
| Centralization   | `CentralizedVault.sol`, `AdminWithdrawable.sol`               | `SafeUserWithdraw.sol`, `NoFunds.sol`                      |
| DOS              | `DOSContract.sol`, `AirdropAndRefund.sol`, `NestedPayout.sol` | `PullPayment.sol`, `SingleWithdraw.sol`, `ValidateAll.sol` |
| Unchecked Call   | `UncheckedCall.sol`, `UncheckedSend.sol`                      | `CheckedCall.sol`, `TransferSafe.sol`                      |
| Delegatecall     | `DelegatecallProxy.sol`, `UpgradeableProxy.sol`               | `RegularCall.sol`                                          |
| Self-Destruct    | `KillSwitch.sol`, `UnprotectedKill.sol`                       | `NoKillSwitch.sol`                                         |
| Unbounded Loop   | `UnboundedDistribute.sol`, `UnboundedWhile.sol`               | `BoundedLoop.sol`                                          |
| Unused State Var | `UnusedVars.sol`                                              | `AllVarsUsed.sol`, `PublicVarsOnly.sol`                    |

---

## Project Structure

```
mini-slither/
├── main.py
├── conftest.py
├── README.md
├── parser/
│   ├── ast_loader.py
│   └── cfg_loader.py
├── core/
│   ├── engine.py
│   ├── src_mapper.py
│   └── rules.py
├── analyzer/
│   ├── reentrancy.py
│   ├── tx_origin.py
│   ├── centralization.py
│   ├── dos.py
│   ├── unchecked_call.py
│   ├── delegatecall.py
│   ├── self_destruct.py
│   ├── unbounded_loop.py
│   └── unused_state_var.py
└── tests/
    ├── reentrancy/
    │   ├── contracts/
    │   └── test_reentrancy.py
    ├── tx-origin/
    │   ├── contracts/
    │   └── test_tx_origin.py
    ├── centralization/
    │   ├── contracts/
    │   └── test_centralization.py
    ├── dos/
    │   ├── contracts/
    │   └── test_dos.py
    ├── unchecked-call/
    │   ├── contracts/
    │   └── test_unchecked_call.py
    ├── delegatecall/
    │   ├── contracts/
    │   └── test_delegatecall.py
    ├── selfdestruct/
    │   ├── contracts/
    │   └── test_selfdestruct.py
    ├── unbounded-loop/
    │   ├── contracts/
    │   └── test_unbounded_loop.py
    ├── unused-state-var/
    │   ├── contracts/
    │   └── test_unused_state_var.py
    └── src_mapper/
        └── test_src_mapper.py
```
