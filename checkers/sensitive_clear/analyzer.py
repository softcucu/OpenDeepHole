"""敏感信息未清零检测 - 函数级静态候选生成器。

本分析器用宽松启发式找出可能承载敏感信息的变量，并按函数生成候选。
变量名只保存在 metadata 中用于调试，运行时初始提示词不会暴露这些变量名。
"""

from __future__ import annotations

import re
from pathlib import Path

import tree_sitter_cpp
from tree_sitter import Language, Parser

from backend.analyzers.base import BaseAnalyzer, Candidate
from code_parser.code_utils import find_nodes_by_type

CPP_LANGUAGE = Language(tree_sitter_cpp.language())

SENSITIVE_TERMS = {
    "accesskey",
    "accesssecret",
    "accesstoken",
    "aes",
    "apikey",
    "appkey",
    "appsecret",
    "auth",
    "bearer",
    "cert",
    "certificate",
    "chacha",
    "cipher",
    "cookie",
    "cred",
    "credential",
    "crypt",
    "crypto",
    "decrypt",
    "derivedkey",
    "des",
    "digest",
    "drbg",
    "dsa",
    "ecdh",
    "ecdsa",
    "ed25519",
    "encrypt",
    "entropy",
    "hash",
    "handshake",
    "hkdf",
    "hmac",
    "jwt",
    "kdf",
    "key",
    "keybag",
    "keychain",
    "keyfile",
    "keyid",
    "keymaterial",
    "keyring",
    "keystore",
    "kms",
    "mac",
    "masterkey",
    "md5",
    "mfa",
    "nonce",
    "otp",
    "pass",
    "passcode",
    "passphrase",
    "passwd",
    "password",
    "pbkdf",
    "pem",
    "pin",
    "pkcs",
    "pkey",
    "poly1305",
    "premaster",
    "private",
    "privatekey",
    "privkey",
    "psk",
    "pwd",
    "random",
    "refresh",
    "refreshtoken",
    "rng",
    "rsa",
    "salt",
    "secret",
    "seed",
    "session",
    "sessionid",
    "sha",
    "sharedkey",
    "signature",
    "signingkey",
    "skey",
    "ssl",
    "ticket",
    "tls",
    "token",
    "totp",
    "trafficsecret",
    "vault",
    "x509",
}

SENSITIVE_RE = re.compile("|".join(re.escape(term) for term in sorted(SENSITIVE_TERMS, key=len, reverse=True)))


def _node_text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _identifier_name(node) -> str:
    ids = find_nodes_by_type(node, "identifier")
    if not ids:
        return ""
    return _node_text(ids[-1]).strip()


def _declarator_name(node) -> str:
    ids = find_nodes_by_type(node, "identifier")
    if not ids:
        return ""
    return _node_text(ids[0]).strip()


def _normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def _sensitive_matches(name: str, declaration: str) -> list[str]:
    haystack = f"{_normalize(name)} {_normalize(declaration)}"
    matches = {match.group(0) for match in SENSITIVE_RE.finditer(haystack)}
    return sorted(matches)


def _type_fragment(declaration: str, name: str) -> str:
    if not declaration or not name:
        return ""
    idx = declaration.find(name)
    if idx < 0:
        return declaration.strip()
    return declaration[:idx].strip(" \t\n=*&,")


def _variable_item(name: str, kind: str, node, declaration_node=None) -> dict:
    declaration = _node_text(declaration_node or node).strip()
    return {
        "name": name,
        "kind": kind,
        "line": node.start_point[0] + 1,
        "declaration": declaration,
        "type": _type_fragment(declaration, name),
        "matches": _sensitive_matches(name, declaration),
    }


def _extract_parameters(root) -> list[dict]:
    variables: list[dict] = []
    for node_type in ("parameter_declaration", "optional_parameter_declaration"):
        for param in find_nodes_by_type(root, node_type):
            name = _identifier_name(param)
            if not name:
                continue
            variables.append(_variable_item(name, "parameter", param))
    return variables


def _extract_local_variables(root) -> list[dict]:
    variables: list[dict] = []
    for decl in find_nodes_by_type(root, "declaration"):
        if any(c.type == "function_declarator" for c in decl.children):
            continue
        for child in decl.children:
            if child.type in {
                "init_declarator",
                "pointer_declarator",
                "array_declarator",
                "reference_declarator",
                "identifier",
            }:
                name = _declarator_name(child)
                if not name:
                    continue
                variables.append(_variable_item(name, "local", child, decl))

    for decl in find_nodes_by_type(root, "for_range_declaration"):
        name = _identifier_name(decl)
        if name:
            variables.append(_variable_item(name, "local", decl))
    return variables


def _extract_variables(body_source: str) -> list[dict]:
    parser = Parser(CPP_LANGUAGE)
    tree = parser.parse(body_source.encode("utf-8"))
    root = tree.root_node

    variables: list[dict] = []
    seen: set[tuple[str, str, int]] = set()
    for item in _extract_parameters(root) + _extract_local_variables(root):
        if not item["matches"]:
            continue
        key = (item["kind"], item["name"], int(item["line"]))
        if key in seen:
            continue
        seen.add(key)
        variables.append(item)
    return variables


def _row_value(row, key: str, default=None):
    try:
        value = row[key]
    except (KeyError, IndexError, TypeError):
        value = getattr(row, key, default)
    return default if value is None else value


def _build_function_candidate(func: dict, variables: list[dict]) -> Candidate:
    function_name = str(_row_value(func, "name", "") or "")
    file_path = str(_row_value(func, "file_path", "") or "")
    start_line = int(_row_value(func, "start_line", 1) or 1)
    end_line = int(_row_value(func, "end_line", start_line) or start_line)
    candidate_id = f"sensitive-clear-{file_path}:{start_line}:{function_name}"
    suspicious_variables = [
        {
            "name": variable["name"],
            "kind": variable["kind"],
            "line": start_line + int(variable["line"]) - 1,
            "type": variable["type"],
            "declaration": variable["declaration"],
            "matches": variable["matches"],
        }
        for variable in variables
    ]
    return Candidate(
        file=file_path,
        line=start_line,
        function=function_name,
        description=(
            f"敏感信息未清零函数审计: 函数 {function_name} 存在启发式敏感变量线索，"
            "需要审计变量生命周期结束后是否显式清零。"
        ),
        vuln_type="sensitive_clear",
        metadata={
            "kind": "sensitive_clear_function",
            "candidate_id": candidate_id,
            "function_name": function_name,
            "file": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "suspicious_variables": suspicious_variables,
        },
    )


class Analyzer(BaseAnalyzer):
    """按函数生成敏感信息未清零审计候选。"""

    vuln_type = "sensitive_clear"

    def find_candidates(self, project_path: Path, db=None) -> list[Candidate]:
        if db is None:
            return []

        candidates: list[Candidate] = []
        functions = db.get_all_functions()
        total = len(functions)
        for idx, func in enumerate(functions):
            if self.on_file_progress:
                self.on_file_progress(idx + 1, total)

            body = str(_row_value(func, "body", "") or "")
            if not body:
                continue

            variables = _extract_variables(body)
            if not variables:
                continue

            candidates.append(_build_function_candidate(func, variables))

        return candidates
