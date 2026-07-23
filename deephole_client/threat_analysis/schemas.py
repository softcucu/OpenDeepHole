"""JSON schemas used by threat-analysis agent tasks."""

from __future__ import annotations

from typing import Any


YES_NO = {"type": "string", "enum": ["是", "否"]}
NON_EMPTY_STRING = {"type": "string", "minLength": 1}


VALUE_ASSET_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "资产名",
        "资产类别",
        "资产描述",
        "攻击损失",
        "判断为价值资产的原因",
    ],
    "properties": {
        "资产名": NON_EMPTY_STRING,
        "资产类别": {
            "type": "string",
            "enum": ["数据资产", "软件资产", "硬件资产", "服务资产"],
        },
        "资产描述": NON_EMPTY_STRING,
        "攻击损失": NON_EMPTY_STRING,
        "判断为价值资产的原因": NON_EMPTY_STRING,
    },
    "additionalProperties": False,
}

VALUE_ASSETS_SCHEMA: dict[str, Any] = {
    "type": "array",
    "items": VALUE_ASSET_ITEM_SCHEMA,
}


HIGH_RISK_MODULE_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "模块名称",
        "代码目录",
        "面临威胁",
        "是否涉及设备或系统对外提供管理和控制接口相关的代码",
        "是否涉及对不可信来源数据进行解析或处理的代码",
        "是否涉及安全相关类代码(如，认证、授权、接入控制、加解密、密钥管理、日志审计、软件完整性保护等模块)",
        "是否涉及个人数据或者敏感数据的代码",
        "是否涉及web相关处理",
        "是否外部暴露面",
        "判断为高风险模块的原因",
    ],
    "properties": {
        "模块名称": NON_EMPTY_STRING,
        "代码目录": {
            "type": ["string", "array"],
            "items": NON_EMPTY_STRING,
        },
        "面临威胁": NON_EMPTY_STRING,
        "是否涉及设备或系统对外提供管理和控制接口相关的代码": YES_NO,
        "是否涉及对不可信来源数据进行解析或处理的代码": YES_NO,
        "是否涉及安全相关类代码(如，认证、授权、接入控制、加解密、密钥管理、日志审计、软件完整性保护等模块)": YES_NO,
        "是否涉及个人数据或者敏感数据的代码": YES_NO,
        "是否涉及web相关处理": YES_NO,
        "是否外部暴露面": YES_NO,
        "判断为高风险模块的原因": NON_EMPTY_STRING,
    },
    "additionalProperties": False,
}

HIGH_RISK_MODULES_SCHEMA: dict[str, Any] = {
    "type": "array",
    "items": HIGH_RISK_MODULE_ITEM_SCHEMA,
}


ATTACK_PATTERN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["pattern_id", "pattern_name", "association_description"],
    "properties": {
        "pattern_id": {"type": "string"},
        "pattern_name": {"type": "string"},
        "association_description": NON_EMPTY_STRING,
    },
    "additionalProperties": False,
}

RELATED_HIGH_RISK_MODULE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "module_name",
        "node_id",
        "external_exposure",
        "path_role",
        "association_description",
    ],
    "properties": {
        "module_name": NON_EMPTY_STRING,
        "node_id": NON_EMPTY_STRING,
        "external_exposure": {"type": "boolean"},
        "path_role": {
            "type": "string",
            "enum": ["外部攻击入口", "内部影响模块", "直接资产影响模块"],
        },
        "association_description": NON_EMPTY_STRING,
    },
    "additionalProperties": False,
}

ATTACK_TREE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["attack_trees"],
    "properties": {
        "attack_trees": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["tree_id", "value_asset", "nodes", "edges", "attack_paths"],
                "properties": {
                    "tree_id": NON_EMPTY_STRING,
                    "value_asset": {
                        "type": "object",
                        "required": [
                            "asset_name",
                            "asset_category",
                            "asset_description",
                            "attack_loss",
                        ],
                        "properties": {
                            "asset_name": NON_EMPTY_STRING,
                            "asset_category": {
                                "type": "string",
                                "enum": ["数据资产", "软件资产", "硬件资产", "服务资产"],
                            },
                            "asset_description": NON_EMPTY_STRING,
                            "attack_loss": NON_EMPTY_STRING,
                        },
                        "additionalProperties": False,
                    },
                    "nodes": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": [
                                "node_id",
                                "node_type",
                                "node_name",
                                "description",
                                "module_name",
                                "is_high_risk_module",
                                "external_exposure",
                                "external_interface_description",
                            ],
                            "properties": {
                                "node_id": NON_EMPTY_STRING,
                                "node_type": {
                                    "type": "string",
                                    "enum": ["根节点", "内部节点", "叶子节点"],
                                },
                                "node_name": NON_EMPTY_STRING,
                                "description": NON_EMPTY_STRING,
                                "module_name": {"type": ["string", "null"]},
                                "is_high_risk_module": {"type": "boolean"},
                                "external_exposure": {"type": "boolean"},
                                "external_interface_description": {"type": ["string", "null"]},
                            },
                            "additionalProperties": False,
                        },
                    },
                    "edges": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": [
                                "edge_id",
                                "source_node_id",
                                "target_node_id",
                                "influence_type",
                                "description",
                            ],
                            "properties": {
                                "edge_id": NON_EMPTY_STRING,
                                "source_node_id": NON_EMPTY_STRING,
                                "target_node_id": NON_EMPTY_STRING,
                                "influence_type": {
                                    "type": "string",
                                    "enum": ["调用", "数据传递", "消息传递", "控制", "依赖", "直接影响"],
                                },
                                "description": NON_EMPTY_STRING,
                            },
                            "additionalProperties": False,
                        },
                    },
                    "attack_paths": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": [
                                "path_id",
                                "path_name",
                                "node_ids",
                                "edge_ids",
                                "path_description",
                                "related_high_risk_modules",
                                "attack_patterns",
                            ],
                            "properties": {
                                "path_id": NON_EMPTY_STRING,
                                "path_name": NON_EMPTY_STRING,
                                "node_ids": {"type": "array", "items": NON_EMPTY_STRING},
                                "edge_ids": {"type": "array", "items": NON_EMPTY_STRING},
                                "path_description": NON_EMPTY_STRING,
                                "related_high_risk_modules": {
                                    "type": "array",
                                    "items": RELATED_HIGH_RISK_MODULE_SCHEMA,
                                },
                                "attack_patterns": {
                                    "type": "array",
                                    "items": ATTACK_PATTERN_SCHEMA,
                                },
                            },
                            "additionalProperties": False,
                        },
                    },
                },
                "additionalProperties": False,
            },
        },
    },
    "additionalProperties": False,
}
