"""HTML collapsible tree visualization for YARA AST."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import Template

from yaraast.visitor import ASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import ASTNode, YaraFile
    from yaraast.ast.rules import Rule
    from yaraast.ast.strings import HexString, PlainString, RegexString


class HtmlTreeGenerator(ASTVisitor[dict[str, Any]]):
    """Generates HTML collapsible tree visualization from YARA AST."""

    def __init__(self, include_metadata: bool = True) -> None:
        self.include_metadata = include_metadata
        self.node_counter = 0

    def generate_html(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        title: str = "YARA AST Visualization",
    ) -> str:
        """Generate HTML tree visualization."""
        self.node_counter = 0
        tree_data = self.visit(ast)

        html_content = self._render_html_template(tree_data, title)

        if output_path:
            with Path(output_path).open("w", encoding="utf-8") as f:
                f.write(html_content)

        return html_content

    def generate_interactive_html(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        title: str = "Interactive YARA AST",
    ) -> str:
        """Generate interactive HTML with search and filtering."""
        self.node_counter = 0
        tree_data = self.visit(ast)

        html_content = self._render_interactive_template(tree_data, title)

        if output_path:
            with Path(output_path).open("w", encoding="utf-8") as f:
                f.write(html_content)

        return html_content

    def _get_node_id(self) -> str:
        """Get unique node ID."""
        self.node_counter += 1
        return f"node_{self.node_counter}"

    def _render_html_template(self, tree_data: dict[str, Any], title: str) -> str:
        """Render HTML template with tree data."""
        template = Template(
            """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        body {
            font-family: 'Consolas', 'Monaco', 'Lucida Console', monospace;
            line-height: 1.6;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }
        .tree {
            margin: 20px 0;
        }
        .tree-node {
            margin: 2px 0;
            padding: 4px 8px;
            border-radius: 4px;
            position: relative;
        }
        .tree-node.yara-file { background-color: #e3f2fd; border-left: 4px solid #2196f3; }
        .tree-node.rule { background-color: #f3e5f5; border-left: 4px solid #9c27b0; }
        .tree-node.import { background-color: #e8f5e8; border-left: 4px solid #4caf50; }
        .tree-node.include { background-color: #fff3e0; border-left: 4px solid #ff9800; }
        .tree-node.string { background-color: #fce4ec; border-left: 4px solid #e91e63; }
        .tree-node.condition { background-color: #f1f8e9; border-left: 4px solid #8bc34a; }
        .tree-node.expression { background-color: #e0f2f1; border-left: 4px solid #009688; }
        .tree-node.literal { background-color: #f9fbe7; border-left: 4px solid #cddc39; }

        .toggle {
            cursor: pointer;
            user-select: none;
            font-weight: bold;
            color: #666;
            margin-right: 8px;
        }
        .toggle:hover {
            color: #333;
        }
        .toggle.expanded::before {
            content: "▼ ";
        }
        .toggle.collapsed::before {
            content: "▶ ";
        }

        .node-content {
            display: inline-block;
            vertical-align: top;
        }
        .node-label {
            font-weight: bold;
            color: #333;
        }
        .node-details {
            color: #666;
            font-size: 0.9em;
            margin-left: 16px;
        }
        .node-value {
            color: #d32f2f;
            font-style: italic;
        }

        .children {
            margin-left: 20px;
            border-left: 1px dotted #ccc;
            padding-left: 16px;
        }
        .children.hidden {
            display: none;
        }

        .stats {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            border: 1px solid #dee2e6;
        }
        .stats h3 {
            margin-top: 0;
            color: #495057;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
        }
        .stat-item {
            background: white;
            padding: 10px;
            border-radius: 4px;
            border: 1px solid #e9ecef;
        }
        .stat-value {
            font-size: 1.5em;
            font-weight: bold;
            color: #007bff;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{ title }}</h1>

        {% if stats %}
        <div class="stats">
            <h3>📊 AST Statistics</h3>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value">{{ stats.rules }}</div>
                    <div>Rules</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{ stats.imports }}</div>
                    <div>Imports</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{ stats.strings }}</div>
                    <div>Total Strings</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{ stats.nodes }}</div>
                    <div>AST Nodes</div>
                </div>
            </div>
        </div>
        {% endif %}

        <div class="tree">
            {{ render_node(tree_data, 0) }}
        </div>
    </div>

    <script>
        function toggleNode(nodeId) {
            const children = document.getElementById(nodeId + '_children');
            const toggle = document.getElementById(nodeId + '_toggle');

            if (children.classList.contains('hidden')) {
                children.classList.remove('hidden');
                toggle.classList.remove('collapsed');
                toggle.classList.add('expanded');
            } else {
                children.classList.add('hidden');
                toggle.classList.remove('expanded');
                toggle.classList.add('collapsed');
            }
        }

        // Expand all nodes by default for better visibility
        document.addEventListener('DOMContentLoaded', function() {
            const toggles = document.querySelectorAll('.toggle');
            toggles.forEach(toggle => toggle.classList.add('expanded'));
        });
    </script>
</body>
</html>

{% macro render_node(node, depth) %}
    <div class="tree-node {{ node.node_class }}">
        {% if node.children %}
            <span class="toggle expanded" id="{{ node.id }}_toggle"
                  onclick="toggleNode('{{ node.id }}')"></span>
        {% endif %}

        <div class="node-content">
            <span class="node-label">{{ node.label }}</span>
            {% if node.value %}
                <span class="node-value">{{ node.value }}</span>
            {% endif %}
            {% if node.details %}
                <div class="node-details">{{ node.details }}</div>
            {% endif %}
        </div>

        {% if node.children %}
            <div class="children" id="{{ node.id }}_children">
                {% for child in node.children %}
                    {{ render_node(child, depth + 1) }}
                {% endfor %}
            </div>
        {% endif %}
    </div>
{% endmacro %}
        """,
        )

        # Calculate statistics
        stats = self._calculate_stats(tree_data) if self.include_metadata else None

        return template.render(
            title=title,
            tree_data=tree_data,
            stats=stats,
            render_node=self._create_render_macro(),
        )

    def _render_interactive_template(
        self,
        tree_data: dict[str, Any],
        title: str,
    ) -> str:
        """Render interactive HTML template with search and filtering."""
        template = Template(
            """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        /* Include all styles from basic template */
        body {
            font-family: 'Consolas', 'Monaco', 'Lucida Console', monospace;
            line-height: 1.6;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .controls {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border: 1px solid #dee2e6;
        }
        .control-group {
            display: flex;
            gap: 15px;
            align-items: center;
            margin-bottom: 15px;
        }
        .control-group:last-child {
            margin-bottom: 0;
        }
        .control-group label {
            font-weight: bold;
            min-width: 80px;
        }
        .control-group input, .control-group select {
            padding: 8px 12px;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 14px;
        }
        .control-group input[type="text"] {
            min-width: 200px;
        }
        .btn {
            padding: 8px 16px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .btn:hover {
            background: #0056b3;
        }
        .btn.secondary {
            background: #6c757d;
        }
        .btn.secondary:hover {
            background: #545b62;
        }

        /* Tree styles from basic template */
        .tree-node {
            margin: 2px 0;
            padding: 4px 8px;
            border-radius: 4px;
            position: relative;
        }
        .tree-node.yara-file { background-color: #e3f2fd; border-left: 4px solid #2196f3; }
        .tree-node.rule { background-color: #f3e5f5; border-left: 4px solid #9c27b0; }
        .tree-node.import { background-color: #e8f5e8; border-left: 4px solid #4caf50; }
        .tree-node.string { background-color: #fce4ec; border-left: 4px solid #e91e63; }
        .tree-node.condition { background-color: #f1f8e9; border-left: 4px solid #8bc34a; }
        .tree-node.expression { background-color: #e0f2f1; border-left: 4px solid #009688; }

        .toggle {
            cursor: pointer;
            user-select: none;
            font-weight: bold;
            color: #666;
            margin-right: 8px;
        }
        .toggle.expanded::before { content: "▼ "; }
        .toggle.collapsed::before { content: "▶ "; }

        .node-content {
            display: inline-block;
            vertical-align: top;
        }
        .node-label {
            font-weight: bold;
            color: #333;
        }
        .node-details {
            color: #666;
            font-size: 0.9em;
            margin-left: 16px;
        }
        .node-value {
            color: #d32f2f;
            font-style: italic;
        }

        .children {
            margin-left: 20px;
            border-left: 1px dotted #ccc;
            padding-left: 16px;
        }
        .children.hidden { display: none; }

        .highlighted {
            background-color: yellow !important;
            font-weight: bold;
        }
        .filtered-out {
            opacity: 0.3;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{ title }}</h1>

        <div class="controls">
            <div class="control-group">
                <label>Search:</label>
                <input type="text" id="searchInput" placeholder="Search AST nodes...">
                <button class="btn" onclick="searchNodes()">Search</button>
                <button class="btn secondary" onclick="clearSearch()">Clear</button>
            </div>
            <div class="control-group">
                <label>Filter:</label>
                <select id="filterSelect" onchange="filterNodes()">
                    <option value="">All Nodes</option>
                    <option value="rule">Rules Only</option>
                    <option value="string">Strings Only</option>
                    <option value="condition">Conditions Only</option>
                    <option value="expression">Expressions Only</option>
                </select>
                <button class="btn" onclick="expandAll()">Expand All</button>
                <button class="btn secondary" onclick="collapseAll()">Collapse All</button>
            </div>
        </div>

        <div class="tree" id="astTree">
            <!-- Tree content will be rendered here -->
        </div>
    </div>

    <script>
        let treeData = {{ tree_data | tojson }};

        function renderTree() {
            const treeContainer = document.getElementById('astTree');
            treeContainer.innerHTML = renderNode(treeData, 0);
        }

        function renderNode(node, depth) {
            let html = '<div class="tree-node ' + node.node_class + '" data-node-type="' + node.node_class + '">';

            if (node.children && node.children.length > 0) {
                html += '<span class="toggle expanded" id="' + node.id + '_toggle" onclick="toggleNode(\'' + node.id + '\')"></span>';
            }

            html += '<div class="node-content">';
            html += '<span class="node-label">' + node.label + '</span>';
            if (node.value) {
                html += '<span class="node-value">' + node.value + '</span>';
            }
            if (node.details) {
                html += '<div class="node-details">' + node.details + '</div>';
            }
            html += '</div>';

            if (node.children && node.children.length > 0) {
                html += '<div class="children" id="' + node.id + '_children">';
                for (let child of node.children) {
                    html += renderNode(child, depth + 1);
                }
                html += '</div>';
            }

            html += '</div>';
            return html;
        }

        function toggleNode(nodeId) {
            const children = document.getElementById(nodeId + '_children');
            const toggle = document.getElementById(nodeId + '_toggle');

            if (children.classList.contains('hidden')) {
                children.classList.remove('hidden');
                toggle.classList.remove('collapsed');
                toggle.classList.add('expanded');
            } else {
                children.classList.add('hidden');
                toggle.classList.remove('expanded');
                toggle.classList.add('collapsed');
            }
        }

        function searchNodes() {
            const query = document.getElementById('searchInput').value.toLowerCase();
            const nodes = document.querySelectorAll('.tree-node');

            nodes.forEach(node => {
                const text = node.textContent.toLowerCase();
                if (query && text.includes(query)) {
                    node.classList.add('highlighted');
                    // Expand parent nodes
                    let parent = node.parentElement;
                    while (parent) {
                        if (parent.classList.contains('children')) {
                            parent.classList.remove('hidden');
                            const toggleId = parent.id.replace('_children', '_toggle');
                            const toggle = document.getElementById(toggleId);
                            if (toggle) {
                                toggle.classList.remove('collapsed');
                                toggle.classList.add('expanded');
                            }
                        }
                        parent = parent.parentElement;
                    }
                } else {
                    node.classList.remove('highlighted');
                }
            });
        }

        function clearSearch() {
            document.getElementById('searchInput').value = '';
            const nodes = document.querySelectorAll('.tree-node');
            nodes.forEach(node => node.classList.remove('highlighted'));
        }

        function filterNodes() {
            const filter = document.getElementById('filterSelect').value;
            const nodes = document.querySelectorAll('.tree-node');

            nodes.forEach(node => {
                if (!filter || node.dataset.nodeType === filter) {
                    node.classList.remove('filtered-out');
                } else {
                    node.classList.add('filtered-out');
                }
            });
        }

        function expandAll() {
            const children = document.querySelectorAll('.children');
            const toggles = document.querySelectorAll('.toggle');

            children.forEach(child => child.classList.remove('hidden'));
            toggles.forEach(toggle => {
                toggle.classList.remove('collapsed');
                toggle.classList.add('expanded');
            });
        }

        function collapseAll() {
            const children = document.querySelectorAll('.children');
            const toggles = document.querySelectorAll('.toggle');

            children.forEach(child => child.classList.add('hidden'));
            toggles.forEach(toggle => {
                toggle.classList.remove('expanded');
                toggle.classList.add('collapsed');
            });
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            renderTree();
        });
    </script>
</body>
</html>
        """,
        )

        return template.render(title=title, tree_data=tree_data)

    def _create_render_macro(self):
        """Create render macro function for Jinja2."""

        def render_node(node, depth):
            html = f'<div class="tree-node {node["node_class"]}">'

            if node.get("children"):
                html += f'<span class="toggle expanded" id="{node["id"]}_toggle" onclick="toggleNode(\'{node["id"]}\')"></span>'

            html += '<div class="node-content">'
            html += f'<span class="node-label">{node["label"]}</span>'

            if node.get("value"):
                html += f'<span class="node-value">{node["value"]}</span>'

            if node.get("details"):
                html += f'<div class="node-details">{node["details"]}</div>'

            html += "</div>"

            if node.get("children"):
                html += f'<div class="children" id="{node["id"]}_children">'
                for child in node["children"]:
                    html += render_node(child, depth + 1)
                html += "</div>"

            html += "</div>"
            return html

        return render_node

    def _calculate_stats(self, tree_data: dict[str, Any]) -> dict[str, int]:
        """Calculate tree statistics."""
        stats = {"rules": 0, "imports": 0, "strings": 0, "nodes": 0}

        def count_nodes(node) -> None:
            stats["nodes"] += 1
            node_class = node.get("node_class", "")

            if node_class == "rule":
                stats["rules"] += 1
            elif node_class == "import":
                stats["imports"] += 1
            elif node_class == "string":
                stats["strings"] += 1

            children = node.get("children", [])
            if children:
                for child in children:
                    count_nodes(child)

        count_nodes(tree_data)
        return stats

    # Visitor methods
    def visit_yara_file(self, node: YaraFile) -> dict[str, Any]:
        """Visit YARA file node."""
        children = []

        for imp in node.imports:
            children.append(self.visit(imp))

        for inc in node.includes:
            children.append(self.visit(inc))

        for rule in node.rules:
            children.append(self.visit(rule))

        return {
            "id": self._get_node_id(),
            "label": "YARA File",
            "node_class": "yara-file",
            "details": f"{len(node.rules)} rules, {len(node.imports)} imports, {len(node.includes)} includes",
            "children": children,
        }

    def visit_import(self, node) -> dict[str, Any]:
        """Visit import node."""
        label = f'Import: "{node.module}"'
        if hasattr(node, "alias") and node.alias:
            label += f" as {node.alias}"

        return {
            "id": self._get_node_id(),
            "label": label,
            "node_class": "import",
            "value": node.module,
        }

    def visit_include(self, node) -> dict[str, Any]:
        """Visit include node."""
        return {
            "id": self._get_node_id(),
            "label": f'Include: "{node.path}"',
            "node_class": "include",
            "value": node.path,
        }

    def visit_rule(self, node: Rule) -> dict[str, Any]:
        """Visit rule node."""
        children = []

        # Add modifiers
        if node.modifiers:
            children.append(
                {
                    "id": self._get_node_id(),
                    "label": "Modifiers",
                    "node_class": "modifiers",
                    "value": ", ".join(node.modifiers),
                },
            )

        # Add tags
        if node.tags:
            tag_children = []
            for tag in node.tags:
                tag_children.append(self.visit(tag))
            children.append(
                {
                    "id": self._get_node_id(),
                    "label": "Tags",
                    "node_class": "tags",
                    "children": tag_children,
                },
            )

        # Add meta
        if node.meta:
            meta_children = []
            for key, value in node.meta.items():
                meta_children.append(
                    {
                        "id": self._get_node_id(),
                        "label": f"Meta: {key}",
                        "node_class": "meta",
                        "value": str(value),
                    },
                )
            children.append(
                {
                    "id": self._get_node_id(),
                    "label": "Meta",
                    "node_class": "meta-section",
                    "children": meta_children,
                },
            )

        # Add strings
        if node.strings:
            string_children = []
            for string_def in node.strings:
                string_children.append(self.visit(string_def))
            children.append(
                {
                    "id": self._get_node_id(),
                    "label": "Strings",
                    "node_class": "strings-section",
                    "children": string_children,
                },
            )

        # Add condition
        if node.condition:
            children.append(
                {
                    "id": self._get_node_id(),
                    "label": "Condition",
                    "node_class": "condition-section",
                    "children": [self.visit(node.condition)],
                },
            )

        return {
            "id": self._get_node_id(),
            "label": f"Rule: {node.name}",
            "node_class": "rule",
            "details": f"{len(node.strings)} strings, {len(node.meta)} meta",
            "children": children,
        }

    def visit_tag(self, node) -> dict[str, Any]:
        """Visit tag node."""
        return {
            "id": self._get_node_id(),
            "label": f"Tag: {node.name}",
            "node_class": "tag",
            "value": node.name,
        }

    def visit_plain_string(self, node: PlainString) -> dict[str, Any]:
        """Visit plain string node."""
        children = []

        if node.modifiers:
            mod_children = []
            for mod in node.modifiers:
                mod_children.append(self.visit(mod))
            children.append(
                {
                    "id": self._get_node_id(),
                    "label": "Modifiers",
                    "node_class": "modifiers",
                    "children": mod_children,
                },
            )

        return {
            "id": self._get_node_id(),
            "label": f"Plain String: {node.identifier}",
            "node_class": "string",
            "value": f'"{node.value}"',
            "children": children if children else None,
        }

    def visit_hex_string(self, node: HexString) -> dict[str, Any]:
        """Visit hex string node."""
        children = []

        # Add tokens
        if node.tokens:
            token_children = []
            for token in node.tokens:
                token_children.append(self.visit(token))
            children.append(
                {
                    "id": self._get_node_id(),
                    "label": "Hex Tokens",
                    "node_class": "hex-tokens",
                    "children": token_children,
                },
            )

        if node.modifiers:
            mod_children = []
            for mod in node.modifiers:
                mod_children.append(self.visit(mod))
            children.append(
                {
                    "id": self._get_node_id(),
                    "label": "Modifiers",
                    "node_class": "modifiers",
                    "children": mod_children,
                },
            )

        return {
            "id": self._get_node_id(),
            "label": f"Hex String: {node.identifier}",
            "node_class": "string",
            "details": f"{len(node.tokens)} tokens",
            "children": children if children else None,
        }

    def visit_regex_string(self, node: RegexString) -> dict[str, Any]:
        """Visit regex string node."""
        children = []

        if node.modifiers:
            mod_children = []
            for mod in node.modifiers:
                mod_children.append(self.visit(mod))
            children.append(
                {
                    "id": self._get_node_id(),
                    "label": "Modifiers",
                    "node_class": "modifiers",
                    "children": mod_children,
                },
            )

        return {
            "id": self._get_node_id(),
            "label": f"Regex String: {node.identifier}",
            "node_class": "string",
            "value": f"/{node.regex}/",
            "children": children if children else None,
        }

    def visit_string_modifier(self, node) -> dict[str, Any]:
        """Visit string modifier node."""
        value = f"{node.name}"
        if node.value:
            value += f"({node.value})"

        return {
            "id": self._get_node_id(),
            "label": "Modifier",
            "node_class": "modifier",
            "value": value,
        }

    def visit_hex_byte(self, node) -> dict[str, Any]:
        """Visit hex byte node."""
        return {
            "id": self._get_node_id(),
            "label": "Hex Byte",
            "node_class": "hex-byte",
            "value": str(node.value),
        }

    def visit_hex_wildcard(self, node) -> dict[str, Any]:
        """Visit hex wildcard node."""
        return {
            "id": self._get_node_id(),
            "label": "Hex Wildcard",
            "node_class": "hex-wildcard",
            "value": "??",
        }

    def visit_binary_expression(self, node) -> dict[str, Any]:
        """Visit binary expression node."""
        children = [
            self.visit(node.left),
            {
                "id": self._get_node_id(),
                "label": "Operator",
                "node_class": "operator",
                "value": node.operator,
            },
            self.visit(node.right),
        ]

        return {
            "id": self._get_node_id(),
            "label": "Binary Expression",
            "node_class": "expression",
            "details": f"Operator: {node.operator}",
            "children": children,
        }

    def visit_string_identifier(self, node) -> dict[str, Any]:
        """Visit string identifier node."""
        return {
            "id": self._get_node_id(),
            "label": "String Identifier",
            "node_class": "expression",
            "value": node.name,
        }

    def visit_boolean_literal(self, node) -> dict[str, Any]:
        """Visit boolean literal node."""
        return {
            "id": self._get_node_id(),
            "label": "Boolean Literal",
            "node_class": "literal",
            "value": str(node.value).lower(),
        }

    def visit_integer_literal(self, node) -> dict[str, Any]:
        """Visit integer literal node."""
        return {
            "id": self._get_node_id(),
            "label": "Integer Literal",
            "node_class": "literal",
            "value": str(node.value),
        }

    # Required visitor methods (minimal implementations)
    def visit_string_definition(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "String Definition",
            "node_class": "string",
        }

    def visit_hex_token(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Hex Token",
            "node_class": "hex-token",
        }

    def visit_hex_jump(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Hex Jump",
            "node_class": "hex-jump",
        }

    def visit_hex_alternative(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Hex Alternative",
            "node_class": "hex-alt",
        }

    def visit_hex_nibble(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Hex Nibble",
            "node_class": "hex-nibble",
        }

    def visit_expression(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Expression",
            "node_class": "expression",
        }

    def visit_identifier(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Identifier",
            "node_class": "expression",
            "value": node.name,
        }

    def visit_string_count(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "String Count",
            "node_class": "expression",
        }

    def visit_string_offset(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "String Offset",
            "node_class": "expression",
        }

    def visit_string_length(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "String Length",
            "node_class": "expression",
        }

    def visit_double_literal(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Double Literal",
            "node_class": "literal",
        }

    def visit_string_literal(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "String Literal",
            "node_class": "literal",
        }

    def visit_regex_literal(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Regex Literal",
            "node_class": "literal",
        }

    def visit_unary_expression(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Unary Expression",
            "node_class": "expression",
        }

    def visit_parentheses_expression(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Parentheses Expression",
            "node_class": "expression",
        }

    def visit_set_expression(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Set Expression",
            "node_class": "expression",
        }

    def visit_range_expression(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Range Expression",
            "node_class": "expression",
        }

    def visit_function_call(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Function Call",
            "node_class": "expression",
        }

    def visit_array_access(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Array Access",
            "node_class": "expression",
        }

    def visit_member_access(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Member Access",
            "node_class": "expression",
        }

    def visit_condition(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Condition",
            "node_class": "condition",
        }

    def visit_for_expression(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "For Expression",
            "node_class": "expression",
        }

    def visit_for_of_expression(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "For-Of Expression",
            "node_class": "expression",
        }

    def visit_at_expression(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "At Expression",
            "node_class": "expression",
        }

    def visit_in_expression(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "In Expression",
            "node_class": "expression",
        }

    def visit_of_expression(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Of Expression",
            "node_class": "expression",
        }

    def visit_meta(self, node) -> dict[str, Any]:
        return {"id": self._get_node_id(), "label": "Meta", "node_class": "meta"}

    def visit_module_reference(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Module Reference",
            "node_class": "expression",
        }

    def visit_dictionary_access(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Dictionary Access",
            "node_class": "expression",
        }

    def visit_comment(self, node) -> dict[str, Any]:
        return {"id": self._get_node_id(), "label": "Comment", "node_class": "comment"}

    def visit_comment_group(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Comment Group",
            "node_class": "comment",
        }

    def visit_defined_expression(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Defined Expression",
            "node_class": "expression",
        }

    def visit_string_operator_expression(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "String Operator Expression",
            "node_class": "expression",
        }

    def visit_extern_import(self, node) -> dict[str, Any]:
        """Visit ExternImport node."""
        return {
            "id": self._get_node_id(),
            "label": "Extern Import",
            "node_class": "import",
        }

    def visit_extern_namespace(self, node) -> dict[str, Any]:
        """Visit ExternNamespace node."""
        return {
            "id": self._get_node_id(),
            "label": "Extern Namespace",
            "node_class": "namespace",
        }

    def visit_extern_rule(self, node) -> dict[str, Any]:
        """Visit ExternRule node."""
        return {"id": self._get_node_id(), "label": "Extern Rule", "node_class": "rule"}

    def visit_extern_rule_reference(self, node) -> dict[str, Any]:
        """Visit ExternRuleReference node."""
        return {
            "id": self._get_node_id(),
            "label": "Extern Rule Reference",
            "node_class": "expression",
        }

    def visit_in_rule_pragma(self, node) -> dict[str, Any]:
        """Visit InRulePragma node."""
        return {
            "id": self._get_node_id(),
            "label": "In-Rule Pragma",
            "node_class": "pragma",
        }

    def visit_pragma(self, node) -> dict[str, Any]:
        """Visit Pragma node."""
        return {"id": self._get_node_id(), "label": "Pragma", "node_class": "pragma"}

    def visit_pragma_block(self, node) -> dict[str, Any]:
        """Visit PragmaBlock node."""
        return {
            "id": self._get_node_id(),
            "label": "Pragma Block",
            "node_class": "pragma",
        }


# Alias for compatibility
HTMLTreeGenerator = HtmlTreeGenerator


def generate_html_tree(ast: YaraFile, title: str = "YARA AST") -> str:
    """Generate HTML tree visualization from AST."""
    gen = HTMLTreeGenerator()
    return gen.generate_html(ast, None, title)


def create_node_html(node: ASTNode) -> str:
    """Create HTML for a single AST node."""
    gen = HTMLTreeGenerator()
    node_data = node.accept(gen)

    html = f'<div class="tree-node {node_data.get("node_class", "")}">'
    html += f'<span class="node-label">{node_data.get("label", "")}</span>'

    if node_data.get("value"):
        html += f'<span class="node-value">{node_data["value"]}</span>'

    if node_data.get("details"):
        html += f'<div class="node-details">{node_data["details"]}</div>'

    html += "</div>"
    return html


def generate_ast_tree(ast: YaraFile) -> dict[str, Any]:
    """Generate tree data structure from AST."""
    gen = HTMLTreeGenerator()
    return gen.visit(ast)


def export_html_tree(
    ast: YaraFile,
    output_path: str | Path,
    title: str = "YARA AST Visualization",
) -> None:
    """Export HTML tree visualization to file."""
    gen = HTMLTreeGenerator()
    gen.generate_html(ast, str(output_path), title)


# Add generate method to HTMLTreeGenerator for better compatibility
def _generate_method(
    self,
    ast: YaraFile,
    title: str = "YARA AST",
    expand_level: int = 2,
    show_attributes: bool = True,
    custom_css: str = "",
    custom_js: str = "",
) -> str:
    """Generate HTML tree visualization."""
    html = self.generate_html(ast, None, title)

    # Add custom CSS/JS if provided
    if custom_css:
        html = html.replace("</style>", f"{custom_css}\n</style>")
    if custom_js:
        html = html.replace("</script>", f"{custom_js}\n</script>")

    return html


HTMLTreeGenerator.generate = _generate_method
