"""HTML templates for metrics visualizations."""

HTML_TREE_TEMPLATE = """
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
        .children {
            margin-left: 20px;
        }
        .node-label {
            font-weight: bold;
            color: #333;
        }
        .node-value {
            color: #666;
            font-style: italic;
        }
        .node-details {
            color: #888;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{ title }}</h1>

        {% if stats %}
        <div class="stats">
            <h2>Statistics</h2>
            <p>Total Nodes: {{ stats.total_nodes }}</p>
            <p>Rules: {{ stats.rule_count }}</p>
            <p>Imports: {{ stats.import_count }}</p>
            <p>Strings: {{ stats.string_count }}</p>
        </div>
        {% endif %}

        <div class="tree">
            {{ render_node(tree_data, 0) }}
        </div>
    </div>

    <script>
        document.querySelectorAll('.toggle').forEach(toggle => {
            toggle.addEventListener('click', () => {
                const children = toggle.parentElement.nextElementSibling;
                if (children) {
                    children.style.display = children.style.display === 'none' ? 'block' : 'none';
                    toggle.textContent = children.style.display === 'none' ? '▶' : '▼';
                }
            });
        });
    </script>
</body>
</html>
"""

INTERACTIVE_HTML_TREE_TEMPLATE = """
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
        .search-box {
            margin-bottom: 20px;
            text-align: center;
        }
        .search-box input {
            padding: 10px;
            width: 60%;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
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
        .children {
            margin-left: 20px;
        }
        .node-label {
            font-weight: bold;
            color: #333;
        }
        .node-value {
            color: #666;
            font-style: italic;
        }
        .node-details {
            color: #888;
            font-size: 0.9em;
        }
        .highlight {
            background-color: #ffeb3b !important;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{ title }}</h1>

        <div class="search-box">
            <input type="text" id="searchInput" placeholder="Search nodes...">
        </div>

        <div class="tree">
            {{ render_node(tree_data, 0) }}
        </div>
    </div>

    <script>
        // Toggle functionality
        document.querySelectorAll('.toggle').forEach(toggle => {
            toggle.addEventListener('click', () => {
                const children = toggle.parentElement.nextElementSibling;
                if (children) {
                    children.style.display = children.style.display === 'none' ? 'block' : 'none';
                    toggle.textContent = children.style.display === 'none' ? '▶' : '▼';
                }
            });
        });

        function searchNodes(query) {
            const normalized = (query || '').toLowerCase();
            document.querySelectorAll('.tree-node').forEach(node => {
                const text = node.textContent.toLowerCase();
                if (normalized && text.includes(normalized)) {
                    node.classList.add('highlight');
                } else {
                    node.classList.remove('highlight');
                }
            });
        }

        function filterNodes(query) {
            searchNodes(query);
        }

        // Search functionality
        const searchInput = document.getElementById('searchInput');
        searchInput.addEventListener('input', function() {
            searchNodes(this.value);
        });
    </script>
</body>
</html>
"""
