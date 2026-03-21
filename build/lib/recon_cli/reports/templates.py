"""
Report Templates for ReconnV2.

Provides:
- Custom template engine
- Built-in templates
- Template loading and parsing

Example:
    >>> from recon_cli.reports.templates import TemplateEngine
    >>> engine = TemplateEngine()
    >>> html = engine.render("executive", data)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

__all__ = [
    "ReportTemplate",
    "TemplateEngine",
    "TemplateContext",
    "load_template",
    "BUILTIN_TEMPLATES",
]


@dataclass
class TemplateContext:
    """Context for template rendering."""

    data: Dict[str, Any] = field(default_factory=dict)
    filters: Dict[str, Callable] = field(default_factory=dict)
    helpers: Dict[str, Callable] = field(default_factory=dict)

    def __post_init__(self):
        # Add default filters
        self.filters.update(
            {
                "upper": str.upper,
                "lower": str.lower,
                "title": str.title,
                "date": lambda x: (
                    x.strftime("%Y-%m-%d") if hasattr(x, "strftime") else str(x)
                ),
                "datetime": lambda x: (
                    x.strftime("%Y-%m-%d %H:%M:%S")
                    if hasattr(x, "strftime")
                    else str(x)
                ),
                "json": lambda x: __import__("json").dumps(x, default=str),
                "len": len,
                "sum": sum,
                "default": lambda x, d="": x if x else d,
                "truncate": lambda x, n=50: x[:n] + "..." if len(str(x)) > n else x,
                "nl2br": lambda x: str(x).replace("\n", "<br>"),
                "escape": lambda x: (
                    str(x)
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                ),
            }
        )

        # Add default helpers
        self.helpers.update(
            {
                "now": datetime.now,
                "range": range,
                "enumerate": enumerate,
                "zip": zip,
            }
        )

    def get(self, key: str, default: Any = None) -> Any:
        """Get value from context."""
        parts = key.split(".")
        value = self.data

        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            elif hasattr(value, part):
                value = getattr(value, part)
            else:
                return default

            if value is None:
                return default

        return value

    def apply_filter(self, value: Any, filter_name: str, *args) -> Any:
        """Apply a filter to a value."""
        filter_func = self.filters.get(filter_name)
        if filter_func:
            return filter_func(value, *args) if args else filter_func(value)
        return value


@dataclass
class ReportTemplate:
    """Report template definition."""

    name: str
    content: str
    description: str = ""
    file_extension: str = "html"
    variables: List[str] = field(default_factory=list)
    sections: List[str] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: Path) -> "ReportTemplate":
        """Load template from file."""
        content = path.read_text()
        name = path.stem

        # Parse metadata from comments
        description = ""
        variables = []

        # Look for template metadata in comments
        meta_match = re.search(r"<!--\s*TEMPLATE\s*(.*?)\s*-->", content, re.DOTALL)
        if meta_match:
            meta_text = meta_match.group(1)
            desc_match = re.search(r"description:\s*(.+)", meta_text)
            if desc_match:
                description = desc_match.group(1).strip()

            vars_match = re.search(r"variables:\s*(.+)", meta_text)
            if vars_match:
                variables = [v.strip() for v in vars_match.group(1).split(",")]

        return cls(
            name=name,
            content=content,
            description=description,
            file_extension=path.suffix[1:] if path.suffix else "html",
            variables=variables,
        )

    def to_file(self, path: Path) -> None:
        """Save template to file."""
        path.write_text(self.content)


class TemplateEngine:
    """Simple template engine for report generation."""

    # Pattern for {{ variable }} or {{ variable|filter }}
    VAR_PATTERN = re.compile(r"\{\{\s*(.+?)\s*\}\}")

    # Pattern for {% if %} {% endif %}
    IF_PATTERN = re.compile(r"\{%\s*if\s+(.+?)\s*%\}(.*?)\{%\s*endif\s*%\}", re.DOTALL)

    # Pattern for {% for item in list %} {% endfor %}
    FOR_PATTERN = re.compile(
        r"\{%\s*for\s+(\w+)\s+in\s+(.+?)\s*%\}(.*?)\{%\s*endfor\s*%\}", re.DOTALL
    )

    # Pattern for {% block name %}{% endblock %}
    BLOCK_PATTERN = re.compile(
        r"\{%\s*block\s+(\w+)\s*%\}(.*?)\{%\s*endblock\s*%\}", re.DOTALL
    )

    # Pattern for {% include "template" %}
    INCLUDE_PATTERN = re.compile(r"\{%\s*include\s+[\"'](.+?)[\"']\s*%\}")

    def __init__(self, templates_dir: Optional[Path] = None):
        self.templates_dir = templates_dir
        self._templates: Dict[str, ReportTemplate] = {}
        self._load_builtin_templates()

    def _load_builtin_templates(self) -> None:
        """Load built-in templates."""
        for name, template in BUILTIN_TEMPLATES.items():
            self._templates[name] = template

    def register_template(self, template: ReportTemplate) -> None:
        """Register a template."""
        self._templates[template.name] = template

    def load_template(self, name: str) -> Optional[ReportTemplate]:
        """Load a template by name."""
        # Check registered templates
        if name in self._templates:
            return self._templates[name]

        # Check templates directory
        if self.templates_dir:
            for ext in ["html", "md", "txt"]:
                path = self.templates_dir / f"{name}.{ext}"
                if path.exists():
                    template = ReportTemplate.from_file(path)
                    self._templates[name] = template
                    return template

        return None

    def render(
        self,
        template_name: str,
        data: Dict[str, Any],
        context: Optional[TemplateContext] = None,
    ) -> str:
        """Render a template with data."""
        template = self.load_template(template_name)
        if template is None:
            raise ValueError(f"Template not found: {template_name}")

        return self.render_string(template.content, data, context)

    def render_string(
        self,
        content: str,
        data: Dict[str, Any],
        context: Optional[TemplateContext] = None,
    ) -> str:
        """Render a template string with data."""
        ctx = context or TemplateContext()
        ctx.data.update(data)

        # Process includes first
        content = self._process_includes(content)

        # Process for loops
        content = self._process_for_loops(content, ctx)

        # Process if statements
        content = self._process_if_statements(content, ctx)

        # Process variables
        content = self._process_variables(content, ctx)

        return content

    def _process_includes(self, content: str) -> str:
        """Process {% include %} tags."""

        def replace_include(match):
            template_name = match.group(1)
            template = self.load_template(template_name)
            if template:
                return template.content
            return f"<!-- Template not found: {template_name} -->"

        return self.INCLUDE_PATTERN.sub(replace_include, content)

    def _process_for_loops(self, content: str, ctx: TemplateContext) -> str:
        """Process {% for %} loops."""

        def replace_for(match):
            var_name = match.group(1)
            iterable_expr = match.group(2).strip()
            loop_content = match.group(3)

            # Get iterable
            iterable = ctx.get(iterable_expr, [])
            if not iterable:
                return ""

            # Render loop iterations
            results = []
            for i, item in enumerate(iterable):
                loop_ctx = TemplateContext(
                    data={
                        **ctx.data,
                        var_name: item,
                        "loop": {
                            "index": i,
                            "index1": i + 1,
                            "first": i == 0,
                            "last": i == len(iterable) - 1,
                            "length": len(iterable),
                        },
                    }
                )
                loop_ctx.filters = ctx.filters
                loop_ctx.helpers = ctx.helpers

                rendered = self._process_for_loops(loop_content, loop_ctx)
                rendered = self._process_if_statements(rendered, loop_ctx)
                rendered = self._process_variables(rendered, loop_ctx)
                results.append(rendered)

            return "".join(results)

        return self.FOR_PATTERN.sub(replace_for, content)

    def _process_if_statements(self, content: str, ctx: TemplateContext) -> str:
        """Process {% if %} statements."""

        def replace_if(match):
            condition = match.group(1).strip()
            if_content = match.group(2)

            # Parse else
            else_match = re.search(r"\{%\s*else\s*%\}", if_content)
            if else_match:
                true_content = if_content[: else_match.start()]
                false_content = if_content[else_match.end() :]
            else:
                true_content = if_content
                false_content = ""

            # Evaluate condition
            result = self._evaluate_condition(condition, ctx)

            if result:
                return true_content
            else:
                return false_content

        return self.IF_PATTERN.sub(replace_if, content)

    def _evaluate_condition(self, condition: str, ctx: TemplateContext) -> bool:
        """Evaluate a condition expression."""
        # Handle comparison operators
        for op in [" == ", " != ", " > ", " < ", " >= ", " <= ", " in "]:
            if op in condition:
                parts = condition.split(op, 1)
                left = self._get_value(parts[0].strip(), ctx)
                right = self._get_value(parts[1].strip(), ctx)

                if op == " == ":
                    return left == right
                elif op == " != ":
                    return left != right
                elif op == " > ":
                    return left > right
                elif op == " < ":
                    return left < right
                elif op == " >= ":
                    return left >= right
                elif op == " <= ":
                    return left <= right
                elif op == " in ":
                    return left in right

        # Handle "not" prefix
        if condition.startswith("not "):
            return not self._get_value(condition[4:].strip(), ctx)

        # Simple truthy check
        value = self._get_value(condition, ctx)
        return bool(value)

    def _process_variables(self, content: str, ctx: TemplateContext) -> str:
        """Process {{ variable }} expressions."""

        def replace_var(match):
            expr = match.group(1)

            # Parse filters (e.g., variable|filter1|filter2)
            parts = expr.split("|")
            var_expr = parts[0].strip()
            filters = [f.strip() for f in parts[1:]]

            # Get value
            value = self._get_value(var_expr, ctx)

            # Apply filters
            for filter_expr in filters:
                # Parse filter args (e.g., truncate:50)
                if ":" in filter_expr:
                    filter_name, args_str = filter_expr.split(":", 1)
                    args = [self._parse_literal(a.strip()) for a in args_str.split(",")]
                else:
                    filter_name = filter_expr
                    args = []

                value = ctx.apply_filter(value, filter_name, *args)

            return str(value) if value is not None else ""

        return self.VAR_PATTERN.sub(replace_var, content)

    def _get_value(self, expr: str, ctx: TemplateContext) -> Any:
        """Get value from expression."""
        # Handle string literals
        if (expr.startswith('"') and expr.endswith('"')) or (
            expr.startswith("'") and expr.endswith("'")
        ):
            return expr[1:-1]

        # Handle numeric literals
        if expr.isdigit():
            return int(expr)
        if expr.replace(".", "").isdigit():
            return float(expr)

        # Handle boolean literals
        if expr == "True" or expr == "true":
            return True
        if expr == "False" or expr == "false":
            return False

        # Handle None
        if expr == "None" or expr == "null":
            return None

        # Handle helpers
        if expr in ctx.helpers:
            helper = ctx.helpers[expr]
            return helper() if callable(helper) else helper

        # Get from context
        return ctx.get(expr)

    def _parse_literal(self, value: str) -> Any:
        """Parse a literal value."""
        value = value.strip()

        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            return value[1:-1]

        if value.isdigit():
            return int(value)

        if value.replace(".", "").isdigit():
            return float(value)

        return value


def load_template(path: Union[str, Path]) -> ReportTemplate:
    """Load a template from file path."""
    path = Path(path)
    return ReportTemplate.from_file(path)


# Built-in templates
BUILTIN_TEMPLATES = {
    "executive": ReportTemplate(
        name="executive",
        description="Executive summary template",
        content="""<!DOCTYPE html>
<html>
<head>
    <title>{{ title }} - Executive Summary</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .summary { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        .metric { display: inline-block; margin: 10px; padding: 15px; background: white; border-radius: 4px; }
        .metric .value { font-size: 2em; font-weight: bold; color: #3b82f6; }
        .metric .label { color: #666; }
        .critical { color: #dc2626; }
        .high { color: #ea580c; }
    </style>
</head>
<body>
    <h1>{{ title }}</h1>
    <p>Generated: {{ now|datetime }}</p>
    
    <div class="summary">
        <h2>Key Metrics</h2>
        <div class="metric">
            <div class="value">{{ total_findings }}</div>
            <div class="label">Total Findings</div>
        </div>
        <div class="metric">
            <div class="value critical">{{ critical_count }}</div>
            <div class="label">Critical</div>
        </div>
        <div class="metric">
            <div class="value high">{{ high_count }}</div>
            <div class="label">High</div>
        </div>
    </div>
    
    {% if findings %}
    <h2>Top Findings</h2>
    <ul>
    {% for finding in findings %}
        <li><strong>{{ finding.title }}</strong> - {{ finding.severity|upper }}</li>
    {% endfor %}
    </ul>
    {% endif %}
</body>
</html>""",
    ),
    "detailed": ReportTemplate(
        name="detailed",
        description="Detailed findings report template",
        content="""<!DOCTYPE html>
<html>
<head>
    <title>{{ title }} - Detailed Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        h1, h2, h3 { color: #333; }
        .finding { border: 1px solid #ddd; padding: 20px; margin: 15px 0; border-radius: 8px; }
        .finding.critical { border-left: 4px solid #dc2626; }
        .finding.high { border-left: 4px solid #ea580c; }
        .finding.medium { border-left: 4px solid #eab308; }
        .finding.low { border-left: 4px solid #3b82f6; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }
        .badge-critical { background: #fef2f2; color: #dc2626; }
        .badge-high { background: #fff7ed; color: #ea580c; }
        .badge-medium { background: #fefce8; color: #ca8a04; }
        .badge-low { background: #eff6ff; color: #3b82f6; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
    </style>
</head>
<body>
    <h1>{{ title }}</h1>
    <p><em>{{ subtitle }}</em></p>
    <p>Report Date: {{ now|datetime }}</p>
    
    <h2>Summary</h2>
    <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Total Targets</td><td>{{ total_targets }}</td></tr>
        <tr><td>Total Findings</td><td>{{ total_findings }}</td></tr>
        <tr><td>Duration</td><td>{{ duration|default:"N/A" }}</td></tr>
    </table>
    
    <h2>Findings ({{ total_findings }})</h2>
    
    {% for finding in findings %}
    <div class="finding {{ finding.severity }}">
        <h3>{{ finding.title|default:"Untitled Finding" }}</h3>
        <span class="badge badge-{{ finding.severity }}">{{ finding.severity|upper }}</span>
        <p><strong>Host:</strong> {{ finding.host|default:finding.target }}</p>
        <p>{{ finding.description }}</p>
        {% if finding.remediation %}
        <p><strong>Remediation:</strong> {{ finding.remediation }}</p>
        {% endif %}
    </div>
    {% endfor %}
    
    <footer>
        <p>Generated by {{ author }}</p>
    </footer>
</body>
</html>""",
    ),
    "markdown": ReportTemplate(
        name="markdown",
        description="Markdown report template",
        file_extension="md",
        content="""# {{ title }}

{{ subtitle }}

**Generated:** {{ now|datetime }}  
**Author:** {{ author }}

---

## Summary

| Metric | Value |
|--------|-------|
| Total Targets | {{ total_targets }} |
| Total Findings | {{ total_findings }} |
| Critical | {{ critical_count }} |
| High | {{ high_count }} |
| Medium | {{ medium_count }} |
| Low | {{ low_count }} |

---

## Findings

{% for finding in findings %}
### {{ finding.title|default:"Finding" }}

- **Severity:** {{ finding.severity|upper }}
- **Host:** {{ finding.host|default:finding.target }}
- **Description:** {{ finding.description|truncate:200 }}

{% endfor %}

---

*Report generated by {{ author }}*
""",
    ),
}
