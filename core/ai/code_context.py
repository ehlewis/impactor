import ast
from pathlib import Path
from textwrap import dedent
from typing import Dict, List, Optional

SOURCE_EXTENSIONS = ['.py', '.js', '.ts', '.java', '.cs', '.go', '.json', '.yaml', '.yml']


def _summarize_python_source(source: str, max_characters: int) -> str:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source[:max_characters]

    excerpts: List[str] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            args = ', '.join(arg.arg for arg in node.args.args)
            doc = ast.get_docstring(node) or ''
            summary = f'Function {node.name}({args})'
            if doc:
                summary += f' — {doc.strip().splitlines()[0]}'
            excerpts.append(summary)
        elif isinstance(node, ast.ClassDef):
            bases = ', '.join(
                base.id if isinstance(base, ast.Name) else getattr(base, 'attr', '')
                for base in node.bases
            )
            doc = ast.get_docstring(node) or ''
            method_count = sum(isinstance(child, ast.FunctionDef) for child in node.body)
            summary = f'Class {node.name}({bases}) — {method_count} methods'
            if doc:
                summary += f' — {doc.strip().splitlines()[0]}'
            excerpts.append(summary)
        if len(excerpts) >= 10:
            break

    if excerpts:
        combined = '\n'.join(excerpts)
        return combined[:max_characters]

    return source[:max_characters]


def extract_code_context(
    root_path: str,
    max_files: int = 5,
    max_characters_per_file: int = 1500,
) -> Dict[str, str]:
    path = Path(root_path)
    if not path.exists():
        return {}

    files = []
    for ext in SOURCE_EXTENSIONS:
        files.extend(path.rglob(f'*{ext}'))
    files = sorted(files, key=lambda p: p.stat().st_size)[:max_files]

    snippets: Dict[str, str] = {}
    for file_path in files:
        try:
            text = file_path.read_text(errors='ignore')
            if file_path.suffix == '.py':
                snippet = _summarize_python_source(text, max_characters_per_file)
            else:
                snippet = text[:max_characters_per_file]
            snippets[str(file_path.relative_to(path))] = dedent(snippet).strip()
        except OSError:
            continue
    return snippets
