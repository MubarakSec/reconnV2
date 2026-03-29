import os
from pathlib import Path

def fix_indentation(root_dir):
    for py_file in Path(root_dir).rglob('*.py'):
        try:
            lines = py_file.read_text(encoding='utf-8').splitlines()
            new_lines = []
            changed = False
            
            i = 0
            while i < len(lines):
                line = lines[i]
                new_lines.append(line)
                
                # Look for the start of our broken block
                if line.strip() == 'except Exception as e:':
                    indent = line[:line.find('except')]
                    expected_child_indent = indent + '    '
                    
                    # Check next lines
                    j = i + 1
                    while j < len(lines) and (
                        'logger.debug(f"Silent failure suppressed:' in lines[j] or
                        'try:' in lines[j] and j+1 < len(lines) and 'from recon_cli.utils.metrics import metrics' in lines[j+1] or
                        'from recon_cli.utils.metrics import metrics' in lines[j] or
                        'metrics.stage_errors.labels' in lines[j] or
                        'except: pass' in lines[j] and 'metrics.stage_errors' in lines[j-1]
                    ):
                        current_line = lines[j]
                        stripped = current_line.lstrip()
                        
                        # Fix indent if it's not what we expect
                        if not current_line.startswith(expected_child_indent):
                            # Special case for nested try inside except
                            if stripped == 'try:':
                                new_lines.append(expected_child_indent + stripped)
                                # The lines inside this nested try need even more indent
                                nested_indent = expected_child_indent + '    '
                                j += 1
                                while j < len(lines) and 'except: pass' not in lines[j]:
                                    new_lines.append(nested_indent + lines[j].lstrip())
                                    j += 1
                                if j < len(lines):
                                    new_lines.append(expected_child_indent + lines[j].lstrip())
                                changed = True
                            else:
                                new_lines.append(expected_child_indent + stripped)
                                changed = True
                        else:
                            new_lines.append(current_line)
                        j += 1
                    i = j - 1
                i += 1
                
            if changed:
                py_file.write_text('\n'.join(new_lines) + '\n', encoding='utf-8')
                print(f"Fixed indentation in {py_file}")
                
        except Exception as ex:
            print(f"Failed to process {py_file}: {ex}")

if __name__ == "__main__":
    fix_indentation('recon_cli')
