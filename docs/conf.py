import os
from pathlib import Path

try:
    import sphinx_rtd_theme
except ImportError:
    sphinx_rtd_theme = None

# -- Execute the _about package ----------------------------------------------
base_dir = Path(__file__).parent.parent
about = {}
exec((base_dir / 'src' / 'fast_file_encryption' / '_about.py').read_text(), about)

# -- Project information -----------------------------------------------------
project = 'Fast File Encryption'
copyright = about['COPYRIGHT']
author = about['AUTHOR']
version = release = about['VERSION']

# -- General configuration ---------------------------------------------------
extensions = [
    'sphinx_design'
]
templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']
if sphinx_rtd_theme:
    html_theme = "sphinx_rtd_theme"
else:
    html_theme = "default"
html_static_path = ['_static']
