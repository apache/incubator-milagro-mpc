# API Documentation

The documentation is in the html directory.

## Quick-start

Install sphinx

```
virtualenv -p python3 --no-site-packages venv
source venv/bin/activate
pip3 install sphinx sphinx-autobuild sphinx-markdown-builder sphinx_markdown_parser
```

initialize project

```
mkdir doc
cd doc
sphinx-quickstart
deactivate
```

Copy files from ./templates to source directory (may require editing).

```
cp ./templates/* ./doc/source/
```

Build the documentation

```
./build.sh 
```

The output will be in the html directory