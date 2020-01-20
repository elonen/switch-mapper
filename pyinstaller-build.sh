#!/bin/bash
PYTHON=python3.8
REQ=requirements.txt
ACTIVATE=venv/bin/activate
set -e

VER=$(git describe --exact-match 2> /dev/null || echo "`git symbolic-ref HEAD 2> /dev/null | cut -b 12-`-`git log --pretty=format:\"%h\" -1`")
echo "Current version string is: '$VER'"

if (uname | grep -q -E '(CYGWIN|MINGW)'); then
  echo "NOTE: Windows OS detected. Using 'python' instead of '$PYTHON'."
  PYTHON=python
  ACTIVATE=venv/Scripts/activate
fi

source $ACTIVATE || { echo "Venv activation failed."; exit 1; }
pip install -r $REQ

echo " "
# pytest || { echo "Tests failed, will not continue with pyinstaller."; exit 1; }
python ./setup.py develop

if (uname | grep -q -E '(CYGWIN|MINGW)'); then
  python setup.py pyinstaller -- --noconsole --onefile
  cp dist/*.exe ./
  rm -rf dist
else
  echo "--- NOTE: We are not on Windows, so binaries will stay in dist/."
  python ./setup.py pyinstaller -- --noconsole --onefile
fi

rm -rf dist
rm -f ./*_*.spec
