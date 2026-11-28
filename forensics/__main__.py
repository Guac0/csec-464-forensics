"""Command line for the forensics content (don't edit; the code is in app/tools/content_cli.py).

python -m forensics check                        check everything in this folder
python -m forensics guide                        print the investigation guide
python -m forensics new windows.dlllist.DllList  create a plugin file
"""

from app.tools.content_cli import main

raise SystemExit(main())
