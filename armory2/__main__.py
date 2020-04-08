from .armory_cmd import main
from .manage import main as manage
import sys
import pdb



if len(sys.argv) > 1 and sys.argv[1] == "manage":
    sys.argv.pop(1)
    manage()
else:
    main()
