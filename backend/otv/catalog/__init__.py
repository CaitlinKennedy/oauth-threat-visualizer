"""Self-registering capability / attack catalog (the plugin seam).

Every capability and attack is its own small module in this package. At import
time each module calls :func:`otv.registry.capability` or
:func:`otv.registry.attack` to add itself to the catalog. :func:`load_all`
discovers and imports every module here (ordered by filename) so the set of
catalogued features is exactly "the files in this directory".

**To add a capability or attack in a later phase:** drop a new module in this
package that calls ``registry.capability(...)`` / ``registry.attack(...)`` at
module scope. Nothing else — no central list to edit, no picker change. The
filename controls display order (a numeric prefix keeps related items grouped:
``c<phase>_*`` for capabilities, ``a<phase>_*`` for attacks).
"""

from __future__ import annotations

import importlib
import pkgutil

_loaded = False


def load_all() -> None:
    """Import every feature module in this package exactly once (idempotent)."""
    global _loaded
    if _loaded:
        return
    for mod in sorted(m.name for m in pkgutil.iter_modules(__path__)):
        importlib.import_module(f"{__name__}.{mod}")
    _loaded = True
