"""
Module Loader

Dynamically loads and manages OFXpwn modules.
"""

import importlib
import inspect
from pathlib import Path
from typing import List, Dict, Optional, Type

from ofxpwn.core.base_module import BaseModule


class ModuleLoader:
    """Dynamic module loader for OFXpwn

    Discovers and loads modules from the modules/ directory.
    """

    def __init__(self):
        """Initialize module loader"""
        self.modules_dir = Path(__file__).parent.parent / "modules"
        self._module_cache: Dict[str, Type[BaseModule]] = {}

    def list_modules(self, category: Optional[str] = None) -> List[Dict[str, str]]:
        """List all available modules

        Args:
            category: Optional category filter (auth, recon, exploit, fuzz, infra)

        Returns:
            List of module information dictionaries
        """
        modules = []

        # Categories to search
        categories = [category] if category else ["auth", "recon", "exploit", "fuzz", "infra"]

        for cat in categories:
            cat_dir = self.modules_dir / cat
            if not cat_dir.exists():
                continue

            # Find all Python modules
            for module_file in cat_dir.glob("*.py"):
                if module_file.name.startswith("_"):
                    continue

                module_name = module_file.stem
                module_path = f"{cat}/{module_name}"

                # Try to get module metadata
                try:
                    module_class = self._load_module_class(module_path)
                    description = module_class.get_description()
                except:
                    description = "No description available"

                modules.append({
                    "name": module_name,
                    "category": cat,
                    "path": module_path,
                    "description": description,
                })

        return modules

    def load_module(self, module_path: str) -> BaseModule:
        """Load a specific module

        Args:
            module_path: Module path like "auth/bruteforce" or "recon/fingerprint"

        Returns:
            Instantiated module

        Raises:
            ModuleNotFoundError: If module doesn't exist
            ImportError: If module can't be imported
        """
        # Check cache first
        if module_path in self._module_cache:
            return self._module_cache[module_path]()

        module_class = self._load_module_class(module_path)
        instance = module_class()

        # Cache the class (not instance)
        self._module_cache[module_path] = module_class

        return instance

    def _load_module_class(self, module_path: str) -> Type[BaseModule]:
        """Load module class

        Args:
            module_path: Module path like "auth/bruteforce"

        Returns:
            Module class (not instantiated)
        """
        parts = module_path.split("/")
        if len(parts) != 2:
            raise ValueError(f"Invalid module path: {module_path}")

        category, module_name = parts

        # Construct import path
        import_path = f"ofxpwn.modules.{category}.{module_name}"

        try:
            module = importlib.import_module(import_path)
        except ImportError as e:
            raise ModuleNotFoundError(f"Module not found: {module_path}") from e

        # Find the module class (should inherit from BaseModule)
        module_class = None
        for name, obj in inspect.getmembers(module):
            if (inspect.isclass(obj) and
                issubclass(obj, BaseModule) and
                obj is not BaseModule):
                module_class = obj
                break

        if module_class is None:
            raise ImportError(f"No BaseModule subclass found in {module_path}")

        return module_class

    def get_module_info(self, module_path: str) -> Dict[str, str]:
        """Get module information

        Args:
            module_path: Module path

        Returns:
            Module information dictionary
        """
        module_class = self._load_module_class(module_path)

        return {
            "name": module_path.split("/")[1],
            "category": module_path.split("/")[0],
            "path": module_path,
            "description": module_class.get_description(),
            "author": getattr(module_class, "__author__", "Unknown"),
            "version": getattr(module_class, "__version__", "1.0.0"),
        }
