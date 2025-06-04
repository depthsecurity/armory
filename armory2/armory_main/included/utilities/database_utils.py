import os
import glob
import importlib.util
from django.conf import settings
from django.db import models, connection
import pdb
def discover_webapp_models():
    """
    Discover and import models from webapp modules in both included and custom webapps.
    """
    # Get the base path for included webapps
    # base_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    # included_webapps_path = os.path.join(base_path, "included/webapps")
    
    # Get all webapp directories
    model_paths = []
    
    # Add custom webapp paths if configured
    if 'ARMORY_CUSTOM_MODELS' in settings.ARMORY_CONFIG:
        for path in settings.ARMORY_CONFIG['ARMORY_CUSTOM_MODELS']:
            model_paths.extend(glob.glob(f"{path}/*/"))
    
    # Import models from each webapp
    for model_path in model_paths:
        models_path = os.path.join(model_path, "models.py")
        if os.path.exists(models_path):
            module_name = os.path.basename(os.path.dirname(model_path))
            spec = importlib.util.spec_from_file_location(
                f"{module_name}_models", models_path
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Import all models from the module
            for item in dir(module):
                if isinstance(getattr(module, item), type) and issubclass(getattr(module, item), models.Model):
                    globals()[item] = getattr(module, item)
                    with connection.schema_editor() as schema_editor:
                        try:
                            schema_editor.create_model(getattr(module, item))
                        except Exception as e:
                            pass
                    