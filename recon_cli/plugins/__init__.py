"""
ReconnV2 Plugin System
Extensible architecture for custom modules
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional, Type, TYPE_CHECKING
import importlib.util
import inspect
import logging

from pydantic import BaseModel, ConfigDict, Field, ValidationError, create_model

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from recon_cli.pipeline.stages import Stage


class PluginType(Enum):
    """Plugin types"""

    SCANNER = "scanner"  # Custom scanning tools
    ENRICHER = "enricher"  # Data enrichment
    REPORTER = "reporter"  # Custom report formats
    NOTIFIER = "notifier"  # Notification channels
    PROCESSOR = "processor"  # Data processors
    STAGE = "stage"  # Pipeline stages


class PluginStatus(Enum):
    """Plugin status"""

    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    LOADING = "loading"


_EMPTY_OBJECT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}

_TYPE_NAME_MAP: Dict[str, Any] = {
    "str": str,
    "string": str,
    "int": int,
    "integer": int,
    "float": float,
    "number": float,
    "bool": bool,
    "boolean": bool,
    "list": list,
    "array": list,
    "dict": dict,
    "object": dict,
    "any": Any,
}


class PluginConfigError(ValueError):
    """Raised when plugin configuration does not satisfy its declared schema."""


def _normalize_type_name(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TYPE_NAME_MAP:
            if lowered in {"str", "string"}:
                return "string"
            if lowered in {"int", "integer"}:
                return "integer"
            if lowered in {"float", "number"}:
                return "number"
            if lowered in {"bool", "boolean"}:
                return "boolean"
            if lowered in {"list", "array"}:
                return "array"
            if lowered in {"dict", "object"}:
                return "object"
            return lowered
        raise PluginConfigError(f"Unsupported schema type: {value}")
    raise PluginConfigError(f"Unsupported schema type declaration: {value!r}")


def _is_schema_object(schema: Dict[str, Any]) -> bool:
    return isinstance(schema, dict) and (
        schema.get("type") == "object" or isinstance(schema.get("properties"), dict)
    )


def _normalize_property_schema(spec: Any) -> Dict[str, Any]:
    if isinstance(spec, str):
        spec = {"type": spec}
    elif not isinstance(spec, dict):
        inferred_type = type(spec).__name__
        spec = {"type": inferred_type, "default": spec}

    normalized_type = _normalize_type_name(spec.get("type"))
    if normalized_type is None:
        if "properties" in spec:
            normalized_type = "object"
        elif "items" in spec:
            normalized_type = "array"
        elif "enum" in spec and spec["enum"]:
            normalized_type = _normalize_type_name(type(spec["enum"][0]).__name__)

    if normalized_type == "object":
        return _normalize_object_schema(spec)
    if normalized_type == "array":
        items = spec.get("items", {"type": "string"})
        normalized: Dict[str, Any] = {
            "type": "array",
            "items": _normalize_property_schema(items),
        }
        for key in ("description", "default", "minItems", "maxItems"):
            if key in spec:
                normalized[key] = spec[key]
        return normalized

    normalized = {"type": normalized_type or "string"}
    for key in (
        "description",
        "default",
        "enum",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "pattern",
    ):
        if key in spec:
            normalized[key] = spec[key]
    return normalized


def _normalize_object_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    if not schema:
        return dict(_EMPTY_OBJECT_SCHEMA)

    properties_source: Dict[str, Any]
    required_source: List[str] = []
    if _is_schema_object(schema):
        properties_source = dict(schema.get("properties", {}))
        raw_required = schema.get("required", [])
        if isinstance(raw_required, list):
            required_source = [str(item) for item in raw_required]
    else:
        properties_source = dict(schema)

    properties: Dict[str, Any] = {}
    required: List[str] = list(required_source)
    for key, raw_spec in properties_source.items():
        properties[str(key)] = _normalize_property_schema(raw_spec)
        if (
            isinstance(raw_spec, dict)
            and raw_spec.get("required", False)
            and str(key) not in required
        ):
            required.append(str(key))

    normalized: Dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": bool(schema.get("additionalProperties", False))
        if _is_schema_object(schema)
        else False,
    }
    if "description" in schema:
        normalized["description"] = schema["description"]
    return normalized


def _literal_annotation(enum_values: List[Any]) -> Any:
    return Literal[tuple(enum_values)]


def _annotation_from_schema(schema: Dict[str, Any], model_name: str) -> Any:
    enum_values = schema.get("enum")
    if isinstance(enum_values, list) and enum_values:
        return _literal_annotation(enum_values)

    schema_type = schema.get("type")
    if schema_type == "string":
        return str
    if schema_type == "integer":
        return int
    if schema_type == "number":
        return float
    if schema_type == "boolean":
        return bool
    if schema_type == "array":
        item_schema = schema.get("items", {"type": "string"})
        return list[_annotation_from_schema(item_schema, f"{model_name}Item")]  # type: ignore[misc]
    if schema_type == "object":
        properties = schema.get("properties", {})
        if not properties:
            return Dict[str, Any]
        return _model_from_object_schema(model_name, schema)
    return Any


def _field_from_schema(
    field_name: str, schema: Dict[str, Any], *, required: bool, model_name: str
) -> tuple[Any, Any]:
    annotation = _annotation_from_schema(schema, f"{model_name}_{field_name.title()}")
    field_kwargs: Dict[str, Any] = {}
    if "description" in schema:
        field_kwargs["description"] = schema["description"]
    if "minimum" in schema:
        field_kwargs["ge"] = schema["minimum"]
    if "maximum" in schema:
        field_kwargs["le"] = schema["maximum"]
    if "pattern" in schema:
        field_kwargs["pattern"] = schema["pattern"]
    min_length = schema.get("minLength", schema.get("minItems"))
    max_length = schema.get("maxLength", schema.get("maxItems"))
    if min_length is not None:
        field_kwargs["min_length"] = min_length
    if max_length is not None:
        field_kwargs["max_length"] = max_length

    if "default" in schema:
        default = schema["default"]
    elif required:
        return annotation, Field(**field_kwargs)
    else:
        annotation = annotation | None
        default = None
    return annotation, Field(default=default, **field_kwargs)


def _model_from_object_schema(
    model_name: str, schema: Dict[str, Any]
) -> type[BaseModel]:
    normalized = _normalize_object_schema(schema)
    properties = normalized.get("properties", {})
    required = set(normalized.get("required", []))
    field_definitions = {
        field_name: _field_from_schema(
            field_name,
            field_schema,
            required=field_name in required,
            model_name=model_name,
        )
        for field_name, field_schema in properties.items()
    }
    return create_model(  # type: ignore[call-overload]
        model_name,
        __config__=ConfigDict(
            extra="allow" if normalized.get("additionalProperties") else "forbid"
        ),
        **field_definitions,
    )


def build_plugin_config_model(
    plugin_name: str, schema: Dict[str, Any]
) -> type[BaseModel]:
    """Build a strict Pydantic model from plugin shorthand/full config schema."""
    return _model_from_object_schema(f"{plugin_name}Config", schema)


def build_plugin_config_json_schema(
    plugin_name: str, schema: Dict[str, Any]
) -> Dict[str, Any]:
    """Return a machine-facing JSON schema that matches plugin config validation."""
    model = build_plugin_config_model(plugin_name, schema)
    return model.model_json_schema()


@dataclass
class PluginMetadata:
    """Plugin metadata"""

    name: str
    version: str
    description: str
    author: str = "Unknown"
    plugin_type: PluginType = PluginType.PROCESSOR
    dependencies: List[str] = field(default_factory=list)
    config_schema: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def config_json_schema(self) -> Dict[str, Any]:
        return build_plugin_config_json_schema(self.name, self.config_schema)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "plugin_type": self.plugin_type.value,
            "dependencies": self.dependencies,
            "config_schema": self.config_json_schema(),
            "tags": self.tags,
        }


@dataclass
class PluginResult:
    """Plugin execution result"""

    success: bool
    data: Any = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0


class PluginInterface(ABC):
    """
    Base interface for all plugins

    All plugins must inherit from this class and implement
    the required methods.
    """

    # Plugin metadata (must be overridden)
    METADATA: PluginMetadata = PluginMetadata(
        name="BasePlugin", version="0.0.0", description="Base plugin interface"
    )

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"plugin.{self.METADATA.name}")
        self._initialized = False
        self._config_error: Optional[str] = None

    @abstractmethod
    def execute(self, context: Dict[str, Any]) -> PluginResult:
        """
        Execute the plugin

        Args:
            context: Execution context with relevant data

        Returns:
            PluginResult with execution results
        """
        pass

    def initialize(self) -> bool:
        """
        Initialize the plugin (optional override)

        Returns:
            True if initialization successful
        """
        self._initialized = True
        return True

    def cleanup(self) -> None:
        """Cleanup resources (optional override)"""
        self._initialized = False

    def validate_config(self) -> bool:
        """
        Validate plugin configuration

        Returns:
            True if configuration is valid
        """
        try:
            model = build_plugin_config_model(
                self.METADATA.name, self.METADATA.config_schema
            )
            validated = model.model_validate(self.config)
        except (PluginConfigError, ValidationError) as exc:
            self._config_error = str(exc)
            self.logger.error(
                "Plugin config validation failed for %s: %s", self.METADATA.name, exc
            )
            return False

        self._config_error = None
        self.config = validated.model_dump(exclude_none=True)
        return True

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    @property
    def config_error(self) -> Optional[str]:
        return self._config_error


class ScannerPlugin(PluginInterface):
    """Base class for scanner plugins"""

    METADATA = PluginMetadata(
        name="ScannerPlugin",
        version="0.0.0",
        description="Base scanner plugin",
        plugin_type=PluginType.SCANNER,
    )

    @abstractmethod
    def scan(self, target: str, options: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Perform scan on target

        Args:
            target: Target to scan
            options: Scan options

        Returns:
            List of scan results
        """
        pass

    def execute(self, context: Dict[str, Any]) -> PluginResult:
        target = context.get("target")
        options = context.get("options", {})

        if not target:
            return PluginResult(success=False, error="No target specified")

        try:
            import time

            start = time.time()
            results = self.scan(target, options)
            execution_time = time.time() - start

            return PluginResult(
                success=True,
                data=results,
                execution_time=execution_time,
                metadata={"result_count": len(results)},
            )
        except Exception as e:
            return PluginResult(success=False, error=str(e))


class EnricherPlugin(PluginInterface):
    """Base class for enricher plugins"""

    METADATA = PluginMetadata(
        name="EnricherPlugin",
        version="0.0.0",
        description="Base enricher plugin",
        plugin_type=PluginType.ENRICHER,
    )

    @abstractmethod
    def enrich(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich data with additional information

        Args:
            data: Data to enrich

        Returns:
            Enriched data
        """
        pass

    def execute(self, context: Dict[str, Any]) -> PluginResult:
        data = context.get("data")

        if not data:
            return PluginResult(success=False, error="No data to enrich")

        try:
            import time

            start = time.time()
            enriched = self.enrich(data)
            execution_time = time.time() - start

            return PluginResult(
                success=True, data=enriched, execution_time=execution_time
            )
        except Exception as e:
            return PluginResult(success=False, error=str(e))


class ReporterPlugin(PluginInterface):
    """Base class for reporter plugins"""

    METADATA = PluginMetadata(
        name="ReporterPlugin",
        version="0.0.0",
        description="Base reporter plugin",
        plugin_type=PluginType.REPORTER,
    )

    @abstractmethod
    def generate_report(
        self, job_data: Dict[str, Any], results: List[Dict[str, Any]], output_path: Path
    ) -> Path:
        """
        Generate report

        Args:
            job_data: Job metadata
            results: Job results
            output_path: Output file path

        Returns:
            Path to generated report
        """
        pass

    def execute(self, context: Dict[str, Any]) -> PluginResult:
        job_data = context.get("job_data", {})
        results = context.get("results", [])
        output_path = context.get("output_path")

        if not output_path:
            return PluginResult(success=False, error="No output path specified")

        try:
            import time

            start = time.time()
            report_path = self.generate_report(job_data, results, Path(output_path))
            execution_time = time.time() - start

            return PluginResult(
                success=True, data=str(report_path), execution_time=execution_time
            )
        except Exception as e:
            return PluginResult(success=False, error=str(e))


class NotifierPlugin(PluginInterface):
    """Base class for notifier plugins"""

    METADATA = PluginMetadata(
        name="NotifierPlugin",
        version="0.0.0",
        description="Base notifier plugin",
        plugin_type=PluginType.NOTIFIER,
    )

    @abstractmethod
    def send(self, message: str, **kwargs) -> bool:
        """
        Send notification

        Args:
            message: Message to send
            **kwargs: Additional options

        Returns:
            True if sent successfully
        """
        pass

    def execute(self, context: Dict[str, Any]) -> PluginResult:
        message = context.get("message")

        if not message:
            return PluginResult(success=False, error="No message to send")

        try:
            import time

            start = time.time()
            payload = dict(context)
            payload.pop("message", None)
            success = self.send(message, **payload)
            execution_time = time.time() - start

            return PluginResult(success=success, execution_time=execution_time)
        except Exception as e:
            return PluginResult(success=False, error=str(e))


@dataclass
class LoadedPlugin:
    """Loaded plugin wrapper"""

    plugin_class: Type[PluginInterface]
    metadata: PluginMetadata
    path: Path
    status: PluginStatus = PluginStatus.INACTIVE
    instance: Optional[PluginInterface] = None
    error: Optional[str] = None
    loaded_at: datetime = field(default_factory=datetime.now)


class PluginLoader:
    """
    Plugin loader and manager

    Loads plugins from directories and manages their lifecycle
    """

    def __init__(self, plugin_dirs: Optional[List[Path]] = None):
        self.plugin_dirs = plugin_dirs or []
        self.plugins: Dict[str, LoadedPlugin] = {}
        self.logger = logging.getLogger("PluginLoader")

    def add_plugin_directory(self, path: Path) -> None:
        """Add a directory to search for plugins"""
        if path.exists() and path.is_dir():
            self.plugin_dirs.append(path)
            self.logger.info(f"Added plugin directory: {path}")

    def discover_plugins(self) -> List[str]:
        """
        Discover all plugins in plugin directories

        Returns:
            List of discovered plugin names
        """
        discovered = []

        for plugin_dir in self.plugin_dirs:
            if not plugin_dir.exists():
                continue

            # Look for Python files
            for py_file in plugin_dir.glob("*.py"):
                if py_file.name.startswith("_"):
                    continue

                try:
                    plugins = self._load_from_file(py_file)
                    discovered.extend([p.metadata.name for p in plugins])
                except Exception as e:
                    self.logger.error(f"Error loading {py_file}: {e}")

            # Look for plugin packages
            for pkg_dir in plugin_dir.iterdir():
                if pkg_dir.is_dir() and (pkg_dir / "__init__.py").exists():
                    try:
                        plugins = self._load_from_package(pkg_dir)
                        discovered.extend([p.metadata.name for p in plugins])
                    except Exception as e:
                        self.logger.error(f"Error loading {pkg_dir}: {e}")

        return discovered

    def _load_from_file(self, file_path: Path) -> List[LoadedPlugin]:
        """Load plugins from a Python file"""
        loaded: List[LoadedPlugin] = []

        spec = importlib.util.spec_from_file_location(file_path.stem, file_path)

        if not spec or not spec.loader:
            return loaded

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Find plugin classes
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, PluginInterface)
                and obj is not PluginInterface
                and not name.endswith("Plugin")
            ):
                try:
                    metadata = getattr(obj, "METADATA", None)
                    if metadata and isinstance(metadata, PluginMetadata):
                        plugin = LoadedPlugin(
                            plugin_class=obj,
                            metadata=metadata,
                            path=file_path,
                            status=PluginStatus.INACTIVE,
                        )
                        self.plugins[metadata.name] = plugin
                        loaded.append(plugin)
                        self.logger.info(f"Loaded plugin: {metadata.name}")
                except Exception as e:
                    self.logger.error(f"Error loading class {name}: {e}")

        return loaded

    def _load_from_package(self, pkg_dir: Path) -> List[LoadedPlugin]:
        """Load plugins from a package directory"""
        init_file = pkg_dir / "__init__.py"
        return self._load_from_file(init_file)

    def load_plugin(
        self, name: str, config: Optional[Dict[str, Any]] = None
    ) -> Optional[PluginInterface]:
        """
        Load and initialize a plugin

        Args:
            name: Plugin name
            config: Plugin configuration

        Returns:
            Initialized plugin instance
        """
        if name not in self.plugins:
            self.logger.error(f"Plugin not found: {name}")
            return None

        loaded = self.plugins[name]

        try:
            loaded.status = PluginStatus.LOADING

            # Create instance
            instance = loaded.plugin_class(config)

            # Validate config
            if not instance.validate_config():
                loaded.status = PluginStatus.ERROR
                loaded.error = (
                    instance.config_error or "Configuration validation failed"
                )
                return None

            # Initialize
            if not instance.initialize():
                loaded.status = PluginStatus.ERROR
                loaded.error = "Initialization failed"
                return None

            loaded.instance = instance
            loaded.status = PluginStatus.ACTIVE

            return instance

        except Exception as e:
            loaded.status = PluginStatus.ERROR
            loaded.error = str(e)
            self.logger.error(f"Error loading plugin {name}: {e}")
            return None

    def unload_plugin(self, name: str) -> bool:
        """
        Unload a plugin

        Args:
            name: Plugin name

        Returns:
            True if unloaded successfully
        """
        if name not in self.plugins:
            return False

        loaded = self.plugins[name]

        if loaded.instance:
            try:
                loaded.instance.cleanup()
            except Exception as e:
                self.logger.error(f"Error cleaning up {name}: {e}")

        loaded.instance = None
        loaded.status = PluginStatus.INACTIVE

        return True

    def get_plugin(self, name: str) -> Optional[PluginInterface]:
        """Get a loaded plugin instance"""
        if name in self.plugins and self.plugins[name].instance:
            return self.plugins[name].instance
        return None

    def list_plugins(
        self,
        plugin_type: Optional[PluginType] = None,
        status: Optional[PluginStatus] = None,
    ) -> List[PluginMetadata]:
        """
        List available plugins

        Args:
            plugin_type: Filter by type
            status: Filter by status

        Returns:
            List of plugin metadata
        """
        result = []

        for loaded in self.plugins.values():
            if plugin_type and loaded.metadata.plugin_type != plugin_type:
                continue
            if status and loaded.status != status:
                continue
            result.append(loaded.metadata)

        return result

    def execute_plugin(self, name: str, context: Dict[str, Any]) -> PluginResult:
        """
        Execute a plugin

        Args:
            name: Plugin name
            context: Execution context

        Returns:
            Plugin result
        """
        plugin = self.get_plugin(name)

        if not plugin:
            # Try to load it
            plugin = self.load_plugin(name)

        if not plugin:
            return PluginResult(
                success=False, error=f"Plugin not found or failed to load: {name}"
            )

        try:
            return plugin.execute(context)
        except Exception as e:
            return PluginResult(success=False, error=str(e))


class PluginRegistry:
    """
    Global plugin registry

    Singleton registry for managing plugins across the application
    """

    _instance: Optional["PluginRegistry"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.loader = PluginLoader()
        self.hooks: Dict[str, List[Callable]] = {}
        self.logger = logging.getLogger("PluginRegistry")
        self._initialized = True

    def setup(self, plugin_dirs: Optional[List[Path]] = None) -> None:
        """
        Setup the registry with plugin directories

        Args:
            plugin_dirs: List of directories to search for plugins
        """
        if plugin_dirs:
            for dir_path in plugin_dirs:
                self.loader.add_plugin_directory(dir_path)

        # Default plugin directories
        default_dirs = [
            Path.home() / ".recon_cli" / "plugins",
            Path(__file__).parent.parent / "plugins",
        ]

        for dir_path in default_dirs:
            if dir_path.exists():
                self.loader.add_plugin_directory(dir_path)

        # Discover plugins
        self.loader.discover_plugins()

    def register_hook(self, event: str, callback: Callable) -> None:
        """
        Register a hook for an event

        Args:
            event: Event name
            callback: Callback function
        """
        if event not in self.hooks:
            self.hooks[event] = []
        self.hooks[event].append(callback)

    def trigger_hook(self, event: str, *args, **kwargs) -> List[Any]:
        """
        Trigger hooks for an event

        Args:
            event: Event name
            *args, **kwargs: Arguments to pass to callbacks

        Returns:
            List of callback results
        """
        results = []

        for callback in self.hooks.get(event, []):
            try:
                result = callback(*args, **kwargs)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Hook error for {event}: {e}")

        return results

    def get_scanners(self) -> List[PluginMetadata]:
        """Get all scanner plugins"""
        return self.loader.list_plugins(plugin_type=PluginType.SCANNER)

    def get_enrichers(self) -> List[PluginMetadata]:
        """Get all enricher plugins"""
        return self.loader.list_plugins(plugin_type=PluginType.ENRICHER)

    def get_reporters(self) -> List[PluginMetadata]:
        """Get all reporter plugins"""
        return self.loader.list_plugins(plugin_type=PluginType.REPORTER)

    def get_notifiers(self) -> List[PluginMetadata]:
        """Get all notifier plugins"""
        return self.loader.list_plugins(plugin_type=PluginType.NOTIFIER)

    def run_scanner(
        self, name: str, target: str, options: Optional[Dict[str, Any]] = None
    ) -> PluginResult:
        """Run a scanner plugin"""
        return self.loader.execute_plugin(
            name, {"target": target, "options": options or {}}
        )

    def run_enricher(self, name: str, data: Dict[str, Any]) -> PluginResult:
        """Run an enricher plugin"""
        return self.loader.execute_plugin(name, {"data": data})

    def run_reporter(
        self,
        name: str,
        job_data: Dict[str, Any],
        results: List[Dict[str, Any]],
        output_path: Path,
    ) -> PluginResult:
        """Run a reporter plugin"""
        return self.loader.execute_plugin(
            name, {"job_data": job_data, "results": results, "output_path": output_path}
        )

    def run_notifier(self, name: str, message: str, **kwargs) -> PluginResult:
        """Run a notifier plugin"""
        return self.loader.execute_plugin(name, {"message": message, **kwargs})


# Convenience function to get the registry
def get_registry() -> PluginRegistry:
    """Get the global plugin registry"""
    return PluginRegistry()


def _stage_log(logger_obj, level: str, message: str) -> None:
    if logger_obj is None:
        return
    log_fn = getattr(logger_obj, level, None)
    if callable(log_fn):
        log_fn(message)


def load_stage_plugins(logger=None) -> List["Stage"]:
    """Load extra pipeline stages from RECON_PLUGIN_STAGES (comma-separated module:Class)."""
    import importlib
    import os

    from recon_cli.pipeline.stages import Stage

    env = os.environ.get("RECON_PLUGIN_STAGES", "")
    if not env:
        return []
    stages: List[Stage] = []
    for entry in env.split(","):
        token = entry.strip()
        if not token:
            continue
        if ":" not in token:
            _stage_log(
                logger,
                "warning",
                f"Plugin stage '{token}' invalid, expected module:Class",
            )
            continue
        mod_name, class_name = token.split(":", 1)
        try:
            module = importlib.import_module(mod_name)
        except Exception as exc:
            _stage_log(
                logger, "warning", f"Failed to import plugin module {mod_name}: {exc}"
            )
            continue
        cls = getattr(module, class_name, None)
        if cls is None:
            _stage_log(
                logger,
                "warning",
                f"Plugin stage class {class_name} not found in {mod_name}",
            )
            continue
        try:
            instance = cls() if isinstance(cls, type) else cls
        except Exception as exc:
            _stage_log(
                logger,
                "warning",
                f"Failed to instantiate plugin stage {class_name}: {exc}",
            )
            continue
        if not isinstance(instance, Stage):
            _stage_log(
                logger, "warning", f"Plugin {class_name} is not a Stage; skipping"
            )
            continue
        stages.append(instance)
    return stages


# Example plugins


class ExampleScanner(ScannerPlugin):
    """Example scanner plugin"""

    METADATA = PluginMetadata(
        name="ExampleScanner",
        version="1.0.0",
        description="Example scanner plugin",
        author="ReconnV2",
        plugin_type=PluginType.SCANNER,
        config_schema={
            "timeout": {"type": "int", "default": 30},
            "threads": {"type": "int", "default": 10},
        },
        tags=["example", "demo"],
    )

    def scan(self, target: str, options: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Example scan implementation"""
        return [
            {
                "type": "host",
                "host": target,
                "source": "ExampleScanner",
                "discovered_at": datetime.now().isoformat(),
            }
        ]


class WebhookNotifier(NotifierPlugin):
    """Webhook notifier plugin"""

    METADATA = PluginMetadata(
        name="WebhookNotifier",
        version="1.0.0",
        description="Send notifications via webhook",
        author="ReconnV2",
        plugin_type=PluginType.NOTIFIER,
        config_schema={
            "webhook_url": {"type": "str", "required": True},
            "method": {"type": "str", "default": "POST"},
        },
        tags=["webhook", "notification"],
    )

    def send(self, message: str, **kwargs) -> bool:
        """Send webhook notification"""
        import requests

        webhook_url = self.config.get("webhook_url")
        if not webhook_url:
            return False

        method = self.config.get("method", "POST")

        try:
            response = requests.request(
                method, webhook_url, json={"message": message, **kwargs}, timeout=30
            )
            return response.status_code < 400
        except Exception as e:
            self.logger.error(f"Webhook error: {e}")
            return False


class JSONEnricher(EnricherPlugin):
    """JSON data enricher plugin"""

    METADATA = PluginMetadata(
        name="JSONEnricher",
        version="1.0.0",
        description="Enrich data with additional JSON fields",
        author="ReconnV2",
        plugin_type=PluginType.ENRICHER,
        tags=["json", "enrichment"],
    )

    def enrich(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add enrichment metadata"""
        enriched = data.copy()
        enriched["enriched_at"] = datetime.now().isoformat()
        enriched["enriched_by"] = self.METADATA.name
        return enriched
