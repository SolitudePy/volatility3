"""Volatility 3 framework"""
import inspect
import logging
import os
import sys

# ##
#
# Libtool version scheme
#
# Current - The number of the current interface exported by the library
# Revision - The implementation number of the most recent interface exported by this library
# Age - The number of previous additional interfaces supported by this library
#
# 1. If the source changes, increment the revision
# 2. If the interface has changed, increment current, set revision to 0
# 3. If only additions to the interface have been made, increment age
# 4. If changes or removals of the interface have been made, set age to 0

# We use the libtool library versioning
import typing

CURRENT = 0  # Number of releases of the library with any change
REVISION = 0  # Number of changes that don't affect the interface
AGE = 0  # Number of consecutive versions of the interface the current version supports


def interface_version():
    """Provides the so version number of the library"""
    return CURRENT - AGE, AGE, REVISION


vollog = logging.getLogger(__name__)


def require_interface_version(*args) -> None:
    """Checks the required version of a plugin"""
    if len(args):
        if args[0] != interface_version()[0]:
            raise RuntimeError(
                "Framework interface version {} is incompatible with required version {}".format(interface_version()[0],
                                                                                                 args[0]))
        if len(args) > 1:
            if args[1] > interface_version()[1]:
                raise RuntimeError(
                    "Framework interface version {} is an older revision than the required version {}".format(
                        ".".join([str(x) for x in interface_version()[0:1]]),
                        ".".join([str(x) for x in args[0:2]])))


class noninheritable(object):
    def __init__(self, value: typing.Any, cls: typing.Type) -> None:
        self.default_value = value
        self.cls = cls

    def __get__(self, obj: typing.Any, type: typing.Type = None) -> typing.Any:
        if type == self.cls:
            if hasattr(self.default_value, '__get__'):
                return self.default_value.__get__(obj, type)
            return self.default_value
        raise AttributeError


def hide_from_subclasses(cls: typing.Type) -> typing.Type:
    cls.hidden = noninheritable(True, cls)
    return cls


def class_subclasses(cls: typing.Type) -> typing.Iterable[typing.Type]:
    """Returns all the (recursive) subclasses of a given class"""
    if not inspect.isclass(cls):
        raise TypeError("class_subclasses parameter not a valid class: {}".format(cls))
    for clazz in cls.__subclasses__():
        # The typing system is not clever enough to realize that clazz has a hidden attr after the hasattr check
        if not hasattr(clazz, 'hidden') or not clazz.hidden:  # type: ignore
            yield clazz
        for return_value in class_subclasses(clazz):
            yield return_value


def import_files(base_module) -> None:
    """Imports all plugins present under plugins path"""
    if not isinstance(base_module.__path__, list):
        raise TypeError("[base_module].__path__ must be a list of paths")
    for path in base_module.__path__:
        for root, _, files in os.walk(path, followlinks = True):
            # TODO: Figure out how to import pycache files
            if root.endswith("__pycache__"):
                continue
            for f in files:
                if (f.endswith(".py") or f.endswith(".pyc") or f.endswith(".pyo")) and not f.startswith("__"):
                    modpath = os.path.join(root[len(path) + len(os.path.sep):], f[:f.rfind(".")])
                    module = modpath.replace(os.path.sep, ".")
                    if module not in sys.modules:
                        try:
                            vollog.debug("Importing module: {}.{}".format(base_module.__name__, module))
                            __import__(base_module.__name__ + "." + module)
                        except ImportError as e:
                            vollog.debug(str(e))
                            vollog.warning("Failed to import module {} based on file: {}".format(module, modpath))
                            raise
                    else:
                        vollog.info("Skipping existing module: {}".format(module))
    return None


def list_plugins() -> typing.Dict[str, typing.Type[interfaces.plugins.PluginInterface]]:
    plugin_list = {}
    for plugin in class_subclasses(interfaces.plugins.PluginInterface):
        plugin_name = plugin.__module__ + "." + plugin.__name__
        if plugin_name.startswith("volatility.plugins."):
            plugin_name = plugin_name[len("volatility.plugins."):]
        plugin_list[plugin_name] = plugin
    return plugin_list


# Check the python version to ensure it's suitable
# We currently require 3.5.3 since 3.5.1 has no typing.Type and 3.5.2 is broken for ''/delayed encapsulated types
required_python_version = (3, 5, 3)
if (sys.version_info.major != required_python_version[0] or sys.version_info.minor < required_python_version[1] or
        (sys.version_info.minor == required_python_version[1] and sys.version_info.micro < required_python_version[2])):
    raise RuntimeError(
        "Volatility framework requires python version {}.{}.{} or greater".format(*required_python_version))
