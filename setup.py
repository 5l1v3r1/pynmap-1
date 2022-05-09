from setuptools import *

kwargs = {
    "author" : "Nathalon",
    "description" : "pynmap",
    "entry_points" : {"console_scripts" : ["pynmap=pynmap.pynmap:main"]},
    "license" : "GPL v3",
    "name" : "pynmap",
    "packages" : ["pynmap"],    
    "version" : "V0.0.1",
    "url" : "https://github.com/Nathalon/pynmap.git"
}

setup(**kwargs)
