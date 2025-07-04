import configparser as ConfigParser
import logging
import sys
import os

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('config')
log_levels = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR
        }

def read_config(cfg_file):
    config = ConfigParser.ConfigParser()
    with open(cfg_file) as f:
        config.read_file(f)
    return config

def get_output_plugins(config):
    output_plugins = []
    for section in config.sections():
        if section.startswith('output_'):
            enabled = config.get(section, 'enabled')
            if enabled == 'true':
                output_plugins.append(section)
    return output_plugins

def get_config():
    cfg_file = None
    cfg_locations = ['/etc/adbnectar.cfg', 'adbnectar.cfg', 'C:\\ProgramData\\ADBNectar\\adbnectar.cfg']
    for l in cfg_locations:
        if os.path.exists(l):
            cfg_file = l
            break
    if not cfg_file:
        logger.error("Could not find config file!")
        sys.exit(1)
    logger.info("Loading config from {}".format(cfg_file))
    config = read_config(cfg_file)
    return config

CONFIG = get_config()
OUTPUT_PLUGINS = get_output_plugins(CONFIG)
