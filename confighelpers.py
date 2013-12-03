def ConfigSectionMap(cfg, section):
    d = {}
    options = cfg.options(section)
    for option in options:
        try:
            d[option] = cfg.get(section, option)
            if d[option] == -1:
                print "skip {0}".format(option)
        except:
            print "exception on {0}".format(option)
            d[option] = None
                
    
    return d