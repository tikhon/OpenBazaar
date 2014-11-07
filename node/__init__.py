import logging

def create_custom_log_levels():
    logging.addLevelName(5, "DATADUMP")

    def datadump(self, message, *args, **kwargs):
        if self.isEnabledFor(5):
            self._log(5, message, args, **kwargs)

    logging.Logger.datadump = datadump

create_custom_log_levels()
