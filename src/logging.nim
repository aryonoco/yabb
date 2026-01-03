## Logging configuration for YABB
## Uses chronicles for structured logging
##
## Configure at compile time via nim.cfg or command line:
##   -d:chronicles_sinks=textlines
##   -d:chronicles_log_level=INFO
##   -d:chronicles_timestamps=UnixTime

{.push raises: [].}

import wrappers/log
export log  # Re-export so other modules can use logging macros

proc initLogging*(debug: bool = false) =
  ## Initialize logging - chronicles is configured at compile time
  ## Runtime debug flag only controls message verbosity, not sink setup
  if debug:
    info "Debug logging enabled"

{.pop.}
