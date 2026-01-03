## Logging facade - isolates chronicles from strict mode code
## All logging calls go through this module
##
## This wrapper pattern allows the rest of the codebase to use strict
## experimental modes (strictFuncs, strictCaseObjects) while chronicles
## macros expand in this isolated module where strict modes are disabled.

# Disable strict modes for chronicle macro expansion
{.push warning[ProveInit]: off.}

import chronicles
export chronicles

{.pop.}

# Re-enable raises tracking for any wrapper functions
{.push raises: [].}

# The chronicles macros (debug, info, warn, error, fatal) are exported above.
# They can be used directly in consuming code.
#
# Usage:
#   import wrappers/log
#   debug "Message", field1 = value1, field2 = value2
#   info "Operation completed"
#   warn "Non-fatal issue"
#   error "Fatal issue"

{.pop.}
