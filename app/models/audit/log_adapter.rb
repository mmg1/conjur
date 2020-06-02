# LogAdapter provides a convenient interface for logging _events_.
#
# We use the adapter pattern to give our audit logger an interface
# customized to its purpose, allowing us to write:
#
#   Audit.logger.log(some_event)
#
# instead of (as required by ruby's default logger):
#
#   Audit.logger.log(event.severity, event, ::Audit::Event2.progname)
#
# wherever we use it.
module Audit
  class LogAdapter
    def initialize(ruby_logger)
      @ruby_logger = ruby_logger
    end

    def log(event)
      @ruby_logger.log(event.severity, event.message, ::Audit::Event2.progname)
    end
  end
end
