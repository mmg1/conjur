# LogAdapter provides a convenient interface for logging _events_.
#
# We use the adapter pattern to give our audit logger an interface
# customized to its purpose, allowing us to write:
#
#   Audit.logger.log(some_event)
#
# instead of (as required by ruby's default logger):
#
#   Audit.logger.log(event.severity, event, ::Audit::Event.progname)
#
# wherever we use it.
module Audit
  class RubyLogAdapter
    def initialize(ruby_logger)
      @ruby_logger = ruby_logger
    end

    def log(event)
      # NOTE: With the Rails logger, this `to_s` is actually unnecessary: The
      # "ActiveSupport::TaggedLogging::Formatter#call" method implicitly invokes
      # to_s when it calls:
      #
      #       super(severity, timestamp, progname, "#{tags_text}#{msg}")
      #
      # However, we do want an implicit dependency on the Rails logger, even
      # though we happen to be using it now.  Our only dependency should be
      # on the _interface_ defined by Ruby's standard Logger.  Additionally,
      # the Rails logger makes no guarantees about this behavior, so we'd be
      # coupling to an implementation detail by depending on it.
      @ruby_logger.log(s, event.to_s, ::Audit::Event.progname)
    end
  end

  class SyslogLogAdapter
    def initialize(ruby_logger)
      @ruby_logger = ruby_logger
    end

    def log(event)
      @ruby_logger.log(s, event, pn)
    end
  end
end
