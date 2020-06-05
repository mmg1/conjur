# frozen_string_literal: true

require 'syslog'
require 'logger'

module Audit

  class Event < Util::Struct
    abstract_field :facility, :message, :message_id, :severity, :structured_data, :progname

    progname 'conjur'

    # TODO: This is a _serious_ design flaw.  Our events are built our Syslog.
    #       Hence they should only know about Syslog severity levels.  Instead
    #       of putting this translation here, it needs to go in an adapter over
    #       the Rails logger that we write.
    #       Also we'll just remove this method since the calling code will
    #       do the logging.
    def log_to logger
      logger.log logger_severity, self, progname
    end

    def to_s
      message
    end

    # Pretend this is a String because Ruby's built-in log formatter matches it
    # like this and uses #inspect to print the message otherwise.
    #
    # I suppose it does :reek:ControlParameter, but there isn't much that can be
    # done about it.
    #
    def === other
      (other == String) || super
    end

    structured_data({}) # provide a base for subclasses to merge from
    
    def self.can_fail
      include CanFail
    end

    private

    # Return severity as it's understood by Ruby ::Logger
    def logger_severity
      SEVERITY_MAP[severity]
    end

    SDID = ::Audit::SDID

    SEVERITY_MAP = {
      LOG_EMERG: :FATAL,
      LOG_ALERT: :FATAL,
      LOG_CRIT: :ERROR,
      LOG_ERR: :ERROR,
      LOG_WARNING: :WARN,
      LOG_NOTICE: :INFO,
      LOG_INFO: :INFO,
      LOG_DEBUG: :DEBUG
    }.map do |syslog, logger|
      [Syslog::Level.const_get(syslog), Logger::Severity.const_get(logger)]
    end.to_h.freeze
  end
end
