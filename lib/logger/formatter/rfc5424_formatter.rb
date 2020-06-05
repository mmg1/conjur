# frozen_string_literal: true

require 'logger'
require 'syslog'
require 'time'

require 'util/struct'

class Logger
  class Formatter
    # RFC5424-compliant log formatter. If given a message that responds to 
    # severity, facility, message_id and/or structured_data, it'll use them.
    class RFC5424Formatter
      # The :reek:LongParameterList here is to conform to Formatter interface.
      def self.call severity, time, progname, msg
        Format.new(severity: severity, time: time, progname: progname, msg: msg).to_s
      end

      # Utility class that formats a single message
      class Format < Util::Struct
        field :severity, :time, :progname, :msg

        SEVERITY_MAP = {
          Logger::Severity::DEBUG => Syslog::LOG_DEBUG,
          Logger::Severity::ERROR => Syslog::LOG_ERR,
          # TODO: is this right? (doesn't match reverse map)
          Logger::Severity::FATAL => Syslog::LOG_CRIT,
          Logger::Severity::INFO => Syslog::LOG_INFO,
          Logger::Severity::WARN => Syslog::LOG_WARNING
        }.freeze

        # header: "<#{severity + facility}>1"
        # timestamp: time.utc.iso8601 3
        # hostname: nil -- Will be filled in by syslogd.
        # progname: progname
        # Format.pid: Thread.current[:request_id] || Process.pid
        # msgid: msg.try(:message_id)
        # sd:
            # return unless (sdata = msg.try(:structured_data))
            # sdata.map do |id, params|
            #   format "[%s]", [id, *Format.sd_parameters(params)].join(" ")
            # end.join
        # msg:
        #
        # HENCE:
        # passed or hardoded:
        # - severity
        # - facility
        # - time
        # - progname
        # - msg (finally to_s)
        #
        # How it's used:
        #
        # @event.new(
        #     role: role,
        #     authenticator_name: @authenticator_input.authenticator_name,
        #     service: @resource_cls[webservice_id],
        #     success: @success,
        #     error_message: @message
        # ).log_to @audit_log
        #
        def to_s
          [header, timestamp, hostname, progname, Format.pid, msgid, sd, msg]
            .map {|part| part || '-'}.join(" ") + "\n"
        end

        def header
          "<#{severity + facility}>1"
        end

        # TODO: Severity translations now spread across two classes
        def severity
          msg.try(:severity) || SEVERITY_MAP[super]
        end

        def facility
          msg.try(:facility) || Syslog::LOG_AUTH
        end

        def timestamp
          time.utc.iso8601 3
        end

        def hostname
          # Will be filled in by syslogd.
          nil
        end

        def msgid
          msg.try :message_id
        end

        def sd
          return unless (sdata = msg.try(:structured_data))
          sdata.map do |id, params|
            format "[%s]", [id, *Format.sd_parameters(params)].join(" ")
          end.join
        end

        def self.pid
          # use http request id (as stored by Rack::RememberUuid) if available
          Thread.current[:request_id] || Process.pid
        end

        def self.sd_parameters params
          # Ensure quote, backslash, and closing square bracket are all escaped per:
          # https://tools.ietf.org/html/rfc5424#section-6.3.3
          #
          # `inspect` handles quote and backslash, gsub handles the square bracket
          params.map { |parameter, value| [parameter, value.to_s.inspect.gsub("]", "\\]")].join('=') }
        end
      end
    end
  end
end
