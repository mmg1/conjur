require 'forwardable'

module Audit
  class PossiblyFailingEvent

    extend Forwardable
    def_delegators :@event, :facility, :message_id, :structured_data

    def initialize(
      facility:,
      message_id:,
      success_message:,

      structured_data:,
      failure_message:, # TODO: Add comment re: difference between these 2
      error_message: nil,
      success: true
    )
      @success_message = success_message
      @failure_message = failure_message
      @error_message = error_message
      @success = success
      @event = Audit::Event2.new(
        facility: facility,
        message: nil, # We implement it here rather than delegate.
        message_id: message_id,
        severity: severity,
        structured_data: structured_data
      )
    end

    def message
      return @success_message if @success
      [@failure_message, @error_message].compact.join(': ')
    end

    # Event classes delegating to this class will merge this structured data
    # with their own.
    def action_structured_data(success_text)
      { SDID::ACTION => { result: success_text } }
    end

    def severity
      @success ? Syslog::LOG_INFO : Syslog::LOG_WARNING
    end

    private

    def success_text
      @success ? 'success' : 'failure'
    end
  end
end
