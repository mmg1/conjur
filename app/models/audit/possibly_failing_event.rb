module Audit
  module Event2
    class PossiblyFailingEvent

      def initialize(success)
        @success = success
      end

      # TODO: Add comment re: difference between these failure & error msgs
      def message(success_msg:, failure_msg:, error_msg: nil)
        return success_msg if @success
        [failure_msg, error_msg].compact.join(': ')
      end

      # action_sd means "action structured data"
      def action_sd(operation)
        { SDID::ACTION => { result: success_text, operation: operation } }
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
end
