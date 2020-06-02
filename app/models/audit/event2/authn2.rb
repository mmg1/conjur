module Audit
  module Event2
    class Authn

      def initialize(
          role:,
          authenticator_name:,
          service:,
          success:,
          operation:
      )
        @role = role
        @authenticator_name = authenticator_name
        @service = service
        @success = success
        @operation = operation
      end

      def progname
        Event2.progname
      end

      def severity
        RubySeverity.new(possibly_failing_event.severity)
      end

      def authenticator_description
        return @authenticator_name unless service_id
        "#{@authenticator_name} service #{service_id}"
      end

      def service_id
        @service&.resource_id
      end

      def message(success_msg:, failure_msg:, error_msg: nil)
        possibly_failing_event.message(
            success_msg: success_msg,
            failure_msg: failure_msg,
            error_msg: error_msg
        )
      end

      def message_id
        "authn"
      end

      def structured_data
        {
          SDID::SUBJECT => {role: @role.id},
          SDID::AUTH => auth_stuctured_data,
        }.merge(
          possibly_failing_event.action_sd(@operation)
        )
      end

      def facility
        # Security or authorization messages which should be kept private. See:
        # https://github.com/ruby/ruby/blob/b753929806d0e42cdfde3f1a8dcdbf678f937e44/ext/syslog/syslog.c#L109
        Syslog::LOG_AUTHPRIV
      end

      private

      def possibly_failing_event
        @possibly_failing_event ||= PossiblyFailingEvent.new(@success)
      end

      def auth_stuctured_data
        return {authenticator: @authenticator_name} unless service_id
        {authenticator: @authenticator_name, service: service_id}
      end
    end
  end
end

