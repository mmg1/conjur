module Audit
  module Event2
    class Update

      def initialize(
        user:,
        resource:,
        success:,
        error_message: nil
      )
        @user = user
        @resource = resource
        @success = success
        @error_message = error_message
      end

      def progname
        Event2.progname
      end

      def severity
        @success ? Syslog::LOG_NOTICE : Syslog::LOG_WARNING
        # TODO: I think this was intended to be the following
        #   but was mistakenly change to above (just sloppy inconsistency):
        # possibly_failing_event.severity
      end

      def service_id
        @service&.id
      end

      def message
        possibly_failing_event.message(
          success_msg: "#{user.id} updated #{resource.id}",
          failure_msg: "#{user.id} tried to update #{resource.id}",
          error_msg: @error_message
        )
      end

      # message_id or "operation". An Syslog term from RFC5424.
      def message_id
        "update"
      end

      def structured_data
        {
          SDID::AUTH => { user: user.id },
          SDID::SUBJECT => Subject::Resource.new(resource.pk_hash).to_h,
        }.merge(
          possibly_failing_event.action_sd(message_id)
        )
      end

      def facility
        # Security or authorization messages which should be kept private. See:
        # https://github.com/ruby/ruby/blob/b753929806d0e42cdfde3f1a8dcdbf678f937e44/ext/syslog/syslog.c#L109
        # Note: Changed this to from LOG_AUTH to LOG_AUTHPRIV because the former
        # is deprecated.
        Syslog::LOG_AUTHPRIV
      end

      private

      def possibly_failing_event
        @possibly_failing_event ||= PossiblyFailingEvent.new(@success)
      end

    end
  end
end

