
module Audit
  module Event2
    class Fetch

      def initialize(
        user:,
        resource:,
        success:,
        error_message:,
        version:
      )
        @user = user
        @resource = resource
        @success = success
        @error_message = error_message
        @version = version
      end

      def progname
        Event2.progname
      end

      def severity
        possibly_failing_event.severity
      end

      def message
        possibly_failing_event.message(
          success_msg: "#{@user.id} fetched #{resource_description}",
          failure_msg: "#{@user.id} tried to fetch #{resource_description}",
          error_msg: @error_message
        )
      end

      # message_id or "operation". An Syslog term from RFC5424.
      def message_id
        "fetch"
      end

      def structured_data
        {
          SDID::AUTH => { user: user.id },
          SDID::SUBJECT => subject_sd_value,
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

      def resource_description
        return @resource.id unless @version
        "version #{@version} of #{@resource.id}"
      end

      def subject_sd_value
        return { resource: resource.id } unless @version
        { resource: resource.id, version: @version }
      end

      def possibly_failing_event
        @possibly_failing_event ||= PossiblyFailingEvent.new(@success)
      end

    end
  end
end

