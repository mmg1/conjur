module Audit
  module Event2
    class Check

      def initialize(
        user:,
        resource:,
        privilege:,
        role:,
        success:
      )
        @user = user
        @resource = resource
        @privilege = privilege
        @role = role
        @success = success
      end

      def progname
        Event2.progname
      end

      def severity
        possibly_failing_event.severity
      end

      def message
        "#{@user.id} checked if #{role_text} can #{@privilege} " \
          "#{@resource.id} (#{success_text})"
      end

      # message_id or "operation". An Syslog term from RFC5424.
      def message_id
        "check"
      end

      def structured_data
        {
          SDID::AUTH => { user: @user.id },
          SDID::SUBJECT => {
            resource: @resource.id,
            role: @role.id,
            privilege: @privilege
          },
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

      def role_text
        @user == @role ? 'they' : @role.id
      end

      def success_text
        @possibly_failing_event.success_text
      end

    end
  end
end

