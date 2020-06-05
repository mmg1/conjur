module Audit
  module Event
    class Policy

      def initialize(
        operation:,
        subject:,
        user: nil,
        policy_version: nil
      )
        @operation = operation
        @subject = subject
        @user = user
        @policy_version = policy_version
      end

      def progname
        Event.progname
      end

      def severity
        Syslog::LOG_NOTICE
      end

      def message
        past_tense_verb = @operation.to_s.chomp('e') + "ed"
        "#{user.id} #{past_tense_verb} #{@subject}"
      end

      # message_id or "operation". An Syslog term from RFC5424.
      def message_id
        "policy"
      end

      def structured_data
        {
          SDID::AUTH => { user: user.id },
          SDID::SUBJECT => @subject.to_h,
          SDID::ACTION => { operation: @operation }
        }.tap do |sd|
          if @policy_version
            sd[SDID::POLICY] = {
              id: @policy_version.id,
              version: @policy_version.version
            }
          end
        end
      end

      def facility
        # Security or authorization messages which should be kept private. See:
        # https://github.com/ruby/ruby/blob/b753929806d0e42cdfde3f1a8dcdbf678f937e44/ext/syslog/syslog.c#L109
        # Note: Changed this to from LOG_AUTH to LOG_AUTHPRIV because the former
        # is deprecated.
        Syslog::LOG_AUTHPRIV
      end

      private

      def user
        @user || @policy_version.role
      end

      def resource_description
        return @resource.id unless @version
        "version #{@version} of #{@resource.id}"
      end
    end
  end
end

