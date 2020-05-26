module Audit
  class Event2
    class Authn

      # abstract_field :facility, :message, :message_id, :severity, :structured_data, :progname
      def initialize(
          role:,
          authenticator_name:,
          service:,
          success:,
          error_message:
      )
        @role = role
        @authenticator_name = authenticator_name
        @service = service
        @success = success
        @error_message = error_message

        evt = PossiblyFailingEvent.new(
            facility: facility,
            message_id: message_id,
            success_message:,

            structured_data:,
            failure_message:, # TODO: Add comment re: difference between these 2
            error_message: nil,
            success: true
        )
      end

      def authenticator_description
        # TODO Add part with name and servicemessagepart
      end

      def message_id
        "authn"
      end

      def facility
        # Security or authorization messages which should be kept private. See:
        # https://github.com/ruby/ruby/blob/b753929806d0e42cdfde3f1a8dcdbf678f937e44/ext/syslog/syslog.c#L109
        Syslog::LOG_AUTHPRIV
      end
    end
end

class Event2
    @role = role
    @authenticator_name = authenticator_name
    @success = success
    @service = service
  end

  def severity
    success ? Syslog::LOG_INFO : Syslog::LOG_WARNING
  end

  private

  def service_id
    @service&.id
  end

  def role_id
    @role.id
  end

  # TODO: Use longer name
  def auth_sd
    { authenticator: authenticator_name }.merge(
        service_id ? { service: service_id } : {}
    )
  end

  # From super: CanFail
  # def structured_data
  #   super.deep_merge SDID::ACTION => { result: success_text }
  # end

  # what varies among the different events?
  # make that into data objects which we pass to event to configure it.
  # I can generate Class objects that way.
  # EventClass.new(config...) => AuthnEvent, BlahEvent, etc
  # Since AuthnEvent has subtypes, that means it shares config
  # YES!
  def structured_data
    super.deep_merge(
        SDID::SUBJECT => { role: role_id },
        SDID::AUTH => auth_sd,
        SDID::ACTION => { operation: operation }
    )
  end
end
