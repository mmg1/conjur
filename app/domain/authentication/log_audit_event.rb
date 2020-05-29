# frozen_string_literal: true

module Authentication

  LogAuditEvent = CommandClass.new(
    dependencies: {
      role_cls:  ::Role,
      resource_cls: ::Resource,
      audit_log: ::Audit.logger
    },
    inputs:       %i(authenticator_name webservice role event success message)
  ) do

    # TODO: Use Audit::Event2 events everywhere.
    def call
      return unless @role

      # TODO: These will always be created in the callers.
      evt = @event.new(
        role: @role,
        authenticator_name: @authenticator_name,
        service: @resource_cls[webservice_id],
        success: @success,
        error_message: @message
      )

      @audit_log.log(evt)
    end

    private

    def webservice_id
      @webservice.resource_id
    end
  end
end
