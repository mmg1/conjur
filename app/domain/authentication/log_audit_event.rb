# frozen_string_literal: true

module Authentication

  LogAuditEvent = CommandClass.new(
    dependencies: {
      role_cls: ::Role,
      resource_cls: ::Resource,
      audit_log: ::Audit.logger
    },
    inputs: %i(event)
  ) do

    def call
      # TODO: We actually shouldn't need this
      # return unless @event.role || @event.user

      # evt = @event.class.new(
      #   role: @event.role,
      #   authenticator_name: @event.authenticator_name,
      #   # TODO: Do we need to hit the database for the service_id?
      #   #   Can we possibly get directly form webservice object?
      #   service: @event.service,
      #   success: @event.success,
      #   error_message: @event.message
      # )

      @audit_log.log(@event)
    end

    private

    def webservice_id
      @event.service&.resource_id
    end
  end
end
