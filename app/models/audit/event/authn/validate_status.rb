require 'forwardable'

module Audit
  module Event
    class Authn
      class ValidateStatus
        attr_reader :role, :authenticator_name, :service, :success,
                    :error_message

        extend Forwardable
        def_delegators :@authn, :facility, :message_id, :severity,
                       :structured_data, :progname

        def initialize(
          role:,
          client_ip:,
          authenticator_name:,
          service:,
          success:,
          error_message: nil
        )
          @role = role
          @error_message = error_message
          @authn = Authn.new(
            role: role,
            client_ip: client_ip,
            authenticator_name: authenticator_name,
            service: service,
            success: success,
            operation: "validate-status"
          )
        end

        def to_s
          message
        end

        def message
          @authn.message(
            success_msg:
              "#{@role&.id} successfully validated status for authenticator "\
                "#{@authn.authenticator_description}",
            failure_msg:
              "#{@role&.id} failed to authenticate with authenticator "\
                "#{@authn.authenticator_description}",
            error_msg: @error_message
          )
        end
      end
    end
  end
end
